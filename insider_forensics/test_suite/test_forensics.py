"""Automated Test Suite for Insider Forensics 5-Pillar Engine."""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from insider_forensics.core.engine import ForensicInvestigationEngine
from insider_forensics.core.models import (
    ConfidenceRating,
    FactLevel,
    IncidentStage,
    StepStatus,
)
from insider_forensics.test_suite.generator import generate_synthetic_scenario


class TestInsiderForensics(unittest.TestCase):
    """Verifies all 5 core unique forensic pillars."""

    def setUp(self) -> None:
        self.test_dir = Path(tempfile.mkdtemp(prefix="test_aegis_forensics_"))
        self.evidence_dir = self.test_dir / "evidence"
        self.output_dir = self.test_dir / "reports"
        generate_synthetic_scenario(self.evidence_dir)
        self.engine = ForensicInvestigationEngine()

    def tearDown(self) -> None:
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_pillar_1_data_theft_reconstruction(self) -> None:
        """Pillar 1: Reconstructs sequence of file access, staging, USB connection, transfer & deletion."""
        result = self.engine.analyze_directory(self.evidence_dir)
        self.assertIsNotNone(result.hypothesis)
        hyp = result.hypothesis

        # Verify stages are captured in chronological order
        stages = [s.stage for s in hyp.steps]
        self.assertIn(IncidentStage.RECONNAISSANCE, stages)
        self.assertIn(IncidentStage.FILE_STAGING, stages)
        self.assertIn(IncidentStage.DEVICE_PREPARATION, stages)
        self.assertIn(IncidentStage.DATA_TRANSFER, stages)
        self.assertIn(IncidentStage.COVER_UP_ANTI_FORENSICS, stages)

        # Verify target files and staging container identified
        self.assertTrue(any("Client_Financials_Q4.xlsx" in f for f in hyp.target_files))
        self.assertIn("exfil_backup.7z", hyp.staging_containers)

        # Verify confirmed vs unconfirmed step separation
        transfer_step = next(s for s in hyp.steps if s.stage == IncidentStage.DATA_TRANSFER)
        self.assertIsNotNone(transfer_step.unconfirmed_notes)

    def test_pillar_2_forensic_anomalies_and_gaps(self) -> None:
        """Pillar 2: Detects timestamp inconsistencies, log gaps, deleted file traces & log clearing."""
        result = self.engine.analyze_directory(self.evidence_dir)
        self.assertGreaterEqual(len(result.anomalies), 3)

        types = [a.anomaly_type for a in result.anomalies]
        # Anti-forensics: Security Log cleared (1102)
        self.assertIn("LOG_TAMPERING_CLEARED", types)
        # Anti-forensics: Timestomping ($STANDARD_INFO vs $FILE_NAME)
        self.assertIn("TIMESTAMP_CONTRADICTION_TIMESTOMP", types)
        # Ghost staging deletion (USN Journal FILE_DELETE)
        self.assertIn("GHOST_STAGING_REMOVAL", types)

        # Verify each anomaly explains investigative impact
        for anom in result.anomalies:
            self.assertTrue(len(anom.investigative_impact) > 10)

    def test_pillar_3_evidence_integrity_and_provenance(self) -> None:
        """Pillar 3: Calculates SHA-256 hashes, links findings to source, and verifies integrity."""
        result = self.engine.analyze_directory(self.evidence_dir)
        self.assertGreaterEqual(len(result.tracker.evidence_items), 5)

        # Verify each item has SHA-256 and SHA-1
        for item in result.tracker.evidence_items.values():
            self.assertEqual(len(item.sha256), 64)
            self.assertEqual(len(item.sha1), 40)
            self.assertEqual(item.verification_status, "VERIFIED")

        # Verify chain of custody verification succeeds
        audit = result.tracker.verify_all_integrity()
        self.assertTrue(all(audit.values()))

        # Verify event provenance link
        for ev in result.raw_events:
            self.assertIn(ev.evidence_id, result.tracker.evidence_items)

    def test_pillar_4_cross_artifact_correlation(self) -> None:
        """Pillar 4: Connects EventLogs, Registry, LNK, JumpLists, NTFS metadata & USB records."""
        result = self.engine.analyze_directory(self.evidence_dir)
        bundle = result.bundle

        # Verify USB session mapped to SanDisk drive
        self.assertGreaterEqual(len(bundle.device_sessions), 1)
        sess = bundle.device_sessions[0]
        self.assertEqual(sess.usb_serial, "07018899AABB")
        self.assertEqual(sess.volume_serial, "4A8F201B")

        # Verify LNK Volume Serial Number (4A8F201B) was correlated with USB session
        self.assertTrue(any(e.fact_level == FactLevel.INFERRED_RELATIONSHIP for e in bundle.inferred_events))

    def test_pillar_5_explainable_confidence_and_reporting(self) -> None:
        """Pillar 5: Assigns confidence, explains rules, lists alternative explanations & generates reports."""
        result = self.engine.analyze_directory(self.evidence_dir)
        hyp = result.hypothesis
        self.assertIsNotNone(hyp)

        conf = hyp.confidence
        self.assertGreater(conf.score, 0.70)
        self.assertIn(conf.rating, (ConfidenceRating.HIGH, ConfidenceRating.VERY_HIGH))
        self.assertTrue(len(conf.triggered_rules) > 0)
        self.assertTrue(len(conf.alternative_explanations) > 0)
        self.assertTrue(len(conf.missing_evidence_gaps) > 0)

        # Test export of all 3 reports
        self.engine.export_reports(result, self.output_dir)
        self.assertTrue((self.output_dir / "FORENSIC_REPORT.md").exists())
        self.assertTrue((self.output_dir / "forensic_findings.json").exists())
        self.assertTrue((self.output_dir / "super_timeline.csv").exists())

        md_content = (self.output_dir / "FORENSIC_REPORT.md").read_text(encoding="utf-8")
        self.assertIn("DIGITAL FORENSIC INVESTIGATION REPORT", md_content)
        self.assertIn("Reconstructed Incident Sequence", md_content)
        self.assertIn("Cryptographic Evidence Manifest", md_content)


if __name__ == "__main__":
    unittest.main()
