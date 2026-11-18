"""Unit tests for FTK Imager integration and manifest verification."""

from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

# Add project root to sys.path for direct test execution
_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from insider_forensics.imager.ftk_imager import (
    FtkImagerLogParser,
    WindowsLiveTriageCollector,
)
from insider_forensics.provenance.tracker import EvidenceTracker


SAMPLE_FTK_REPORT = """Created By AccessData® FTK® Imager 4.7.1.2

Case Information:
Case Number: INC-2026-9041
Evidence Number: EV-001
Unique Description: Suspect Corporate ThinkPad Workstation NVMe Drive
Examiner: Lead Forensic Investigator J. Vance
Notes: Bitstream disk image acquired on-site prior to workstation shutdown

----------------------------------------------------------------
Physical Evidentiary Item (Drive) Information:
[Drive Information]
Source Type: Physical Drive
Drive Model: Samsung SSD 980 PRO 1TB
Drive Serial Number: S5GXNX0T987654
Drive Interface Type: NVMe / USB
Sector Count: 1953525168
Bytes per Sector: 512

----------------------------------------------------------------
Image Information:
Acquisition started: Wed Oct 24 14:00:00 2026
Acquisition finished: Wed Oct 24 14:28:45 2026
Segment list:
  E:\\Images\\TargetDrive.E01
  E:\\Images\\TargetDrive.E02

----------------------------------------------------------------
Checksums:
MD5 checksum: 87d8984f8d9b891823abce37719f9901 : Verified
SHA1 checksum: a1b2c3d4e5f60718293a4b5c6d7e8f9012345678 : Verified
"""


class TestFtkImagerIntegration(unittest.TestCase):
    """Test suite verifying FTK Imager log parsing and triage acquisition."""

    def setUp(self) -> None:
        self.temp_dir = Path(tempfile.mkdtemp(prefix="test_ftk_"))
        self.log_file = self.temp_dir / "TargetDrive_Summary.txt"
        self.log_file.write_text(SAMPLE_FTK_REPORT, encoding="utf-8")

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_ftk_log_identification(self) -> None:
        """Verify FTK Imager text report recognition signature."""
        self.assertTrue(FtkImagerLogParser.is_ftk_log(SAMPLE_FTK_REPORT))
        self.assertFalse(FtkImagerLogParser.is_ftk_log("Random text file with no headers"))

    def test_ftk_metadata_extraction(self) -> None:
        """Verify extraction of Case Number, Examiner, Serial, and Checksums."""
        info = FtkImagerLogParser.parse_log_text(SAMPLE_FTK_REPORT, self.log_file)
        self.assertEqual(info.case_number, "INC-2026-9041")
        self.assertEqual(info.evidence_number, "EV-001")
        self.assertEqual(info.examiner, "Lead Forensic Investigator J. Vance")
        self.assertEqual(info.drive_model, "Samsung SSD 980 PRO 1TB")
        self.assertEqual(info.drive_serial, "S5GXNX0T987654")
        self.assertEqual(info.sector_count, 1953525168)
        self.assertEqual(info.md5_checksum, "87d8984f8d9b891823abce37719f9901")
        self.assertTrue(info.md5_verified)
        self.assertEqual(info.sha1_checksum, "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678")
        self.assertTrue(info.sha1_verified)
        self.assertEqual(len(info.image_paths), 2)

    def test_ftk_log_parser_event_generation(self) -> None:
        """Verify FtkImagerLogParser creates ForensicEvent and updates EvidenceTracker."""
        tracker = EvidenceTracker()
        parser = FtkImagerLogParser(tracker)
        events = parser.parse(self.log_file)

        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIn("Samsung SSD 980 PRO", event.summary)
        self.assertEqual(event.usb_serial, "S5GXNX0T987654")
        self.assertEqual(len(tracker.evidence_items), 1)
        evidence_item = list(tracker.evidence_items.values())[0]
        self.assertIn("FTK Imager", evidence_item.notes or "")

    def test_live_triage_collector_manifest_generation(self) -> None:
        """Verify WindowsLiveTriageCollector produces valid FTK-compatible summary."""
        out_dir = self.temp_dir / "triage_out"
        collector = WindowsLiveTriageCollector(out_dir, case_id="CASE-REAL-001", examiner="Agent Smith")

        mock_file = out_dir / "test_artifact.log"
        mock_file.parent.mkdir(parents=True, exist_ok=True)
        mock_file.write_text("sample log data", encoding="utf-8")
        collector.collected_files.append((mock_file, "TEST_CATEGORY", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))

        t0 = datetime.now(timezone.utc)
        summary_text = collector._build_ftk_summary(t0, t0)
        self.assertTrue(FtkImagerLogParser.is_ftk_log(summary_text))
        self.assertIn("CASE-REAL-001", summary_text)
        self.assertIn("Agent Smith", summary_text)


if __name__ == "__main__":
    unittest.main()
