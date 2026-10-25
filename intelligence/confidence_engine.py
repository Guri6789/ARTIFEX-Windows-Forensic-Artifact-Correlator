"""Explainable Investigation and Confidence Engine (Feature 5).

Provides transparent forensic reasoning:
- Computes confidence scores based on evidence quality, source reliability, and cross-corroboration
- Explains exactly which forensic rules triggered
- Generates plausible alternative explanations (to prevent confirmation bias)
- Identifies missing evidence needed to reach full certainty
"""

from __future__ import annotations

from typing import List, Tuple

from insider_forensics.core.models import (
    ArtifactType,
    ConfidenceExplanation,
    ConfidenceRating,
    FactLevel,
    ForensicAnomaly,
    IncidentHypothesis,
    IncidentStage,
    StepStatus,
)
from insider_forensics.correlation.cross_correlator import CorrelationBundle


class ConfidenceAndExplanationEngine:
    """Evaluates hypothesis validity with mathematical source weighting and transparent explanations."""

    # Baseline reliability weights per artifact category (0.0 to 1.0)
    RELIABILITY_WEIGHTS = {
        ArtifactType.EVENT_LOG_DRIVER_FRAMEWORKS: 0.95,  # Cryptographically signed kernel logs
        ArtifactType.EVENT_LOG_SECURITY: 0.95,
        ArtifactType.EVENT_LOG_SYSTEM: 0.95,
        ArtifactType.NTFS_USN_JOURNAL: 0.90,            # High-fidelity NTFS transaction stream
        ArtifactType.PREFETCH: 0.90,                     # Windows Cache Manager execution proofs
        ArtifactType.JUMP_LIST: 0.85,                    # Application-specific interaction records
        ArtifactType.LNK_SHORTCUT: 0.85,                 # Rich metadata (VSN, drive type, MAC)
        ArtifactType.REGISTRY_USBSTOR: 0.85,             # PnP device enumerations
        ArtifactType.BROWSER_SQLITE: 0.80,               # Browser session databases
        ArtifactType.NTFS_MFT: 0.75,                     # Variable due to SI timestomp vulnerability
    }

    def evaluate(
        self,
        hypothesis: IncidentHypothesis,
        bundle: CorrelationBundle,
        anomalies: List[ForensicAnomaly],
    ) -> ConfidenceExplanation:
        """Calculate weighted confidence and generate explainability rationales."""
        triggered_rules: List[str] = []
        corroborating_sources: List[str] = []
        alternative_explanations: List[str] = []
        missing_evidence_gaps: List[str] = []

        total_weight = 0.0
        weighted_sum = 0.0
        unique_artifacts = set()

        for step in hypothesis.steps:
            for ev in step.supporting_events:
                weight = self.RELIABILITY_WEIGHTS.get(ev.artifact_type, 0.70)
                # Penalize unconfirmed inferred steps slightly
                if ev.fact_level == FactLevel.INFERRED_RELATIONSHIP:
                    weight *= 0.80
                weighted_sum += weight
                total_weight += 1.0
                unique_artifacts.add(ev.artifact_type)

        base_score = (weighted_sum / total_weight) if total_weight > 0 else 0.50

        # Multi-artifact corroboration boost
        # Having 3 or more independent artifact categories significantly reduces false positives
        corroboration_factor = min(len(unique_artifacts) * 0.05, 0.20)
        final_score = min(base_score + corroboration_factor, 0.99)

        # Severe anomalies (like deliberate log clearing or timestomping) elevate malicious confidence
        has_critical_anomaly = any(a.severity.value == "CRITICAL" for a in anomalies)
        if has_critical_anomaly:
            triggered_rules.append("RULE_MALICIOUS_ANTI_FORENSICS_CORROBORATION")
            final_score = min(final_score + 0.05, 0.99)

        # Check rule firings
        has_staging = any(s.stage == IncidentStage.FILE_STAGING and s.status == StepStatus.CONFIRMED for s in hypothesis.steps)
        has_usb = any(s.stage == IncidentStage.DEVICE_PREPARATION and s.status == StepStatus.CONFIRMED for s in hypothesis.steps)
        has_transfer = any(s.stage == IncidentStage.DATA_TRANSFER for s in hypothesis.steps)
        has_coverup = any(s.stage == IncidentStage.COVER_UP_ANTI_FORENSICS for s in hypothesis.steps)

        if has_staging and has_usb:
            triggered_rules.append("RULE_STAGING_DURING_REMOVABLE_MEDIA_SESSION")
        if has_usb and has_transfer:
            triggered_rules.append("RULE_USB_VOLUME_SERIAL_EXFILTRATION_CORRELATION")
        if has_coverup:
            triggered_rules.append("RULE_EVIDENCE_PURGE_AND_COVER_UP_SEQUENCE")

        # Document corroborating sources
        for art in unique_artifacts:
            corroborating_sources.append(f"{art.value} (Reliability Weight: {self.RELIABILITY_WEIGHTS.get(art, 0.7):.2f})")

        # Formulate Alternative Explanations (Critical for forensic defensibility)
        if not has_coverup and not has_critical_anomaly:
            alternative_explanations.append(
                "Authorized IT Administration: User was performing legitimate local data backup or routine system migration."
            )
        alternative_explanations.append(
            "Accidental Multi-Tasking: Removable drive was connected for charging or personal media while work documents were simultaneously open."
        )
        if has_staging and not has_usb:
            alternative_explanations.append(
                "Routine Storage Management: User compressed large project folders solely to save local drive capacity."
            )

        # Document Missing Evidence Gaps
        if any(s.status == StepStatus.UNCONFIRMED for s in hypothesis.steps):
            missing_evidence_gaps.append(
                "Exact File Copy Payload: Windows Removable Storage Auditing (Event 4663) or DLP agent logs not present."
            )
        missing_evidence_gaps.append(
            "Physical Removable Storage Device: The physical USB thumb drive has not been seized for forensic bitstream imaging."
        )
        if not any(e.artifact_type == ArtifactType.BROWSER_SQLITE for e in bundle.all_events_sorted):
            missing_evidence_gaps.append(
                "Cloud Browser Data: Chromium/Firefox web history databases were not available in the acquired triage set."
            )

        # Qualitative Rating
        if final_score >= 0.90:
            rating = ConfidenceRating.VERY_HIGH
        elif final_score >= 0.75:
            rating = ConfidenceRating.HIGH
        elif final_score >= 0.60:
            rating = ConfidenceRating.MEDIUM
        elif final_score >= 0.40:
            rating = ConfidenceRating.LOW
        else:
            rating = ConfidenceRating.TENTATIVE

        return ConfidenceExplanation(
            score=final_score,
            rating=rating,
            triggered_rules=triggered_rules,
            corroborating_sources=corroborating_sources,
            alternative_explanations=alternative_explanations,
            missing_evidence_gaps=missing_evidence_gaps,
        )
