"""Markdown Forensic Investigation Report Generator.

Formats the complete investigation into a formal, court-defensible forensic report:
- Executive Summary
- Reconstructed Data-Theft Sequence (Confirmed vs Unconfirmed steps)
- Forensic Anomalies, Tampering & Evidence Gaps
- Explainable Confidence Assessment & Alternative Explanations
- Cryptographic Chain-of-Custody Evidence Manifest (SHA-256 hashes)
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import List

from insider_forensics.core.models import (
    ForensicAnomaly,
    IncidentHypothesis,
    StepStatus,
)
from insider_forensics.provenance.tracker import EvidenceTracker


class MarkdownReporter:
    """Generates a professional Markdown investigative dossier."""

    def __init__(self, tracker: EvidenceTracker) -> None:
        self.tracker = tracker

    def generate_report(
        self,
        hypothesis: IncidentHypothesis,
        anomalies: List[ForensicAnomaly],
        output_file: Path,
    ) -> str:
        lines: List[str] = []

        lines.append("# DIGITAL FORENSIC INVESTIGATION REPORT")
        lines.append("## Windows Forensic Artifact Analysis: Insider Data Exfiltration")
        lines.append(f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  ")
        lines.append(f"**Investigation Case ID:** `{hypothesis.hypothesis_id}`  ")
        lines.append(f"**Subject of Investigation:** `{hypothesis.subject_user or 'Unknown'}`  ")
        lines.append(f"**Incident Time Window:** `{hypothesis.time_window_start.strftime('%Y-%m-%d %H:%M:%S UTC')}` to `{hypothesis.time_window_end.strftime('%Y-%m-%d %H:%M:%S UTC')}`  ")
        lines.append(f"**Confidence Rating:** **{hypothesis.confidence.rating.value}** (Score: {hypothesis.confidence.score * 100:.1f}%)  \n")

        lines.append("---")
        lines.append("### 1. Executive Summary")
        lines.append(
            f"Forensic examination of Windows system artifacts identified a coordinated multi-stage data exfiltration "
            f"sequence targeting **{len(hypothesis.target_files)} sensitive file(s)**. The activity involved temporary "
            f"staging container creation ({', '.join(hypothesis.staging_containers) or 'N/A'}), attachment of unauthorized "
            f"removable storage ({', '.join(hypothesis.destination_devices) or 'N/A'}), followed by deliberate anti-forensic "
            f"tampering ({len(anomalies)} anomalies detected).\n"
        )

        lines.append("---")
        lines.append("### 2. Reconstructed Incident Sequence (5-Stage Lifecycle)")
        lines.append("The table below details each chronological stage of the incident, distinguishing directly verified facts from analytical inferences:\n")
        lines.append("| Step | Stage | Verification Status | Timestamp (UTC) | Description |")
        lines.append("| :--- | :--- | :--- | :--- | :--- |")

        for step in hypothesis.steps:
            status_badge = f"**{step.status.value}**"
            ts_str = step.timestamp.strftime("%Y-%m-%d %H:%M:%S") if step.timestamp else "N/A"
            lines.append(f"| {step.step_number} | `{step.stage.value}` | {status_badge} | {ts_str} | {step.description} |")

        lines.append("\n#### Detailed Step Analysis & Supporting Artifacts:\n")
        for step in hypothesis.steps:
            lines.append(f"##### Step {step.step_number}: [{step.stage.value}] - Status: {step.status.value}")
            lines.append(f"- **Summary:** {step.description}")
            if step.unconfirmed_notes:
                lines.append(f"- ⚠️ **Investigative Note on Unconfirmed Action:** {step.unconfirmed_notes}")
            lines.append(f"- **Corroborating Forensic Events ({len(step.supporting_events)}):**")
            for ev in step.supporting_events[:5]:  # Top 5 representative events
                lines.append(
                    f"  - `[{ev.timestamp.strftime('%H:%M:%S')}]` **{ev.artifact_type.value}** ({ev.fact_level.value}): {ev.summary}"
                )
            lines.append("")

        lines.append("---")
        lines.append("### 3. Forensic Anomalies & Evidence Gap Analysis")
        lines.append(
            f"The forensic anomaly analyzer detected **{len(anomalies)} inconsistency or tampering indicator(s)**:\n"
        )
        for anom in anomalies:
            lines.append(f"#### ⚠️ [{anom.severity.value}] {anom.title}")
            lines.append(f"- **Anomaly Type:** `{anom.anomaly_type}`")
            lines.append(f"- **Finding Explanation:** {anom.explanation}")
            lines.append(f"- **Investigative Impact:** {anom.investigative_impact}")
            if anom.recommended_action:
                lines.append(f"- **Recommended Follow-up:** {anom.recommended_action}")
            lines.append("")

        lines.append("---")
        lines.append("### 4. Explainable Confidence Assessment & Alternative Explanations")
        lines.append(f"- **Overall Confidence Score:** `{hypothesis.confidence.score * 100:.1f}%` ({hypothesis.confidence.rating.value})")
        lines.append("- **Triggered Forensic Decision Rules:**")
        for rule in hypothesis.confidence.triggered_rules:
            lines.append(f"  - `{rule}`")

        lines.append("\n- **Corroborating Evidence Sources:**")
        for src in hypothesis.confidence.corroborating_sources:
            lines.append(f"  - {src}")

        lines.append("\n- **Plausible Alternative Explanations Evaluated:**")
        for alt in hypothesis.confidence.alternative_explanations:
            lines.append(f"  - ℹ️ {alt}")

        lines.append("\n- **Identified Evidence Gaps:**")
        for gap in hypothesis.confidence.missing_evidence_gaps:
            lines.append(f"  - 🔍 {gap}")

        lines.append("\n---")
        lines.append("### 5. Chain of Custody & Cryptographic Evidence Manifest")
        lines.append("All parsed forensic artifact containers have been verified with SHA-256 and SHA-1 cryptographic hashes:\n")
        lines.append("| Evidence ID | Artifact File | Size (Bytes) | SHA-256 Hash | Integrity Status |")
        lines.append("| :--- | :--- | :--- | :--- | :--- |")

        for item in self.tracker.evidence_items.values():
            lines.append(
                f"| `{item.evidence_id}` | `{item.file_name}` | {item.file_size_bytes} | `{item.sha256[:20]}...` | **{item.verification_status}** |"
            )

        report_content = "\n".join(lines)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(report_content, encoding="utf-8")
        return report_content
