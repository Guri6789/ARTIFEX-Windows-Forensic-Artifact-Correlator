"""Forensic Anomaly and Evidence-Gap Analyzer (Feature 2).

Detects:
- Anti-forensics: Explicit log clearings (Security 1102 / System 104)
- Timestamp inconsistencies & timestomping ($STANDARD_INFO vs $FILE_NAME, sub-second zeroing)
- Ghost staging & deleted file traces (files in USN/Prefetch/JumpLists that vanished from disk)
- Cross-artifact contradictions (e.g. Prefetch execution without Security 4688 records)
- Unreliable or missing records affecting the investigation
- Explains investigative impact and required follow-up actions for each gap
"""

from __future__ import annotations

import uuid
from typing import List, Optional

from insider_forensics.core.models import (
    AnomalySeverity,
    ArtifactType,
    EventCategory,
    ForensicAnomaly,
    ForensicEvent,
)
from insider_forensics.correlation.cross_correlator import CorrelationBundle


class ForensicAnomalyAnalyzer:
    """Analyzes evidence weaknesses, tampering, timestamp contradictions, and gaps."""

    def analyze(self, bundle: CorrelationBundle) -> List[ForensicAnomaly]:
        anomalies: List[ForensicAnomaly] = []

        # 1. Anti-Forensic Log Clearings
        anomalies.extend(self._detect_log_clearing(bundle.all_events_sorted))

        # 2. Timestomping & SI vs FN Discrepancies
        anomalies.extend(self._detect_timestomping(bundle.all_events_sorted))

        # 3. Ghost Staging & Deleted File Traces
        anomalies.extend(self._detect_ghost_staging(bundle))

        # 4. Cross-Artifact Contradictions
        anomalies.extend(self._detect_cross_artifact_contradictions(bundle))

        # 5. Missing Evidence Gaps & Audit Vulnerabilities
        anomalies.extend(self._detect_evidence_gaps(bundle))

        return anomalies

    def _detect_log_clearing(self, events: List[ForensicEvent]) -> List[ForensicAnomaly]:
        anomalies: List[ForensicAnomaly] = []
        for ev in events:
            if ev.category == EventCategory.LOG_CLEARED:
                log_type = "Security" if ev.artifact_type == ArtifactType.EVENT_LOG_SECURITY else "System"
                anomaly = ForensicAnomaly(
                    anomaly_id=f"ANOM-{uuid.uuid4().hex[:8].upper()}",
                    anomaly_type="LOG_TAMPERING_CLEARED",
                    severity=AnomalySeverity.CRITICAL,
                    title=f"Anti-Forensic Event Log Clearing ({log_type})",
                    explanation=(
                        f"The {log_type} event log was deliberately wiped by user '{ev.user or 'Unknown'}' "
                        f"at {ev.timestamp.isoformat()}. Windows Event ID: {ev.record_id or '1102/104'}."
                    ),
                    investigative_impact=(
                        "Historical audit records, logon session history, and process execution events "
                        "prior to this timestamp were permanently erased, destroying evidence of pre-attack reconnaissance."
                    ),
                    affected_artifacts=[ev.artifact_type],
                    supporting_events=[ev],
                    recommended_action=(
                        "Examine Volume Shadow Copies (VSS) or SIEM forwarders for preserved pre-clear logs."
                    ),
                )
                anomalies.append(anomaly)
        return anomalies

    def _detect_timestomping(self, events: List[ForensicEvent]) -> List[ForensicAnomaly]:
        anomalies: List[ForensicAnomaly] = []
        for ev in events:
            if ev.category == EventCategory.TIMESTOMP_DETECTED:
                meta = ev.raw_metadata or {}
                delta = meta.get("delta_sec", 0)
                anomaly = ForensicAnomaly(
                    anomaly_id=f"ANOM-{uuid.uuid4().hex[:8].upper()}",
                    anomaly_type="TIMESTAMP_CONTRADICTION_TIMESTOMP",
                    severity=AnomalySeverity.HIGH,
                    title=f"Timestomp Anomaly Detected on {ev.source_file_path or 'File'}",
                    explanation=(
                        f"Inconsistency detected between NTFS $STANDARD_INFORMATION (user-modifiable) "
                        f"and $FILE_NAME (NTFS kernel-protected). Modified timestamp was altered by {delta:.0f} seconds."
                    ),
                    investigative_impact=(
                        "The target file was manipulated to appear older than it actually is, designed to bypass "
                        "date-bounded triage acquisition scripts and mislead timeline analysis."
                    ),
                    affected_artifacts=[ArtifactType.NTFS_MFT],
                    supporting_events=[ev],
                    recommended_action=(
                        "Rely on kernel-enforced $FILE_NAME timestamps and $UsnJrnl change logs rather than Explorer timestamps."
                    ),
                )
                anomalies.append(anomaly)
        return anomalies

    def _detect_ghost_staging(self, bundle: CorrelationBundle) -> List[ForensicAnomaly]:
        anomalies: List[ForensicAnomaly] = []
        for fname, trail in bundle.file_trails.items():
            if trail.is_staging_archive and trail.was_deleted:
                del_events = [e for e in trail.events if e.category == EventCategory.FILE_DELETION]
                anomaly = ForensicAnomaly(
                    anomaly_id=f"ANOM-{uuid.uuid4().hex[:8].upper()}",
                    anomaly_type="GHOST_STAGING_REMOVAL",
                    severity=AnomalySeverity.HIGH,
                    title=f"Ghost Staging Archive Destroyed: '{trail.file_name}'",
                    explanation=(
                        f"Staging archive container '{trail.file_name}' was actively populated/accessed and "
                        f"subsequently deleted via Shift+Delete/programmatic purge as evidenced by NTFS USN Journal records."
                    ),
                    investigative_impact=(
                        "The actual payload container is absent from disk, preventing direct hash verification "
                        "of file contents. However, metadata traces confirm its temporary existence during the incident."
                    ),
                    affected_artifacts=[ArtifactType.NTFS_USN_JOURNAL, ArtifactType.PREFETCH],
                    supporting_events=del_events or trail.events,
                    recommended_action=(
                        "Attempt file carving on unallocated NTFS clusters corresponding to the USN Journal FRN record."
                    ),
                )
                anomalies.append(anomaly)
        return anomalies

    def _detect_cross_artifact_contradictions(self, bundle: CorrelationBundle) -> List[ForensicAnomaly]:
        """Flags mismatches between process execution in Prefetch vs Security Event Logs."""
        anomalies: List[ForensicAnomaly] = []
        prefetch_tools = set()
        for ev in bundle.all_events_sorted:
            if ev.artifact_type == ArtifactType.PREFETCH and ev.process_name:
                prefetch_tools.add(ev.process_name.upper())

        sec_proc_events = [
            e for e in bundle.all_events_sorted
            if e.artifact_type == ArtifactType.EVENT_LOG_SECURITY and e.process_name
        ]
        sec_tools = set(e.process_name.upper() for e in sec_proc_events)

        # Look for staging tools in Prefetch that have zero Event Log 4688 records
        for tool in ("7Z.EXE", "WINRAR.EXE", "RCLONE.EXE"):
            if tool in prefetch_tools and sec_proc_events and tool not in sec_tools:
                anomaly = ForensicAnomaly(
                    anomaly_id=f"ANOM-{uuid.uuid4().hex[:8].upper()}",
                    anomaly_type="CROSS_ARTIFACT_OMISSION",
                    severity=AnomalySeverity.MEDIUM,
                    title=f"Execution Record Discrepancy: {tool}",
                    explanation=(
                        f"Prefetch confirms {tool} executed on the host, yet Windows Security Event Log "
                        f"(Event ID 4688) contains no corresponding process creation record."
                    ),
                    investigative_impact=(
                        "Indicates either Windows Process Creation Auditing was not enabled, or specific event "
                        "log records were selectively purged/filtered."
                    ),
                    affected_artifacts=[ArtifactType.PREFETCH, ArtifactType.EVENT_LOG_SECURITY],
                    recommended_action="Verify Audit Policy configuration in Security GPO.",
                )
                anomalies.append(anomaly)
        return anomalies

    def _detect_evidence_gaps(self, bundle: CorrelationBundle) -> List[ForensicAnomaly]:
        """Identifies systemic missing forensic data sources that require investigator caution."""
        anomalies: List[ForensicAnomaly] = []
        has_usb = any(e.category == EventCategory.USB_ATTACH for e in bundle.all_events_sorted)
        has_removable_auditing = any(
            e.artifact_type == ArtifactType.EVENT_LOG_SECURITY and "4663" in str(e.record_id)
            for e in bundle.all_events_sorted
        )

        if has_usb and not has_removable_auditing:
            anomaly = ForensicAnomaly(
                anomaly_id=f"ANOM-{uuid.uuid4().hex[:8].upper()}",
                anomaly_type="EVIDENCE_GAP_UNAUDITED_TRANSFER",
                severity=AnomalySeverity.MEDIUM,
                title="Evidence Gap: Removable Storage Object Auditing Disabled",
                explanation=(
                    "Removable device connection was observed, but granular File Read/Write events on the removable "
                    "drive (Event ID 4663) were not recorded by Windows Security Auditing."
                ),
                investigative_impact=(
                    "Exact byte-by-byte file copy actions must be proven through circumstantial correlation "
                    "(Volume Serial Numbers in LNK files and temporal windowing) rather than direct transfer logs."
                ),
                affected_artifacts=[ArtifactType.EVENT_LOG_SECURITY],
                recommended_action=(
                    "Enable 'Audit Removable Storage' in Group Policy Object (GPO) for enterprise hosts."
                ),
            )
            anomalies.append(anomaly)

        return anomalies
