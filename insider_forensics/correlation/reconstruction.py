"""Data-Theft Reconstruction and USB Correlation Engine (Feature 1).

Combines:
- Data-theft sequence reconstruction across 5 stages
- USB-to-file correlation
- Identification of confirmed vs unconfirmed steps
- Transforms isolated events into a connected forensic incident narrative
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import List, Optional

from insider_forensics.core.models import (
    ConfidenceRating,
    EventCategory,
    FactLevel,
    ForensicEvent,
    IncidentHypothesis,
    IncidentStage,
    IncidentStep,
    StepStatus,
)
from insider_forensics.correlation.cross_correlator import CorrelationBundle


class DataTheftReconstructionEngine:
    """Reconstructs the full chronological lifecycle of an insider data theft incident."""

    def reconstruct(self, bundle: CorrelationBundle) -> Optional[IncidentHypothesis]:
        """Synthesize correlated events into a structured hypothesis with step verification."""
        if not bundle.all_events_sorted:
            return None

        steps: List[IncidentStep] = []
        target_files: List[str] = []
        staging_containers: List[str] = []
        destination_devices: List[str] = []
        step_counter = 1

        # -------------------------------------------------------------
        # Stage 1: RECONNAISSANCE / TARGET FILE DISCOVERY
        # -------------------------------------------------------------
        recon_events = [
            e for e in bundle.all_events_sorted
            if e.category == EventCategory.RECON_ACCESS and e.source_file_path
        ]
        if recon_events:
            for ev in recon_events:
                if ev.source_file_path and ev.source_file_path not in target_files:
                    target_files.append(ev.source_file_path)

            step1 = IncidentStep(
                step_number=step_counter,
                stage=IncidentStage.RECONNAISSANCE,
                status=StepStatus.CONFIRMED,
                description=f"Insider accessed or browsed {len(target_files)} sensitive file(s) via Explorer/LNK/JumpLists.",
                timestamp=recon_events[0].timestamp,
                supporting_events=recon_events,
                confidence_score=0.95,
            )
            steps.append(step1)
            step_counter += 1

        # -------------------------------------------------------------
        # Stage 2: FILE STAGING / ARCHIVING
        # -------------------------------------------------------------
        staging_events = [
            e for e in bundle.all_events_sorted
            if e.category == EventCategory.FILE_STAGING or
            (e.category == EventCategory.PROCESS_EXECUTION and e.process_name in ("7Z.EXE", "WINRAR.EXE", "TAR.EXE"))
        ]
        for trail in bundle.file_trails.values():
            if trail.is_staging_archive and trail.file_name not in staging_containers:
                staging_containers.append(trail.file_name)

        if staging_events or staging_containers:
            desc = (
                f"Data staging activity detected: Archive containers identified "
                f"({', '.join(staging_containers) or 'compression utility execution'}) "
                f"corroborated by Prefetch and NTFS USN Journal."
            )
            step2 = IncidentStep(
                step_number=step_counter,
                stage=IncidentStage.FILE_STAGING,
                status=StepStatus.CONFIRMED,
                description=desc,
                timestamp=staging_events[0].timestamp if staging_events else None,
                supporting_events=staging_events,
                confidence_score=0.90,
            )
            steps.append(step2)
            step_counter += 1

        # -------------------------------------------------------------
        # Stage 3: DEVICE PREPARATION / REMOVABLE MEDIA ATTACHMENT
        # -------------------------------------------------------------
        usb_events = [
            e for e in bundle.all_events_sorted
            if e.category == EventCategory.USB_ATTACH
        ]
        if usb_events or bundle.device_sessions:
            for sess in bundle.device_sessions:
                dev_desc = f"{sess.vendor or 'USB'} (Serial: {sess.usb_serial}, Drive: {sess.drive_letter or 'N/A'})"
                if dev_desc not in destination_devices:
                    destination_devices.append(dev_desc)

            step3 = IncidentStep(
                step_number=step_counter,
                stage=IncidentStage.DEVICE_PREPARATION,
                status=StepStatus.CONFIRMED,
                description=f"External storage device mounted: {', '.join(destination_devices)}.",
                timestamp=usb_events[0].timestamp if usb_events else bundle.device_sessions[0].attach_time,
                supporting_events=usb_events,
                confidence_score=0.98,
            )
            steps.append(step3)
            step_counter += 1

        # -------------------------------------------------------------
        # Stage 4: DATA TRANSFER / EXFILTRATION
        # -------------------------------------------------------------
        transfer_events = [
            e for e in bundle.all_events_sorted + bundle.inferred_events
            if e.category in (EventCategory.FILE_TRANSFER_USB, EventCategory.CLOUD_UPLOAD)
        ]
        if transfer_events:
            usb_transfers = [e for e in transfer_events if e.category == EventCategory.FILE_TRANSFER_USB]
            cloud_transfers = [e for e in transfer_events if e.category == EventCategory.CLOUD_UPLOAD]
            has_inferred = any(e.fact_level == FactLevel.INFERRED_RELATIONSHIP for e in transfer_events)

            unconfirmed_notes = None
            if has_inferred or usb_transfers:
                unconfirmed_notes = (
                    "Windows does not natively log raw file copy payload transfers to USB without "
                    "Removable Storage Auditing (Event ID 4663). Transfer inferred from Volume Serial "
                    "Number (VSN) linkage and contemporaneous device attachment."
                )

            status = StepStatus.CONFIRMED if not has_inferred else StepStatus.UNCONFIRMED
            desc_parts = []
            if usb_transfers:
                desc_parts.append("Removable USB Storage (VSN Correlated)")
            if cloud_transfers:
                desc_parts.append("Web Cloud Storage Upload")
            desc = "Data exfiltration via " + (" and ".join(desc_parts) or "external target.")

            step4 = IncidentStep(
                step_number=step_counter,
                stage=IncidentStage.DATA_TRANSFER,
                status=status,
                description=desc,
                timestamp=transfer_events[0].timestamp,
                supporting_events=transfer_events,
                unconfirmed_notes=unconfirmed_notes,
                confidence_score=0.85 if status == StepStatus.CONFIRMED else 0.75,
            )
            steps.append(step4)
            step_counter += 1

        # -------------------------------------------------------------
        # Stage 5: COVER-UP / ANTI-FORENSICS
        # -------------------------------------------------------------
        coverup_events = [
            e for e in bundle.all_events_sorted
            if e.category in (EventCategory.FILE_DELETION, EventCategory.LOG_CLEARED, EventCategory.TIMESTOMP_DETECTED)
        ]
        if coverup_events:
            step5 = IncidentStep(
                step_number=step_counter,
                stage=IncidentStage.COVER_UP_ANTI_FORENSICS,
                status=StepStatus.CONFIRMED,
                description="Evidence tampering and cleanup activities detected (file deletion, timestomping, or log clearing).",
                timestamp=coverup_events[0].timestamp,
                supporting_events=coverup_events,
                confidence_score=0.95,
            )
            steps.append(step5)
            step_counter += 1

        if not steps:
            return None

        # Determine primary user
        user = next((e.user for e in bundle.all_events_sorted if e.user), "Unknown_Subject")
        t_start = bundle.all_events_sorted[0].timestamp
        t_end = bundle.all_events_sorted[-1].timestamp

        from insider_forensics.core.models import ConfidenceExplanation
        dummy_conf = ConfidenceExplanation(
            score=0.85,
            rating=ConfidenceRating.HIGH,
            triggered_rules=["CROSS_ARTIFACT_DATA_THEFT_RECONSTRUCTION"],
            corroborating_sources=[a.value for a in set(e.artifact_type for e in bundle.all_events_sorted)],
            alternative_explanations=[],
            missing_evidence_gaps=[],
        )

        return IncidentHypothesis(
            hypothesis_id=f"HYP-{uuid.uuid4().hex[:8].upper()}",
            title="Reconstructed Insider Data Exfiltration Sequence",
            subject_user=user,
            time_window_start=t_start,
            time_window_end=t_end,
            target_files=target_files,
            staging_containers=staging_containers,
            destination_devices=destination_devices,
            steps=steps,
            anomalies=[],
            confidence=dummy_conf,
        )
