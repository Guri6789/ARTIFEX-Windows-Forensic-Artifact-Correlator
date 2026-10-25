"""Cross-Artifact Evidence Correlation Engine (Feature 4).

Connects Windows Event Logs, Registry artifacts, LNK shortcuts, Jump Lists,
NTFS metadata, and USB records.
Groups related events by:
- Timestamps (Temporal clustering)
- Target file paths & file names
- Device identifiers (USB Serial, Volume Serial Number, Drive Letter)
- User identity

Strictly separates DIRECT_OBSERVATION facts from INFERRED_RELATIONSHIP linkages.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple

from insider_forensics.core.models import (
    ArtifactType,
    EventCategory,
    FactLevel,
    ForensicEvent,
)


@dataclass
class DeviceSession:
    """Represents a continuous period where a specific removable storage device was connected."""
    session_id: str
    usb_serial: Optional[str]
    volume_serial: Optional[str]
    drive_letter: Optional[str]
    vendor: Optional[str]
    product: Optional[str]
    attach_time: datetime
    detach_time: Optional[datetime]
    attach_event: Optional[ForensicEvent] = None
    detach_event: Optional[ForensicEvent] = None
    associated_file_events: List[ForensicEvent] = field(default_factory=list)


@dataclass
class FileTrail:
    """Cross-artifact evidence trail for a specific file or staging archive."""
    file_name: str
    canonical_path: Optional[str]
    observed_in_artifacts: Set[ArtifactType] = field(default_factory=set)
    events: List[ForensicEvent] = field(default_factory=list)
    volume_serials: Set[str] = field(default_factory=set)
    associated_processes: Set[str] = field(default_factory=set)
    is_staging_archive: bool = False
    was_deleted: bool = False
    timestomp_detected: bool = False


@dataclass
class CorrelationBundle:
    """The master indexed correlation output."""
    all_events_sorted: List[ForensicEvent]
    device_sessions: List[DeviceSession]
    file_trails: Dict[str, FileTrail]
    temporal_clusters: List[List[ForensicEvent]]
    inferred_events: List[ForensicEvent]


class CrossArtifactCorrelator:
    """Correlates disparate Windows artifact records into connected investigative trails."""

    def __init__(self, temporal_window_minutes: int = 15) -> None:
        self.temporal_window = timedelta(minutes=temporal_window_minutes)

    def correlate(self, events: List[ForensicEvent]) -> CorrelationBundle:
        """Run multi-dimensional correlation over normalized events."""
        # 1. Sort strictly by timestamp
        sorted_events = sorted(events, key=lambda e: e.timestamp)

        # 2. Reconstruct Device Attachment Sessions
        device_sessions = self._build_device_sessions(sorted_events)

        # 3. Build File-centric cross-artifact trails
        file_trails = self._build_file_trails(sorted_events)

        # 4. Synthesize Inferred Relationships (separating them from direct facts)
        inferred_events = self._synthesize_inferred_relationships(device_sessions, file_trails, sorted_events)

        # 5. Build Temporal Clusters
        temporal_clusters = self._build_temporal_clusters(sorted_events)

        return CorrelationBundle(
            all_events_sorted=sorted_events,
            device_sessions=device_sessions,
            file_trails=file_trails,
            temporal_clusters=temporal_clusters,
            inferred_events=inferred_events,
        )

    def _build_device_sessions(self, events: List[ForensicEvent]) -> List[DeviceSession]:
        """Correlate USB attach and detach events, mapping drive letters and VSNs."""
        sessions: List[DeviceSession] = []
        open_sessions: Dict[str, DeviceSession] = {}

        for ev in events:
            if ev.category == EventCategory.USB_ATTACH:
                key = ev.usb_serial or ev.drive_letter or "UNKNOWN_USB"
                session = DeviceSession(
                    session_id=f"SESS-{uuid.uuid4().hex[:8].upper()}",
                    usb_serial=ev.usb_serial,
                    volume_serial=ev.volume_serial,
                    drive_letter=ev.drive_letter,
                    vendor=ev.usb_vendor,
                    product=ev.usb_product,
                    attach_time=ev.timestamp,
                    detach_time=None,
                    attach_event=ev,
                )
                open_sessions[key] = session
                sessions.append(session)

            elif ev.category == EventCategory.USB_DETACH:
                key = ev.usb_serial or ev.drive_letter or "UNKNOWN_USB"
                if key in open_sessions:
                    open_sessions[key].detach_time = ev.timestamp
                    open_sessions[key].detach_event = ev
                    del open_sessions[key]

        # Set default detach window if not explicitly observed
        for s in sessions:
            if s.detach_time is None:
                s.detach_time = s.attach_time + timedelta(hours=2)

        return sessions

    def _build_file_trails(self, events: List[ForensicEvent]) -> Dict[str, FileTrail]:
        """Group events by file name or path across LNK, JumpLists, Prefetch, and USN."""
        trails: Dict[str, FileTrail] = {}

        for ev in events:
            path = ev.source_file_path or ev.target_file_path
            if not path:
                continue

            fname = path.replace("/", "\\").split("\\")[-1].strip()
            if not fname:
                continue

            fname_key = fname.lower()
            if fname_key not in trails:
                trails[fname_key] = FileTrail(
                    file_name=fname,
                    canonical_path=path,
                    is_staging_archive=any(fname.lower().endswith(ext) for ext in (".zip", ".7z", ".rar", ".tar")),
                )

            trail = trails[fname_key]
            trail.observed_in_artifacts.add(ev.artifact_type)
            trail.events.append(ev)

            if ev.volume_serial:
                trail.volume_serials.add(ev.volume_serial.upper())

            if ev.process_name:
                trail.associated_processes.add(ev.process_name.upper())

            if ev.category == EventCategory.FILE_DELETION:
                trail.was_deleted = True

            if ev.category == EventCategory.TIMESTOMP_DETECTED:
                trail.timestomp_detected = True

        return trails

    def _synthesize_inferred_relationships(
        self,
        sessions: List[DeviceSession],
        trails: Dict[str, FileTrail],
        events: List[ForensicEvent],
    ) -> List[ForensicEvent]:
        """Deduce causal relationships without confusing them with direct facts."""
        inferred: List[ForensicEvent] = []

        # Rule 1: Link LNK VSN match with USB storage device
        for trail in trails.values():
            for vsn in trail.volume_serials:
                for sess in sessions:
                    if sess.volume_serial and sess.volume_serial.upper() == vsn:
                        summary = (
                            f"INFERRED LINKAGE: File '{trail.file_name}' was physically present on "
                            f"USB device ({sess.vendor or 'USB'} Serial: {sess.usb_serial}) "
                            f"based on exact Volume Serial Number match (VSN: {vsn})"
                        )
                        inferred_ev = ForensicEvent(
                            event_id=f"INF-{uuid.uuid4().hex[:8].upper()}",
                            timestamp=trail.events[0].timestamp if trail.events else sess.attach_time,
                            artifact_type=ArtifactType.LNK_SHORTCUT,
                            category=EventCategory.FILE_TRANSFER_USB,
                            fact_level=FactLevel.INFERRED_RELATIONSHIP,
                            summary=summary,
                            source_file_path=trail.canonical_path,
                            volume_serial=vsn,
                            usb_serial=sess.usb_serial,
                            evidence_id=trail.events[0].evidence_id if trail.events else "CORRELATION_ENGINE",
                            raw_metadata={"rule": "VSN_USB_SERIAL_MATCH", "trail_file": trail.file_name},
                        )
                        inferred.append(inferred_ev)

        # Rule 2: Correlate file activity occurring strictly inside an active USB session window
        for sess in sessions:
            for ev in events:
                if ev.source_file_path and sess.attach_time <= ev.timestamp <= (sess.detach_time or datetime.max):
                    if sess.drive_letter and sess.drive_letter.upper() in ev.source_file_path.upper():
                        sess.associated_file_events.append(ev)

        return inferred

    def _build_temporal_clusters(self, events: List[ForensicEvent]) -> List[List[ForensicEvent]]:
        """Cluster events into temporal burst windows."""
        clusters: List[List[ForensicEvent]] = []
        if not events:
            return clusters

        current_cluster: List[ForensicEvent] = [events[0]]
        for ev in events[1:]:
            if ev.timestamp - current_cluster[-1].timestamp <= self.temporal_window:
                current_cluster.append(ev)
            else:
                clusters.append(current_cluster)
                current_cluster = [ev]

        if current_cluster:
            clusters.append(current_cluster)

        return clusters
