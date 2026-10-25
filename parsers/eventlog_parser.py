"""Windows Event Log (.evtx) Parser for USB, Security, and Anti-Forensics.

Targeted Event IDs:
- DriverFrameworks 2003 / 2004 / 2101: USB physical connection and removal
- Security 1102: The audit log was cleared (Anti-Forensics)
- System 104: The system log was cleared (Anti-Forensics)
- Security 4624: Logon sessions (User attribution)
- Security 4688: Process creation (CLI commands, staging)
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from insider_forensics.core.models import (
    ArtifactType,
    EventCategory,
    FactLevel,
    ForensicEvent,
)
from insider_forensics.parsers.base import BaseArtifactParser


class WindowsEventLogParser(BaseArtifactParser):
    """Parses Windows Event Logs for USB device lifecycle and anti-forensics."""

    PARSER_NAME = "WindowsEventLogParser"
    PARSER_VERSION = "1.0.0"

    def parse(self, file_path: Path) -> List[ForensicEvent]:
        evidence = self.register_file(file_path, "WINDOWS_EVENT_LOG")
        events: List[ForensicEvent] = []

        content = file_path.read_text(encoding="utf-8", errors="replace")

        # Case 1: Structured JSON export (from EvtxECmd or python-evtx dump)
        if file_path.suffix.lower() == ".json":
            try:
                data = json.loads(content)
                if isinstance(data, list):
                    for rec in data:
                        ev = self._parse_record(rec, evidence.evidence_id)
                        if ev:
                            events.append(ev)
                elif isinstance(data, dict):
                    for rec in data.get("events", [data]):
                        ev = self._parse_record(rec, evidence.evidence_id)
                        if ev:
                            events.append(ev)
                return events
            except json.JSONDecodeError:
                pass

        # Case 2: XML / Text representation parsing
        events.extend(self._parse_xml_text(content, evidence.evidence_id))
        return events

    def _parse_record(self, rec: Dict[str, Any], evidence_id: str) -> Optional[ForensicEvent]:
        event_id = str(rec.get("EventId") or rec.get("event_id") or rec.get("Id") or "")
        ts_str = rec.get("TimeCreated") or rec.get("timestamp") or rec.get("Time")
        channel = rec.get("Channel") or rec.get("channel", "")
        user = rec.get("TargetUserName") or rec.get("user") or rec.get("SubjectUserName")
        rec_num = str(rec.get("RecordId") or rec.get("record_id") or "N/A")

        if not ts_str:
            return None

        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
        except ValueError:
            return None

        # 1. Anti-Forensic Log Cleared
        if event_id in ("1102", "104"):
            log_name = "Security Audit Log" if event_id == "1102" else "System Event Log"
            summary = f"CRITICAL ANTI-FORENSICS: {log_name} was explicitly CLEARED by user: {user or 'Unknown'}"
            return self.create_event(
                timestamp=ts,
                artifact_type=ArtifactType.EVENT_LOG_SECURITY if event_id == "1102" else ArtifactType.EVENT_LOG_SYSTEM,
                category=EventCategory.LOG_CLEARED,
                summary=summary,
                evidence_id=evidence_id,
                fact_level=FactLevel.DIRECT_OBSERVATION,
                user=user,
                record_id=rec_num,
                raw_metadata=rec,
            )

        # 2. USB Connection Lifecycle (DriverFrameworks-UserMode)
        if event_id in ("2003", "2004", "2101"):
            msg = str(rec.get("Message") or rec.get("Payload") or "")
            is_attach = event_id in ("2003", "2101")
            cat = EventCategory.USB_ATTACH if is_attach else EventCategory.USB_DETACH
            action_word = "connected / arrived" if is_attach else "disconnected / stopped"

            # Extract serial and vendor if embedded in message
            usb_serial = None
            m = re.search(r"USBSTOR\\.*?\\([A-Za-z0-9\&\_\-\.]+)", msg)
            if m:
                usb_serial = m.group(1).split("&")[0]

            summary = f"USB device {action_word} logged via DriverFrameworks (Event {event_id}, Serial: {usb_serial or 'Unknown'})"
            return self.create_event(
                timestamp=ts,
                artifact_type=ArtifactType.EVENT_LOG_DRIVER_FRAMEWORKS,
                category=cat,
                summary=summary,
                evidence_id=evidence_id,
                fact_level=FactLevel.DIRECT_OBSERVATION,
                usb_serial=usb_serial,
                user=user,
                record_id=rec_num,
                raw_metadata=rec,
            )

        # 3. Process Execution (Event 4688)
        if event_id == "4688":
            proc = rec.get("NewProcessName") or rec.get("process")
            cmd = rec.get("CommandLine") or rec.get("command_line")
            summary = f"Process spawned (Event 4688): {proc} (Command: {cmd})"
            return self.create_event(
                timestamp=ts,
                artifact_type=ArtifactType.EVENT_LOG_SECURITY,
                category=EventCategory.PROCESS_EXECUTION,
                summary=summary,
                evidence_id=evidence_id,
                fact_level=FactLevel.DIRECT_OBSERVATION,
                process_name=proc,
                command_line=cmd,
                user=user,
                record_id=rec_num,
                raw_metadata=rec,
            )

        return None

    def _parse_xml_text(self, text: str, evidence_id: str) -> List[ForensicEvent]:
        """Regex parser for XML-formatted EVTX records."""
        events: List[ForensicEvent] = []
        pattern = re.compile(
            r"<Event [^>]*>.*?<EventID>(\d+)</EventID>.*?"
            r"<TimeCreated SystemTime=['\"]([^'\"]+)['\"].*?"
            r"(?:<Security UserID=['\"]([^'\"]*)['\"])?.*?"
            r"</Event>",
            re.DOTALL,
        )

        for match in pattern.finditer(text):
            event_id = match.group(1)
            time_str = match.group(2)
            user_id = match.group(3)

            try:
                ts = datetime.fromisoformat(time_str.replace("Z", "+00:00"))
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
            except ValueError:
                continue

            rec = {"EventId": event_id, "TimeCreated": time_str, "user": user_id}
            ev = self._parse_record(rec, evidence_id)
            if ev:
                events.append(ev)

        return events
