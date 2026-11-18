"""Windows Event Log (.evtx) Parser for USB, Security, and Anti-Forensics.

Targeted Event IDs:
- DriverFrameworks 2003 / 2004 / 2101: USB physical connection and removal
- Security 1102: The audit log was cleared (Anti-Forensics)
- System 104: The system log was cleared (Anti-Forensics)
- Security 4624: Logon sessions (User attribution)
- Security 4688: Process creation (CLI commands, staging)

Supports:
- Raw binary .evtx files (Chunk 'ElfChnk' and Record '**' parsing with FILETIME)
- Structured JSON exports (from EvtxECmd or python-evtx)
- XML and text exports
"""

from __future__ import annotations

import json
import re
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Add project root to sys.path
_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from insider_forensics.core.models import (
    ArtifactType,
    EventCategory,
    FactLevel,
    ForensicEvent,
)
from insider_forensics.parsers.base import BaseArtifactParser, filetime_to_datetime


class WindowsEventLogParser(BaseArtifactParser):
    """Parses Windows Event Logs for USB device lifecycle and anti-forensics."""

    PARSER_NAME = "WindowsEventLogParser"
    PARSER_VERSION = "2.0.0"

    EVTX_FILE_MAGIC = b"ElfFile\x00"
    EVTX_CHUNK_MAGIC = b"ElfChnk\x00"
    EVTX_RECORD_MAGIC = b"\x2a\x2a\x00\x00"

    def parse(self, file_path: Path) -> List[ForensicEvent]:
        evidence = self.register_file(file_path, "WINDOWS_EVENT_LOG")
        events: List[ForensicEvent] = []

        # Case 1: Structured JSON export
        if file_path.suffix.lower() == ".json":
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
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
            except Exception:
                pass

        # Case 2: Read raw bytes to check for Binary EVTX magic
        try:
            raw_bytes = file_path.read_bytes()
        except Exception:
            return events

        if len(raw_bytes) >= 8 and raw_bytes[:8] == self.EVTX_FILE_MAGIC:
            events.extend(self._parse_binary_evtx(raw_bytes, evidence.evidence_id))
            return events

        # Case 3: XML / Text representation parsing fallback
        text_content = raw_bytes.decode("utf-8", errors="replace")
        events.extend(self._parse_xml_text(text_content, evidence.evidence_id))
        return events

    def _parse_binary_evtx(self, data: bytes, evidence_id: str) -> List[ForensicEvent]:
        """Binary parser for raw .evtx files navigating 64KB chunks and record headers."""
        events: List[ForensicEvent] = []
        chunk_size = 65536
        header_size = 4096

        total_chunks = (len(data) - header_size) // chunk_size
        if total_chunks <= 0 and len(data) >= chunk_size:
            total_chunks = len(data) // chunk_size

        for c_idx in range(max(1, total_chunks)):
            c_offset = header_size + (c_idx * chunk_size)
            if c_offset + chunk_size > len(data):
                c_offset = c_idx * chunk_size
                if c_offset + chunk_size > len(data):
                    break

            chunk = data[c_offset:c_offset + chunk_size]
            if len(chunk) < 512 or chunk[:8] != self.EVTX_CHUNK_MAGIC:
                continue

            events.extend(self._parse_chunk_records(chunk, evidence_id))

        return events

    def _parse_chunk_records(self, chunk: bytes, evidence_id: str) -> List[ForensicEvent]:
        """Parse event records within a 64KB EVTX chunk."""
        events: List[ForensicEvent] = []
        rec_offset = 512  # Records begin after 512-byte chunk header

        while rec_offset + 24 <= len(chunk):
            # Check for record magic '**\x00\x00'
            if chunk[rec_offset:rec_offset + 4] != self.EVTX_RECORD_MAGIC:
                next_pos = chunk.find(self.EVTX_RECORD_MAGIC, rec_offset + 1)
                if next_pos == -1 or next_pos + 24 > len(chunk):
                    break
                rec_offset = next_pos

            rec_size = struct.unpack("<I", chunk[rec_offset + 4:rec_offset + 8])[0]
            if rec_size < 24 or rec_offset + rec_size > len(chunk):
                rec_offset += 4
                continue

            rec_id = struct.unpack("<Q", chunk[rec_offset + 8:rec_offset + 16])[0]
            filetime = struct.unpack("<Q", chunk[rec_offset + 16:rec_offset + 24])[0]
            ts = filetime_to_datetime(filetime)

            if not ts:
                rec_offset += rec_size
                continue

            payload = chunk[rec_offset + 24:rec_offset + rec_size]
            ev = self._parse_binary_record_payload(payload, ts, str(rec_id), evidence_id)
            if ev:
                events.append(ev)

            rec_offset += rec_size

        return events

    def _parse_binary_record_payload(
        self, payload: bytes, ts: datetime, record_id: str, evidence_id: str
    ) -> Optional[ForensicEvent]:
        """Extract EventID, User, and details from record payload strings and BinXML tokens."""
        text_utf16 = payload.decode("utf-16le", errors="ignore")
        text_ascii = payload.decode("latin-1", errors="ignore")
        combined_text = text_utf16 + " " + text_ascii

        # Identify Event ID
        event_id = None
        m_id = re.search(r"<EventID(?:\s+[^>]*>|>)\s*(\d+)", combined_text)
        if m_id:
            event_id = m_id.group(1)
        else:
            for candidate in ("1102", "104", "4624", "4688", "2003", "2004", "2101"):
                if candidate in combined_text:
                    event_id = candidate
                    break

        if not event_id:
            return None

        # Extract User
        user = None
        m_user = re.search(r"(?:TargetUserName|SubjectUserName|UserID)['\"]\s*:\s*['\"]([^'\"]+)['\"]", combined_text, re.I)
        if not m_user:
            m_user = re.search(r"<(?:TargetUserName|SubjectUserName)>([^<]+)<", combined_text, re.I)
        if m_user:
            user = m_user.group(1).strip(" \t\r\n\x00")

        rec = {
            "EventId": event_id,
            "RecordId": record_id,
            "timestamp": ts.isoformat(),
            "user": user,
            "raw_text": combined_text[:400],
        }

        # Anti-Forensic Clearing
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
                record_id=record_id,
                raw_metadata=rec,
            )

        # USB Lifecycle (DriverFrameworks)
        if event_id in ("2003", "2004", "2101"):
            is_attach = event_id in ("2003", "2101")
            cat = EventCategory.USB_ATTACH if is_attach else EventCategory.USB_DETACH
            action_word = "connected / arrived" if is_attach else "disconnected / stopped"

            usb_serial = None
            m_serial = re.search(r"USBSTOR\\.*?\\([A-Za-z0-9\&\_\-\.]+)", combined_text)
            if m_serial:
                usb_serial = m_serial.group(1).split("&")[0].strip(" \t\r\n\x00")

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
                record_id=record_id,
                raw_metadata=rec,
            )

        # Process Execution (4688)
        if event_id == "4688":
            proc = None
            cmd = None
            m_proc = re.search(r"<(?:NewProcessName)>([^<]+)<", combined_text, re.I)
            if m_proc:
                proc = m_proc.group(1).strip(" \t\r\n\x00")
            m_cmd = re.search(r"<(?:CommandLine)>([^<]+)<", combined_text, re.I)
            if m_cmd:
                cmd = m_cmd.group(1).strip(" \t\r\n\x00")

            summary = f"Process spawned (Event 4688): {proc or 'Unknown'} (Command: {cmd or 'N/A'})"
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
                record_id=record_id,
                raw_metadata=rec,
            )

        return None

    def _parse_record(self, rec: Dict[str, Any], evidence_id: str) -> Optional[ForensicEvent]:
        event_id = str(rec.get("EventId") or rec.get("event_id") or rec.get("Id") or "")
        ts_str = rec.get("TimeCreated") or rec.get("timestamp") or rec.get("Time")
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

            usb_serial = None
            m = re.search(r"USBSTOR\\.*?\\([A-Za-z0-9\&\_\-\.]+)", msg)
            if m:
                usb_serial = m.group(1).split("&")[0].strip(" \t\r\n\x00")

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
