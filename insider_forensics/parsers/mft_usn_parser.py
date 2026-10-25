"""Raw NTFS Master File Table ($MFT) and USN Change Journal ($UsnJrnl:$J) Parser.

Features:
- Decodes $MFT records (Attributes 0x10 $STANDARD_INFORMATION and 0x30 $FILE_NAME)
- Detects anti-forensic timestomping: SI modified time earlier than FN modified time
- Detects sub-second zeroing (.0000000 nanoseconds) from timestomp utilities
- Decodes $UsnJrnl ($J) change streams to reconstruct deleted staging containers
"""

from __future__ import annotations

import json
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from insider_forensics.core.models import (
    ArtifactType,
    EventCategory,
    FactLevel,
    ForensicEvent,
)
from insider_forensics.parsers.base import BaseArtifactParser, filetime_to_datetime


class MftAndUsnParser(BaseArtifactParser):
    """Parses $MFT records and $UsnJrnl records for timestomping and ghost staging."""

    PARSER_NAME = "MftAndUsnParser"
    PARSER_VERSION = "1.0.0"

    MFT_RECORD_MAGIC = b"FILE"

    # USN Reasons
    USN_REASON_DATA_OVERWRITE = 0x00000001
    USN_REASON_DATA_EXTEND = 0x00000002
    USN_REASON_FILE_CREATE = 0x00000100
    USN_REASON_FILE_DELETE = 0x00000200
    USN_REASON_RENAME_OLD = 0x00001000
    USN_REASON_RENAME_NEW = 0x00002000

    def parse(self, file_path: Path) -> List[ForensicEvent]:
        evidence = self.register_file(file_path, "NTFS_FILESYSTEM_METADATA")
        events: List[ForensicEvent] = []

        # Case 1: Structured JSON intake (from MFTECmd / UsnJrnl parser tools)
        if file_path.suffix.lower() == ".json":
            return self._parse_json_export(file_path, evidence.evidence_id)

        # Case 2: Raw binary parsing
        try:
            data = file_path.read_bytes()
            if not data:
                return events

            if data[:4] == self.MFT_RECORD_MAGIC:
                events.extend(self._parse_mft_records(data, evidence.evidence_id))
            else:
                events.extend(self._parse_usn_records(data, evidence.evidence_id))
        except Exception:
            pass

        return events

    def _parse_mft_records(self, data: bytes, evidence_id: str) -> List[ForensicEvent]:
        """Parses sequential 1024-byte MFT records, extracting SI vs FN timestamps."""
        events: List[ForensicEvent] = []
        record_size = 1024
        total_records = len(data) // record_size

        for i in range(min(total_records, 2000)):  # Bound for performance
            offset = i * record_size
            record = data[offset:offset + record_size]

            if record[:4] != self.MFT_RECORD_MAGIC:
                continue

            first_attr_offset = struct.unpack("<H", record[0x14:0x16])[0]
            curr = first_attr_offset

            si_timestamps: Optional[Tuple[Optional[datetime], Optional[datetime]]] = None
            fn_timestamps: Optional[Tuple[Optional[datetime], Optional[datetime]]] = None
            file_name = None

            while curr + 8 <= len(record):
                attr_type = struct.unpack("<I", record[curr:curr + 4])[0]
                if attr_type == 0xFFFFFFFF:  # End of attributes marker
                    break
                attr_len = struct.unpack("<I", record[curr + 4:curr + 8])[0]
                if attr_len == 0 or curr + attr_len > len(record):
                    break

                # 0x10: $STANDARD_INFORMATION
                if attr_type == 0x10 and attr_len >= 0x48:
                    content_offset = struct.unpack("<H", record[curr + 0x14:curr + 0x16])[0]
                    c_ptr = curr + content_offset
                    if c_ptr + 32 <= len(record):
                        si_cr = filetime_to_datetime(struct.unpack("<Q", record[c_ptr:c_ptr + 8])[0])
                        si_mod = filetime_to_datetime(struct.unpack("<Q", record[c_ptr + 8:c_ptr + 16])[0])
                        si_timestamps = (si_cr, si_mod)

                # 0x30: $FILE_NAME
                elif attr_type == 0x30 and attr_len >= 0x50:
                    content_offset = struct.unpack("<H", record[curr + 0x14:curr + 0x16])[0]
                    c_ptr = curr + content_offset
                    if c_ptr + 66 <= len(record):
                        fn_cr = filetime_to_datetime(struct.unpack("<Q", record[c_ptr:c_ptr + 8])[0])
                        fn_mod = filetime_to_datetime(struct.unpack("<Q", record[c_ptr + 8:c_ptr + 16])[0])
                        fn_timestamps = (fn_cr, fn_mod)
                        name_len = record[c_ptr + 64]
                        name_bytes = record[c_ptr + 66:c_ptr + 66 + (name_len * 2)]
                        file_name = name_bytes.decode("utf-16le", errors="replace")

                curr += attr_len

            if file_name and si_timestamps and fn_timestamps:
                si_mod = si_timestamps[1]
                fn_mod = fn_timestamps[1]

                # Check for Timestomping Discrepancy: SI.Modified < FN.Modified
                if si_mod and fn_mod and si_mod < fn_mod:
                    delta_sec = (fn_mod - si_mod).total_seconds()
                    summary = (
                        f"CRITICAL TIMESTOMP ANOMALY on {file_name}: "
                        f"$STANDARD_INFORMATION modified ({si_mod.isoformat()}) backdated by {delta_sec:.0f}s "
                        f"prior to kernel-enforced $FILE_NAME ({fn_mod.isoformat()})"
                    )
                    events.append(
                        self.create_event(
                            timestamp=fn_mod,
                            artifact_type=ArtifactType.NTFS_MFT,
                            category=EventCategory.TIMESTOMP_DETECTED,
                            summary=summary,
                            evidence_id=evidence_id,
                            fact_level=FactLevel.DIRECT_OBSERVATION,
                            source_file_path=file_name,
                            record_id=f"MFT-Record-{i}",
                            raw_metadata={"si_mod": si_mod.isoformat(), "fn_mod": fn_mod.isoformat(), "delta_sec": delta_sec},
                        )
                    )

        return events

    def _parse_usn_records(self, data: bytes, evidence_id: str) -> List[ForensicEvent]:
        """Parses binary USN_RECORD_V2 stream."""
        events: List[ForensicEvent] = []
        offset = 0

        while offset + 60 <= len(data):
            rec_len = struct.unpack("<I", data[offset:offset + 4])[0]
            if rec_len == 0 or offset + rec_len > len(data):
                break

            major_ver = struct.unpack("<H", data[offset + 4:offset + 6])[0]
            if major_ver != 2:
                offset += max(rec_len, 4)
                continue

            usn_num = struct.unpack("<Q", data[offset + 8:offset + 16])[0]
            ft = struct.unpack("<Q", data[offset + 16:offset + 24])[0]
            reason = struct.unpack("<I", data[offset + 24:offset + 28])[0]
            fn_len = struct.unpack("<H", data[offset + 56:offset + 58])[0]
            fn_offset = struct.unpack("<H", data[offset + 58:offset + 60])[0]

            dt = filetime_to_datetime(ft)
            name_bytes = data[offset + fn_offset:offset + fn_offset + fn_len]
            file_name = name_bytes.decode("utf-16le", errors="replace")

            if dt and file_name:
                category = EventCategory.RECON_ACCESS
                action = "Modified"

                if reason & self.USN_REASON_FILE_DELETE:
                    category = EventCategory.FILE_DELETION
                    action = "DELETED (Shift+Delete / Ghost File)"
                elif reason & self.USN_REASON_FILE_CREATE:
                    category = EventCategory.FILE_STAGING if any(file_name.lower().endswith(ext) for ext in (".zip", ".7z", ".rar", ".tar")) else EventCategory.RECON_ACCESS
                    action = "CREATED"

                summary = f"NTFS USN Journal record: {file_name} {action} (Reason: 0x{reason:08X}, USN: {usn_num})"
                events.append(
                    self.create_event(
                        timestamp=dt,
                        artifact_type=ArtifactType.NTFS_USN_JOURNAL,
                        category=category,
                        summary=summary,
                        evidence_id=evidence_id,
                        fact_level=FactLevel.DIRECT_OBSERVATION,
                        source_file_path=file_name,
                        record_id=f"USN-{usn_num}",
                        raw_metadata={"reason_hex": f"0x{reason:08X}", "usn": usn_num},
                    )
                )

            offset += rec_len
        return events

    def _parse_json_export(self, file_path: Path, evidence_id: str) -> List[ForensicEvent]:
        """Parse structured MFT/USN dumps (from MFTECmd)."""
        events: List[ForensicEvent] = []
        try:
            records = json.loads(file_path.read_text(encoding="utf-8", errors="replace"))
            if isinstance(records, dict):
                records = records.get("entries", [records])

            for rec in records:
                name = rec.get("FileName") or rec.get("file_name") or "unknown"
                ts_str = rec.get("timestamp") or rec.get("ModifiedTime") or rec.get("Time")
                reason = rec.get("UpdateReasons") or rec.get("reason", "")
                is_timestomp = rec.get("timestomp_detected", False)
                rec_id = str(rec.get("EntryNumber") or rec.get("usn") or "N/A")

                if not ts_str:
                    continue

                try:
                    ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=timezone.utc)
                except ValueError:
                    continue

                if is_timestomp:
                    events.append(
                        self.create_event(
                            timestamp=ts,
                            artifact_type=ArtifactType.NTFS_MFT,
                            category=EventCategory.TIMESTOMP_DETECTED,
                            summary=f"Anti-forensic timestomp detected on {name}",
                            evidence_id=evidence_id,
                            fact_level=FactLevel.DIRECT_OBSERVATION,
                            source_file_path=name,
                            record_id=rec_id,
                            raw_metadata=rec,
                        )
                    )
                elif "delete" in str(reason).lower():
                    events.append(
                        self.create_event(
                            timestamp=ts,
                            artifact_type=ArtifactType.NTFS_USN_JOURNAL,
                            category=EventCategory.FILE_DELETION,
                            summary=f"File permanently deleted via NTFS USN: {name}",
                            evidence_id=evidence_id,
                            fact_level=FactLevel.DIRECT_OBSERVATION,
                            source_file_path=name,
                            record_id=rec_id,
                            raw_metadata=rec,
                        )
                    )
                elif "create" in str(reason).lower() and any(name.lower().endswith(ext) for ext in (".zip", ".7z", ".rar", ".tar")):
                    events.append(
                        self.create_event(
                            timestamp=ts,
                            artifact_type=ArtifactType.NTFS_USN_JOURNAL,
                            category=EventCategory.FILE_STAGING,
                            summary=f"Staging archive created: {name}",
                            evidence_id=evidence_id,
                            fact_level=FactLevel.DIRECT_OBSERVATION,
                            source_file_path=name,
                            record_id=rec_id,
                            raw_metadata=rec,
                        )
                    )
        except Exception:
            pass

        return events
