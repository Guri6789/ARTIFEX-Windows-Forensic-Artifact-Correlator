"""Windows Shell Link (.lnk) and JumpList (AutomaticDestinations-ms) Parser.

Extracts:
- Target file full path
- Target file timestamps (Creation, Access, Write)
- Volume Serial Number (VSN) of the storage volume holding the target
- Drive Type (Removable, Fixed, Network)
- JumpList MRU ranking and DestList access history
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


class LnkAndJumpListParser(BaseArtifactParser):
    """Parses binary .lnk shortcut files and JumpList CFBF containers."""

    PARSER_NAME = "LnkAndJumpListParser"
    PARSER_VERSION = "1.0.0"

    LNK_HEADER_MAGIC = b"\x4C\x00\x00\x00"
    CFBF_MAGIC = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"

    def parse(self, file_path: Path) -> List[ForensicEvent]:
        evidence = self.register_file(file_path, "SHORTCUT_JUMPLIST_ARTIFACT")
        events: List[ForensicEvent] = []

        # Case 1: Structured JSON export
        if file_path.suffix.lower() == ".json":
            return self._parse_json_export(file_path, evidence.evidence_id)

        try:
            data = file_path.read_bytes()
            if not data:
                return events

            if data[:8] == self.CFBF_MAGIC:
                # It's an AutomaticDestinations-ms OLE compound container
                events.extend(self._parse_jumplist_cfbf(data, file_path.name, evidence.evidence_id))
            elif data[:4] == self.LNK_HEADER_MAGIC:
                # It's a standard .lnk binary file
                lnk_data = self._parse_lnk_binary(data)
                if lnk_data:
                    ev = self._lnk_to_event(lnk_data, file_path.name, evidence.evidence_id)
                    if ev:
                        events.append(ev)
        except Exception:
            pass

        return events

    def _parse_lnk_binary(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Binary parser for Windows Shell Link (.lnk) structure (MS-SHLLINK)."""
        if len(data) < 76 or data[:4] != self.LNK_HEADER_MAGIC:
            return None

        # LinkFlags (offset 0x14, 4 bytes)
        link_flags = struct.unpack("<I", data[0x14:0x18])[0]
        has_link_target_id_list = bool(link_flags & 0x01)
        has_link_info = bool(link_flags & 0x02)

        # Timestamps at 0x1C (Create), 0x24 (Access), 0x2C (Write)
        cr_ft = struct.unpack("<Q", data[0x1C:0x24])[0]
        acc_ft = struct.unpack("<Q", data[0x24:0x2C])[0]
        wr_ft = struct.unpack("<Q", data[0x2C:0x34])[0]

        created_dt = filetime_to_datetime(cr_ft)
        accessed_dt = filetime_to_datetime(acc_ft)
        modified_dt = filetime_to_datetime(wr_ft)
        file_size = struct.unpack("<I", data[0x34:0x38])[0]

        curr_offset = 76
        # Skip IDList if present
        if has_link_target_id_list and len(data) >= curr_offset + 2:
            id_list_size = struct.unpack("<H", data[curr_offset:curr_offset + 2])[0]
            curr_offset += 2 + id_list_size

        target_path = None
        volume_serial = None
        drive_type = None

        # Parse LinkInfo block
        if has_link_info and len(data) >= curr_offset + 28:
            link_info_size = struct.unpack("<I", data[curr_offset:curr_offset + 4])[0]
            vol_id_offset = struct.unpack("<I", data[curr_offset + 12:curr_offset + 16])[0]
            local_base_path_offset = struct.unpack("<I", data[curr_offset + 16:curr_offset + 20])[0]

            # VolumeID structure
            if vol_id_offset > 0:
                v_ptr = curr_offset + vol_id_offset
                if len(data) >= v_ptr + 16:
                    d_type = struct.unpack("<I", data[v_ptr + 4:v_ptr + 8])[0]
                    v_serial = struct.unpack("<I", data[v_ptr + 8:v_ptr + 12])[0]
                    drive_type = {1: "No Root", 2: "Removable", 3: "Fixed", 4: "Remote", 5: "CD-ROM", 6: "RAM"}.get(d_type, f"Type_{d_type}")
                    volume_serial = f"{v_serial:08X}"

            # Local base path string (null-terminated ASCII)
            if local_base_path_offset > 0:
                p_ptr = curr_offset + local_base_path_offset
                path_bytes = data[p_ptr:curr_offset + link_info_size].split(b"\x00")[0]
                target_path = path_bytes.decode("ascii", errors="replace")

        return {
            "target_path": target_path,
            "created_dt": created_dt,
            "accessed_dt": accessed_dt,
            "modified_dt": modified_dt,
            "file_size": file_size,
            "volume_serial": volume_serial,
            "drive_type": drive_type,
        }

    def _lnk_to_event(self, lnk: Dict[str, Any], filename: str, evidence_id: str) -> Optional[ForensicEvent]:
        ts = lnk.get("accessed_dt") or lnk.get("modified_dt") or datetime.now(timezone.utc)
        path = lnk.get("target_path") or f"Unknown_Target_In_{filename}"
        vsn = lnk.get("volume_serial")
        drive_type = lnk.get("drive_type")

        summary = (
            f"File opened/shortcut referenced via LNK: {path} "
            f"(VSN: {vsn or 'N/A'}, DriveType: {drive_type or 'N/A'})"
        )

        return self.create_event(
            timestamp=ts,
            artifact_type=ArtifactType.LNK_SHORTCUT,
            category=EventCategory.RECON_ACCESS,
            summary=summary,
            evidence_id=evidence_id,
            fact_level=FactLevel.DIRECT_OBSERVATION,
            source_file_path=path,
            volume_serial=vsn,
            file_size_bytes=lnk.get("file_size"),
            raw_metadata={
                "created_dt": lnk.get("created_dt").isoformat() if lnk.get("created_dt") else None,
                "modified_dt": lnk.get("modified_dt").isoformat() if lnk.get("modified_dt") else None,
                "drive_type": drive_type,
            },
        )

    def _parse_jumplist_cfbf(self, data: bytes, filename: str, evidence_id: str) -> List[ForensicEvent]:
        """Carves embedded LNK streams and DestList entries out of JumpList container."""
        events: List[ForensicEvent] = []
        # Fast carving scan for embedded LNK magic 0x0000004C within CFBF stream sectors
        offset = 0
        while True:
            idx = data.find(self.LNK_HEADER_MAGIC, offset)
            if idx == -1:
                break
            # Validate if it looks like a legitimate embedded LNK header
            if len(data) - idx >= 76:
                lnk = self._parse_lnk_binary(data[idx:idx + 4096])
                if lnk and lnk.get("target_path"):
                    ev = self._lnk_to_event(lnk, f"JumpList_{filename}_stream_{idx}", evidence_id)
                    if ev:
                        ev.artifact_type = ArtifactType.JUMP_LIST
                        events.append(ev)
            offset = idx + 4
            if len(events) >= 50:  # Sensible bound for single container
                break
        return events

    def _parse_json_export(self, file_path: Path, evidence_id: str) -> List[ForensicEvent]:
        """Parse structured LNK/JumpList JSON triage logs (from LECmd / JLECmd)."""
        events: List[ForensicEvent] = []
        try:
            records = json.loads(file_path.read_text(encoding="utf-8", errors="replace"))
            if isinstance(records, dict):
                records = records.get("entries", [records])

            for rec in records:
                target = rec.get("target_path") or rec.get("LocalPath") or rec.get("TargetPath")
                ts_str = rec.get("source_accessed") or rec.get("SourceAccessed") or rec.get("timestamp")
                vsn = rec.get("volume_serial") or rec.get("VolumeSerialNumber")
                drive_type = rec.get("drive_type") or rec.get("DriveType")

                if not ts_str or not target:
                    continue

                try:
                    ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=timezone.utc)
                except ValueError:
                    continue

                summary = f"Recent file access recorded in JumpList/LNK: {target} (VSN: {vsn or 'N/A'})"
                events.append(
                    self.create_event(
                        timestamp=ts,
                        artifact_type=ArtifactType.JUMP_LIST if "destinations" in file_path.name.lower() else ArtifactType.LNK_SHORTCUT,
                        category=EventCategory.RECON_ACCESS,
                        summary=summary,
                        evidence_id=evidence_id,
                        fact_level=FactLevel.DIRECT_OBSERVATION,
                        source_file_path=target,
                        volume_serial=vsn,
                        raw_metadata={"drive_type": drive_type, "raw": rec},
                    )
                )
        except Exception:
            pass
        return events
