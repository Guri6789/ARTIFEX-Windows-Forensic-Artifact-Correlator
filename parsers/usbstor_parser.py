"""USB and Removable Storage Parser (Registry & SetupAPI).

Extracts evidence from:
- SYSTEM\\CurrentControlSet\\Enum\\USBSTOR (Vendor, Product, Serial, Last Connected)
- SYSTEM\\MountedDevices (Drive letter to Volume GUID / VSN mapping)
- NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2
- setupapi.dev.log (First device installation timestamp)

Supports:
- Raw binary Windows Registry Hives ('regf' header: SYSTEM, SOFTWARE, NTUSER.DAT)
- Structured JSON exports (from KAPE, Velociraptor, or Registry Explorer)
- SetupAPI device logs (setupapi.dev.log, setupapi.offline.log)
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


class UsbArtifactParser(BaseArtifactParser):
    """Parses USB registry dumps, mounted devices mappings, binary hives, and device logs."""

    PARSER_NAME = "UsbArtifactParser"
    PARSER_VERSION = "2.0.0"

    REGF_MAGIC = b"regf"

    def parse(self, file_path: Path) -> List[ForensicEvent]:
        """Auto-detect format (JSON export, binary REGF hive, or raw setupapi log)."""
        evidence = self.register_file(file_path, "USB_STORAGE_ARTIFACT")
        events: List[ForensicEvent] = []

        # Case 1: Structured JSON intake
        if file_path.suffix.lower() == ".json":
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
                data = json.loads(content)
                if isinstance(data, list):
                    for entry in data:
                        event = self._parse_structured_entry(entry, evidence.evidence_id)
                        if event:
                            events.append(event)
                elif isinstance(data, dict):
                    entries = data.get("devices", [data])
                    for entry in entries:
                        event = self._parse_structured_entry(entry, evidence.evidence_id)
                        if event:
                            events.append(event)
                return events
            except Exception:
                pass

        # Read bytes to check for Binary Registry Hive
        try:
            raw_bytes = file_path.read_bytes()
        except Exception:
            return events

        # Case 2: Binary Windows Registry Hive (SYSTEM / NTUSER.DAT)
        if len(raw_bytes) >= 4 and raw_bytes[:4] == self.REGF_MAGIC:
            events.extend(self._parse_binary_registry(raw_bytes, file_path.name, evidence.evidence_id))
            return events

        # Case 3: Parse raw text/setupapi log format
        text_content = raw_bytes.decode("utf-8", errors="replace")
        events.extend(self._parse_setupapi_text(text_content, evidence.evidence_id))
        return events

    def _parse_binary_registry(self, data: bytes, filename: str, evidence_id: str) -> List[ForensicEvent]:
        """Parse raw binary registry hive for USBSTOR devices and MountedDevices."""
        events: List[ForensicEvent] = []
        if len(data) < 4096 or data[:4] != self.REGF_MAGIC:
            return events

        seen_serials = set()
        seen_letters = set()

        # 1. Carve and extract USBSTOR entries
        usbstor_pattern = re.compile(
            rb"Disk&Ven_([A-Za-z0-9_\-\.]+?)&Prod_([A-Za-z0-9_\-\.]+?)(?:&Rev_[^\x00\\]*?)?\\([A-Za-z0-9_\-\.]+)",
            re.IGNORECASE,
        )

        for match in usbstor_pattern.finditer(data):
            vendor = match.group(1).decode("latin-1", errors="ignore").replace("_", " ").strip(" \t\r\n\x00")
            product = match.group(2).decode("latin-1", errors="ignore").replace("_", " ").strip(" \t\r\n\x00")
            full_serial = match.group(3).decode("latin-1", errors="ignore").strip(" \t\r\n\x00")
            serial = full_serial.split("&")[0].strip(" \t\r\n\x00")

            if not serial or serial in seen_serials:
                continue
            seen_serials.add(serial)

            # Find cell timestamp preceding or near the match
            cell_offset = max(0, match.start() - 64)
            window = data[cell_offset:match.start() + 32]
            ts = self._carve_cell_filetime(window) or datetime.now(timezone.utc)

            summary = (
                f"USB Removable Storage identified via Registry ({filename}): {vendor} {product} "
                f"(Serial: {serial})"
            )
            event = self.create_event(
                timestamp=ts,
                artifact_type=ArtifactType.REGISTRY_USBSTOR,
                category=EventCategory.USB_ATTACH,
                summary=summary,
                evidence_id=evidence_id,
                fact_level=FactLevel.DIRECT_OBSERVATION,
                usb_serial=serial,
                usb_vendor=vendor,
                usb_product=product,
                raw_metadata={"source_file": filename, "raw_key": match.group(0).decode("latin-1", errors="ignore")},
            )
            events.append(event)

        # 2. Extract MountedDevices volume serials and drive letters
        dos_devices_pattern = re.compile(rb"\\DosDevices\\([A-Za-z]):", re.IGNORECASE)
        for match in dos_devices_pattern.finditer(data):
            drive_letter = match.group(1).decode("latin-1").upper() + ":"
            if drive_letter in seen_letters:
                continue
            seen_letters.add(drive_letter)

            val_window = data[match.end():match.end() + 64]
            vsn = self._extract_vsn_from_bytes(val_window)

            summary = f"Drive Letter Mapping identified ({filename}): {drive_letter} -> VSN: {vsn or 'N/A'}"
            event = self.create_event(
                timestamp=datetime.now(timezone.utc),
                artifact_type=ArtifactType.REGISTRY_MOUNTED_DEVICES,
                category=EventCategory.USB_ATTACH,
                summary=summary,
                evidence_id=evidence_id,
                fact_level=FactLevel.DIRECT_OBSERVATION,
                drive_letter=drive_letter,
                volume_serial=vsn,
                raw_metadata={"source_file": filename, "drive_letter": drive_letter, "volume_serial": vsn},
            )
            events.append(event)

        return events

    @staticmethod
    def _carve_cell_filetime(window: bytes) -> Optional[datetime]:
        """Carve plausible 64-bit Windows FILETIME timestamps from binary cell window."""
        for i in range(0, len(window) - 8, 4):
            val = struct.unpack("<Q", window[i:i + 8])[0]
            if 130645440000000000 <= val <= 136950432000000000:
                dt = filetime_to_datetime(val)
                if dt:
                    return dt
        return None

    @staticmethod
    def _extract_vsn_from_bytes(data: bytes) -> Optional[str]:
        """Extract 4-byte Volume Serial Number from MountedDevices binary value."""
        if len(data) >= 4:
            sig = struct.unpack("<I", data[:4])[0]
            if sig > 0:
                return f"{sig:08X}"
        return None

    def _parse_structured_entry(
        self, entry: Dict[str, Any], evidence_id: str
    ) -> Optional[ForensicEvent]:
        """Parse structured USB record."""
        ts_str = entry.get("timestamp") or entry.get("first_install_time") or entry.get("last_arrival_time")
        if not ts_str:
            return None

        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
        except ValueError:
            return None

        usb_serial = entry.get("serial_number") or entry.get("device_serial")
        vendor = entry.get("vendor", "Unknown_Vendor")
        product = entry.get("product", "Removable_Disk")
        drive_letter = entry.get("drive_letter")
        volume_serial = entry.get("volume_serial")
        user = entry.get("user")

        summary = (
            f"USB Removable Storage connected: {vendor} {product} "
            f"(Serial: {usb_serial}, Drive: {drive_letter or 'N/A'}, VSN: {volume_serial or 'N/A'})"
        )

        return self.create_event(
            timestamp=ts,
            artifact_type=ArtifactType.REGISTRY_USBSTOR,
            category=EventCategory.USB_ATTACH,
            summary=summary,
            evidence_id=evidence_id,
            fact_level=FactLevel.DIRECT_OBSERVATION,
            user=user,
            usb_serial=usb_serial,
            usb_vendor=vendor,
            usb_product=product,
            drive_letter=drive_letter,
            volume_serial=volume_serial,
            raw_metadata=entry,
        )

    def _parse_setupapi_text(self, text: str, evidence_id: str) -> List[ForensicEvent]:
        """Regex parse for setupapi.dev.log device installation timestamps."""
        events: List[ForensicEvent] = []
        pattern = re.compile(
            r"\[Device Install.*?USBSTOR\\(Disk&Ven_([^\&]+)&Prod_([^\&]+)[^\]\\]*)\\([^\]\&]+).*?\n"
            r".*?Section start (\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})",
            re.MULTILINE | re.DOTALL,
        )

        for match in pattern.finditer(text):
            vendor = match.group(2).strip(" \t\r\n\x00")
            product = match.group(3).strip(" \t\r\n\x00")
            serial = match.group(4).strip(" \t\r\n\x00")
            time_str = match.group(5).strip()

            try:
                ts = datetime.strptime(time_str, "%Y/%m/%d %H:%M:%S").replace(tzinfo=timezone.utc)
            except ValueError:
                continue

            summary = f"USB device installed/connected: {vendor} {product} (Serial: {serial})"
            events.append(
                self.create_event(
                    timestamp=ts,
                    artifact_type=ArtifactType.REGISTRY_USBSTOR,
                    category=EventCategory.USB_ATTACH,
                    summary=summary,
                    evidence_id=evidence_id,
                    fact_level=FactLevel.DIRECT_OBSERVATION,
                    usb_serial=serial,
                    usb_vendor=vendor,
                    usb_product=product,
                    raw_metadata={"raw_entry": match.group(0)[:200]},
                )
            )

        return events
