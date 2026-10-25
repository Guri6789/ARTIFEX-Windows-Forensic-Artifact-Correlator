"""USB and Removable Storage Parser (Registry & SetupAPI).

Extracts evidence from:
- SYSTEM\\CurrentControlSet\\Enum\\USBSTOR
- SYSTEM\\MountedDevices (Drive letter to volume GUID mapping)
- setupapi.dev.log (First device installation timestamp)
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


class UsbArtifactParser(BaseArtifactParser):
    """Parses USB registry dumps, mounted devices mappings, and device logs."""

    PARSER_NAME = "UsbArtifactParser"
    PARSER_VERSION = "1.0.0"

    def parse(self, file_path: Path) -> List[ForensicEvent]:
        """Auto-detect format (JSON export, REG text, or raw setupapi log)."""
        evidence = self.register_file(file_path, "USB_STORAGE_ARTIFACT")
        events: List[ForensicEvent] = []

        content = file_path.read_text(encoding="utf-8", errors="replace")

        # Case 1: Structured JSON intake (from forensic collectors like KAPE/Velociraptor)
        if file_path.suffix.lower() == ".json":
            try:
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
            except json.JSONDecodeError:
                pass

        # Case 2: Parse raw text/setupapi log format
        events.extend(self._parse_setupapi_text(content, evidence.evidence_id))
        return events

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
        # Matches: [Device Install (Hardware initiated) - USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.26\070123456789&0]
        # followed by <<<  Section start 2026/10/24 14:02:11.123
        pattern = re.compile(
            r"\[Device Install.*?USBSTOR\\(Disk&Ven_([^\&]+)&Prod_([^\&]+)[^\]\\]*)\\([^\]\&]+).*?\n"
            r".*?Section start (\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})",
            re.MULTILINE | re.DOTALL,
        )

        for match in pattern.finditer(text):
            vendor = match.group(2)
            product = match.group(3)
            serial = match.group(4)
            time_str = match.group(5)

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
