"""Super Timeline CSV Generator (compatible with Timeline Explorer and Plaso)."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import List

from insider_forensics.core.models import ForensicEvent


class CsvTimelineReporter:
    """Exports events into a standardized Super Timeline CSV format."""

    HEADERS = [
        "Timestamp_UTC",
        "Artifact_Source",
        "Fact_Level",
        "Event_Category",
        "Summary",
        "User",
        "Process_Name",
        "Command_Line",
        "Source_File_Path",
        "Volume_Serial",
        "USB_Serial",
        "Drive_Letter",
        "Evidence_ID",
        "Record_ID",
    ]

    def export(self, events: List[ForensicEvent], output_file: Path) -> Path:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        sorted_events = sorted(events, key=lambda e: e.timestamp)

        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(self.HEADERS)

            for ev in sorted_events:
                writer.writerow([
                    ev.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    ev.artifact_type.value,
                    ev.fact_level.value,
                    ev.category.value,
                    ev.summary,
                    ev.user or "",
                    ev.process_name or "",
                    ev.command_line or "",
                    ev.source_file_path or "",
                    ev.volume_serial or "",
                    ev.usb_serial or "",
                    ev.drive_letter or "",
                    ev.evidence_id,
                    ev.record_id or "",
                ])

        return output_file
