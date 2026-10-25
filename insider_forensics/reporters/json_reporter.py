"""JSON Structured Forensic Report Generator."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from insider_forensics.core.models import (
    ForensicAnomaly,
    IncidentHypothesis,
)
from insider_forensics.provenance.tracker import EvidenceTracker


class JsonReporter:
    """Generates a complete, structured JSON export of the investigation."""

    def __init__(self, tracker: EvidenceTracker) -> None:
        self.tracker = tracker

    def generate_report(
        self,
        hypothesis: IncidentHypothesis,
        anomalies: List[ForensicAnomaly],
        output_file: Path,
    ) -> str:
        data: Dict[str, Any] = {
            "investigation_schema_version": "1.0.0",
            "hypothesis": hypothesis.to_dict(),
            "anomalies": [a.to_dict() for a in anomalies],
            "evidence_manifest": self.tracker.export_manifest(),
        }

        json_str = json.dumps(data, indent=2)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(json_str, encoding="utf-8")
        return json_str
