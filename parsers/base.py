"""Base parser interface with integrated provenance tracking and timestamp decoding."""

from __future__ import annotations

import abc
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

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
from insider_forensics.provenance.tracker import EvidenceItem, EvidenceTracker


def filetime_to_datetime(filetime: int) -> Optional[datetime]:
    """Convert a 64-bit Windows FILETIME integer into a Python datetime (UTC).

    FILETIME represents the number of 100-nanosecond intervals since
    January 1, 1601 (UTC).
    """
    if filetime <= 0:
        return None
    try:
        # 116444736000000000 is 100-ns intervals between 1601-01-01 and 1970-01-01
        epoch_delta = 116444736000000000
        unix_timestamp_sec = (filetime - epoch_delta) / 10_000_000
        return datetime.fromtimestamp(unix_timestamp_sec, tz=timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None


class BaseArtifactParser(abc.ABC):
    """Abstract class for all forensic artifact parsers."""

    PARSER_NAME = "BaseParser"
    PARSER_VERSION = "1.0.0"

    def __init__(self, tracker: Optional[EvidenceTracker] = None) -> None:
        self.tracker = tracker or EvidenceTracker()

    def register_file(self, file_path: Path, artifact_category: str) -> EvidenceItem:
        """Register input file in the evidence provenance registry."""
        return self.tracker.register_evidence(
            file_path=file_path,
            artifact_category=artifact_category,
            notes=f"Parsed by {self.PARSER_NAME} v{self.PARSER_VERSION}",
        )

    def create_event(
        self,
        timestamp: datetime,
        artifact_type: ArtifactType,
        category: EventCategory,
        summary: str,
        evidence_id: str,
        fact_level: FactLevel = FactLevel.DIRECT_OBSERVATION,
        **kwargs,
    ) -> ForensicEvent:
        """Helper to create a validated, provenance-linked ForensicEvent."""
        event_id = f"EVT-{uuid.uuid4().hex[:10].upper()}"
        event = ForensicEvent(
            event_id=event_id,
            timestamp=timestamp,
            artifact_type=artifact_type,
            category=category,
            fact_level=fact_level,
            summary=summary,
            evidence_id=evidence_id,
            **kwargs,
        )
        self.tracker.link_event_to_evidence(event_id, evidence_id)
        return event

    @abc.abstractmethod
    def parse(self, file_path: Path) -> List[ForensicEvent]:
        """Parse raw artifact and return normalized ForensicEvent list."""
        raise NotImplementedError
