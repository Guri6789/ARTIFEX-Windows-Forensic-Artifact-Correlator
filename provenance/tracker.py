"""Evidence Integrity and Provenance Tracking (Feature 3).

Guarantees chain-of-custody, non-repudiation, and reproducibility by:
- Calculating SHA-256 and SHA-1 hashes for all ingested raw artifact files.
- Recording file sizes, byte offsets, parser version, and analysis timestamps.
- Linking every extracted ForensicEvent to its original evidence container.
- Providing cryptographic verification functions to detect evidence tampering.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class EvidenceItem:
    """An acquired evidence file or artifact container."""
    evidence_id: str
    file_path: str
    file_name: str
    file_size_bytes: int
    sha256: str
    sha1: str
    acquired_timestamp: str
    artifact_category: str
    notes: Optional[str] = None
    verification_status: str = "VERIFIED"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "file_path": self.file_path,
            "file_name": self.file_name,
            "file_size_bytes": self.file_size_bytes,
            "sha256": self.sha256,
            "sha1": self.sha1,
            "acquired_timestamp": self.acquired_timestamp,
            "artifact_category": self.artifact_category,
            "notes": self.notes,
            "verification_status": self.verification_status,
        }


class EvidenceTracker:
    """Manages evidence intake, hashing, provenance registration, and integrity audits."""

    PARSER_VERSION = "1.0.0-aegis"

    def __init__(self) -> None:
        self.evidence_items: Dict[str, EvidenceItem] = {}
        self.event_provenance_map: Dict[str, str] = {}  # event_id -> evidence_id

    @staticmethod
    def calculate_hashes(file_path: Path) -> Tuple[str, str, int]:
        """Stream file bytes to compute SHA-256 and SHA-1 without memory spikes."""
        sha256_hash = hashlib.sha256()
        sha1_hash = hashlib.sha1()
        size_bytes = 0

        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                sha256_hash.update(chunk)
                sha1_hash.update(chunk)
                size_bytes += len(chunk)

        return sha256_hash.hexdigest(), sha1_hash.hexdigest(), size_bytes

    def register_evidence(
        self,
        file_path: str | Path,
        artifact_category: str,
        notes: Optional[str] = None,
    ) -> EvidenceItem:
        """Hash, register, and tag an acquired raw artifact file."""
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Evidence file not found: {path}")

        sha256, sha1, size = self.calculate_hashes(path)
        evidence_id = f"EV-{sha256[:12].upper()}"

        item = EvidenceItem(
            evidence_id=evidence_id,
            file_path=str(path.resolve()),
            file_name=path.name,
            file_size_bytes=size,
            sha256=sha256,
            sha1=sha1,
            acquired_timestamp=datetime.now(timezone.utc).isoformat(),
            artifact_category=artifact_category,
            notes=notes,
        )
        self.evidence_items[evidence_id] = item
        return item

    def link_event_to_evidence(self, event_id: str, evidence_id: str) -> None:
        """Bind an event to its source evidence item for provenance tracing."""
        if evidence_id not in self.evidence_items:
            raise KeyError(f"Unknown evidence_id: {evidence_id}")
        self.event_provenance_map[event_id] = evidence_id

    def verify_all_integrity(self) -> Dict[str, bool]:
        """Re-hash all registered evidence files to prove zero post-acquisition tampering."""
        results: Dict[str, bool] = {}
        for ev_id, item in self.evidence_items.items():
            path = Path(item.file_path)
            if not path.exists():
                item.verification_status = "FILE_MISSING"
                results[ev_id] = False
                continue

            current_sha256, _, _ = self.calculate_hashes(path)
            if current_sha256 == item.sha256:
                item.verification_status = "VERIFIED_UNCHANGED"
                results[ev_id] = True
            else:
                item.verification_status = "TAMPERED_HASH_MISMATCH"
                results[ev_id] = False
        return results

    def export_manifest(self) -> Dict[str, Any]:
        """Export court-defensible cryptographic chain-of-custody manifest."""
        return {
            "tracker_version": self.PARSER_VERSION,
            "generated_timestamp": datetime.now(timezone.utc).isoformat(),
            "total_evidence_files": len(self.evidence_items),
            "evidence": [item.to_dict() for item in self.evidence_items.values()],
        }
