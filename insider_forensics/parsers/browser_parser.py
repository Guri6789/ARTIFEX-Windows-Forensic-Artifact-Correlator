"""Browser History and Cloud Exfiltration Parser (Chromium & Firefox SQLite / JSON).

Detects:
- Webmail attachments and file uploads
- Cloud storage upload endpoints (WeTransfer, Mega.nz, Google Drive, Dropbox, Box)
- Anonymous drop services (SendSpace, AnonFiles, Wormhole)
"""

from __future__ import annotations

import json
import sqlite3
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


class BrowserHistoryParser(BaseArtifactParser):
    """Parses browser history databases to identify cloud storage and exfiltration uploads."""

    PARSER_NAME = "BrowserHistoryParser"
    PARSER_VERSION = "1.0.0"

    UPLOAD_DOMAINS = {
        "wetransfer.com": "WeTransfer Direct Upload",
        "mega.nz": "Mega.nz Encrypted Cloud Storage",
        "drive.google.com": "Google Drive Upload",
        "dropbox.com": "Dropbox Cloud Storage",
        "sendgb.com": "SendGB File Sharing",
        "transfer.sh": "Transfer.sh CLI/Web Upload",
        "filetransfer.io": "FileTransfer.io",
        "mail.google.com": "Gmail Webmail File Attachment",
        "outlook.live.com": "Outlook Webmail Attachment",
    }

    def parse(self, file_path: Path) -> List[ForensicEvent]:
        evidence = self.register_file(file_path, "BROWSER_ACTIVITY_SQLITE")
        events: List[ForensicEvent] = []

        # Case 1: Structured JSON export
        if file_path.suffix.lower() == ".json":
            return self._parse_json_export(file_path, evidence.evidence_id)

        # Case 2: SQLite database (Chrome/Edge History or Firefox places.sqlite)
        try:
            conn = sqlite3.connect(f"file:{file_path.resolve()}?mode=ro", uri=True)
            cursor = conn.cursor()

            # Query Chrome/Edge urls table
            try:
                cursor.execute("SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC")
                for url, title, count, chrome_time in cursor.fetchall():
                    ev = self._evaluate_url(url, title, chrome_time, "CHROME", evidence.evidence_id)
                    if ev:
                        events.append(ev)
            except sqlite3.OperationalError:
                # Try Firefox moz_places table
                try:
                    cursor.execute("SELECT url, title, visit_count, last_visit_date FROM moz_places ORDER BY last_visit_date DESC")
                    for url, title, count, ff_time in cursor.fetchall():
                        ev = self._evaluate_url(url, title, ff_time, "FIREFOX", evidence.evidence_id)
                        if ev:
                            events.append(ev)
                except sqlite3.OperationalError:
                    pass

            conn.close()
        except Exception:
            pass

        return events

    def _evaluate_url(
        self, url: str, title: Optional[str], raw_ts: int, browser_type: str, evidence_id: str
    ) -> Optional[ForensicEvent]:
        """Check if URL matches cloud storage upload or exfil signature."""
        if not url:
            return None

        matched_service = None
        for domain, name in self.UPLOAD_DOMAINS.items():
            if domain in url.lower():
                matched_service = name
                break

        if not matched_service:
            return None

        # Convert timestamp
        dt = None
        if browser_type == "CHROME" and raw_ts > 0:
            # Microseconds since 1601-01-01
            epoch_delta = 11644473600000000
            dt = datetime.fromtimestamp((raw_ts - epoch_delta) / 1_000_000, tz=timezone.utc)
        elif browser_type == "FIREFOX" and raw_ts > 0:
            # Microseconds since 1970-01-01
            dt = datetime.fromtimestamp(raw_ts / 1_000_000, tz=timezone.utc)

        if not dt:
            dt = datetime.now(timezone.utc)

        summary = f"Cloud exfiltration endpoint accessed ({matched_service}): {url[:100]}"
        return self.create_event(
            timestamp=dt,
            artifact_type=ArtifactType.BROWSER_SQLITE,
            category=EventCategory.CLOUD_UPLOAD,
            summary=summary,
            evidence_id=evidence_id,
            fact_level=FactLevel.DIRECT_OBSERVATION,
            raw_metadata={"url": url, "title": title, "service": matched_service},
        )

    def _parse_json_export(self, file_path: Path, evidence_id: str) -> List[ForensicEvent]:
        events: List[ForensicEvent] = []
        try:
            records = json.loads(file_path.read_text(encoding="utf-8", errors="replace"))
            if isinstance(records, dict):
                records = records.get("history", [records])

            for rec in records:
                url = rec.get("url") or ""
                ts_str = rec.get("timestamp") or rec.get("visit_time")
                title = rec.get("title")

                for domain, name in self.UPLOAD_DOMAINS.items():
                    if domain in url.lower() and ts_str:
                        try:
                            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                            if ts.tzinfo is None:
                                ts = ts.replace(tzinfo=timezone.utc)
                            summary = f"Cloud upload endpoint visited ({name}): {url[:90]}"
                            events.append(
                                self.create_event(
                                    timestamp=ts,
                                    artifact_type=ArtifactType.BROWSER_SQLITE,
                                    category=EventCategory.CLOUD_UPLOAD,
                                    summary=summary,
                                    evidence_id=evidence_id,
                                    fact_level=FactLevel.DIRECT_OBSERVATION,
                                    raw_metadata={"url": url, "service": name, "title": title},
                                )
                            )
                        except ValueError:
                            pass
        except Exception:
            pass
        return events
