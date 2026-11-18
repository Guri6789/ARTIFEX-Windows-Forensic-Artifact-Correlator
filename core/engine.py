"""Master Forensic Coordination Engine.

Orchestrates:
1. Evidence intake & cryptographic hashing (Feature 3)
2. Multi-artifact parsing (USB, EVTX, Prefetch, LNK, JumpList, MFT, USN, Browser, FTK Imager)
3. Cross-artifact correlation (Feature 4)
4. Data-theft sequence reconstruction (Feature 1)
5. Forensic anomaly & gap analysis (Feature 2)
6. Explainable confidence scoring & hypothesis validation (Feature 5)
7. Multi-format reporting (Markdown, JSON, Super Timeline CSV)
"""

from __future__ import annotations

from dataclasses import dataclass
import sys
from pathlib import Path
from typing import List, Optional

# Add project root to sys.path
_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from insider_forensics.anomaly.gap_analyzer import ForensicAnomalyAnalyzer
from insider_forensics.core.models import (
    ForensicAnomaly,
    ForensicEvent,
    IncidentHypothesis,
)
from insider_forensics.correlation.cross_correlator import (
    CorrelationBundle,
    CrossArtifactCorrelator,
)
from insider_forensics.correlation.reconstruction import DataTheftReconstructionEngine
from insider_forensics.imager.ftk_imager import (
    FtkImagerLogParser,
    FTKImagerController,
)
from insider_forensics.intelligence.confidence_engine import (
    ConfidenceAndExplanationEngine,
)
from insider_forensics.parsers.browser_parser import BrowserHistoryParser
from insider_forensics.parsers.eventlog_parser import WindowsEventLogParser
from insider_forensics.parsers.lnk_jumplist_parser import LnkAndJumpListParser
from insider_forensics.parsers.mft_usn_parser import MftAndUsnParser
from insider_forensics.parsers.prefetch_parser import PrefetchParser
from insider_forensics.parsers.usbstor_parser import UsbArtifactParser
from insider_forensics.provenance.tracker import EvidenceTracker
from insider_forensics.reporters.csv_timeline import CsvTimelineReporter
from insider_forensics.reporters.json_reporter import JsonReporter
from insider_forensics.reporters.markdown_reporter import MarkdownReporter


@dataclass
class InvestigationResult:
    """Complete results of an end-to-end forensic investigation run."""
    tracker: EvidenceTracker
    raw_events: List[ForensicEvent]
    bundle: CorrelationBundle
    hypothesis: Optional[IncidentHypothesis]
    anomalies: List[ForensicAnomaly]


class ForensicInvestigationEngine:
    """Master engine orchestrating all 5 core investigative pillars."""

    def __init__(self) -> None:
        self.tracker = EvidenceTracker()
        self.usb_parser = UsbArtifactParser(self.tracker)
        self.prefetch_parser = PrefetchParser(self.tracker)
        self.lnk_parser = LnkAndJumpListParser(self.tracker)
        self.mft_parser = MftAndUsnParser(self.tracker)
        self.evtx_parser = WindowsEventLogParser(self.tracker)
        self.browser_parser = BrowserHistoryParser(self.tracker)
        self.ftk_parser = FtkImagerLogParser(self.tracker)
        self.ftk_controller = FTKImagerController()

        self.correlator = CrossArtifactCorrelator()
        self.reconstructor = DataTheftReconstructionEngine()
        self.gap_analyzer = ForensicAnomalyAnalyzer()
        self.confidence_engine = ConfidenceAndExplanationEngine()

        self.md_reporter = MarkdownReporter(self.tracker)
        self.json_reporter = JsonReporter(self.tracker)
        self.csv_reporter = CsvTimelineReporter()

    def analyze_directory(self, target_dir: str | Path) -> InvestigationResult:
        """Scan a triage folder, auto-dispatch parsers via magic bytes & name patterns,
        and execute the 5-pillar analysis.
        """
        path = Path(target_dir)
        if not path.exists():
            raise FileNotFoundError(f"Target directory does not exist: {path}")

        files: List[Path] = [p for p in path.rglob("*") if p.is_file()] if path.is_dir() else [path]
        all_events: List[ForensicEvent] = []

        for f in files:
            name_lower = f.name.lower()

            # Read first 16 bytes for magic byte identification
            header = b""
            try:
                with open(f, "rb") as fp:
                    header = fp.read(16)
            except Exception:
                pass

            # 1. FTK Imager Log or Summary text
            if f.suffix.lower() == ".txt" or "summary" in name_lower or "ftk" in name_lower:
                try:
                    head_text = f.read_text(encoding="utf-8", errors="replace")[:2000]
                    if FtkImagerLogParser.is_ftk_log(head_text):
                        all_events.extend(self.ftk_parser.parse(f))
                        continue
                except Exception:
                    pass

            # 2. Binary EVTX (ElfFile\x00) or EVTX name pattern
            if header.startswith(b"ElfFile\x00") or any(k in name_lower for k in (".evtx", "eventlog", "security", "driverframeworks", "winevt")):
                all_events.extend(self.evtx_parser.parse(f))

            # 3. Binary Registry Hive ('regf') or Registry name pattern
            elif header.startswith(b"regf") or any(k in name_lower for k in ("usbstor", "setupapi", "mounted", "system", "software", "ntuser", "sam", "registry", ".reg")):
                all_events.extend(self.usb_parser.parse(f))

            # 4. Windows Prefetch ('MAM\x04', 'SCCA') or .pf extension
            elif header.startswith(b"MAM\x04") or b"SCCA" in header or any(k in name_lower for k in (".pf", "prefetch")):
                all_events.extend(self.prefetch_parser.parse(f))

            # 5. Shortcuts & JumpLists (.lnk header 0x4C, CFBF compound file)
            elif header.startswith(b"\x4C\x00\x00\x00") or header.startswith(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1") or any(k in name_lower for k in (".lnk", "automaticdestinations", "customdestinations", "jumplist")):
                all_events.extend(self.lnk_parser.parse(f))

            # 6. NTFS Metadata (MFT 'FILE' or USN Journal)
            elif header.startswith(b"FILE") or any(k in name_lower for k in ("mft", "usn", "$j")):
                all_events.extend(self.mft_parser.parse(f))

            # 7. Browser Databases (SQLite 'SQLite format 3\x00')
            elif header.startswith(b"SQLite format 3") or any(k in name_lower for k in ("history", "places.sqlite", "browser")):
                all_events.extend(self.browser_parser.parse(f))

            # 8. Structured JSON files fallback
            elif f.suffix.lower() == ".json":
                if "usb" in name_lower or "mounted" in name_lower:
                    all_events.extend(self.usb_parser.parse(f))
                elif "prefetch" in name_lower:
                    all_events.extend(self.prefetch_parser.parse(f))
                elif "lnk" in name_lower or "jumplist" in name_lower or "destinations" in name_lower:
                    all_events.extend(self.lnk_parser.parse(f))
                elif "mft" in name_lower or "usn" in name_lower:
                    all_events.extend(self.mft_parser.parse(f))
                elif "security" in name_lower or "system" in name_lower or "driverframeworks" in name_lower:
                    all_events.extend(self.evtx_parser.parse(f))
                elif "browser" in name_lower or "history" in name_lower:
                    all_events.extend(self.browser_parser.parse(f))

        # Pillar 4: Cross-Artifact Evidence Correlation
        bundle = self.correlator.correlate(all_events)

        # Pillar 1: Data-Theft Sequence Reconstruction & USB Correlation
        hypothesis = self.reconstructor.reconstruct(bundle)

        # Pillar 2: Forensic Anomaly and Evidence-Gap Analysis
        anomalies = self.gap_analyzer.analyze(bundle)

        # Pillar 5: Explainable Investigation and Confidence Engine
        if hypothesis:
            hypothesis.anomalies = anomalies
            hypothesis.confidence = self.confidence_engine.evaluate(hypothesis, bundle, anomalies)

        return InvestigationResult(
            tracker=self.tracker,
            raw_events=all_events,
            bundle=bundle,
            hypothesis=hypothesis,
            anomalies=anomalies,
        )

    def export_reports(self, result: InvestigationResult, output_dir: str | Path) -> None:
        """Export Markdown, JSON, and CSV Super Timeline."""
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        if result.hypothesis:
            self.md_reporter.generate_report(result.hypothesis, result.anomalies, out / "FORENSIC_REPORT.md")
            self.json_reporter.generate_report(result.hypothesis, result.anomalies, out / "forensic_findings.json")

        all_events = result.bundle.all_events_sorted + result.bundle.inferred_events
        self.csv_reporter.export(all_events, out / "super_timeline.csv")
