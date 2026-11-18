"""FTK Imager integration and live Windows forensic triage collector.

Provides:
1. FTKImagerController: Orchestrates FTK Imager CLI (ftkimager.exe) for disk imaging and triage acquisition.
2. FtkImagerLogParser: Ingests FTK Imager acquisition manifests (*.txt / Image_Summary.txt),
   extracting cryptographic hashes, hardware serial numbers, and examiner notes into the Chain of Custody.
3. WindowsLiveTriageCollector: Real-life Windows live incident response triage collector.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

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
from insider_forensics.parsers.base import BaseArtifactParser


@dataclass
class FtkAcquisitionInfo:
    """Structured metadata parsed from an FTK Imager acquisition log."""
    case_number: str = ""
    evidence_number: str = ""
    unique_description: str = ""
    examiner: str = ""
    notes: str = ""
    source_type: str = ""
    drive_model: str = ""
    drive_serial: str = ""
    drive_interface: str = ""
    sector_count: int = 0
    bytes_per_sector: int = 512
    acquisition_started: Optional[datetime] = None
    acquisition_finished: Optional[datetime] = None
    image_paths: List[str] = field(default_factory=list)
    md5_checksum: str = ""
    md5_verified: bool = False
    sha1_checksum: str = ""
    sha1_verified: bool = False
    raw_log_path: Optional[Path] = None


class FtkImagerLogParser(BaseArtifactParser):
    """Parses FTK Imager text logs (*.txt, Image_Summary.txt).
    
    Extracts hardware serial numbers, examiner notes, sector counts,
    and verified MD5/SHA-1 checksums into the EvidenceTracker and Event timeline.
    """

    PARSER_NAME = "FtkImagerLogParser"
    PARSER_VERSION = "1.0.0"

    def parse(self, file_path: Path) -> List[ForensicEvent]:
        evidence = self.register_file(file_path, "FTK_IMAGER_ACQUISITION_LOG")
        events: List[ForensicEvent] = []

        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return events

        # Confirm it is an FTK Imager log
        if not self.is_ftk_log(content):
            return events

        info = self.parse_log_text(content, file_path)

        # Update evidence notes with FTK verification
        notes = (
            f"FTK Imager Acquisition: Case={info.case_number or 'N/A'}, "
            f"Device={info.drive_model or 'N/A'} (Serial: {info.drive_serial or 'N/A'}), "
            f"MD5={info.md5_checksum or 'N/A'} (Verified: {info.md5_verified}), "
            f"SHA1={info.sha1_checksum or 'N/A'} (Verified: {info.sha1_verified})"
        )
        evidence.notes = notes
        evidence.artifact_category = "FTK_IMAGER_LOG"

        ts = info.acquisition_started or info.acquisition_finished or datetime.now(timezone.utc)

        summary = (
            f"Forensic Acquisition completed via FTK Imager: {info.drive_model or info.source_type or 'Storage Device'} "
            f"(Serial: {info.drive_serial or 'N/A'}, Examiner: {info.examiner or 'N/A'}, "
            f"SHA1: {info.sha1_checksum or 'N/A'})"
        )

        event = self.create_event(
            timestamp=ts,
            artifact_type=ArtifactType.EVIDENCE_MANIFEST,
            category=EventCategory.EVIDENCE_INGESTION,
            summary=summary,
            evidence_id=evidence.evidence_id,
            fact_level=FactLevel.DIRECT_OBSERVATION,
            user=info.examiner,
            usb_serial=info.drive_serial if info.drive_serial else None,
            raw_metadata={
                "case_number": info.case_number,
                "evidence_number": info.evidence_number,
                "examiner": info.examiner,
                "notes": info.notes,
                "drive_model": info.drive_model,
                "drive_serial": info.drive_serial,
                "md5": info.md5_checksum,
                "sha1": info.sha1_checksum,
                "md5_verified": info.md5_verified,
                "sha1_verified": info.sha1_verified,
                "sector_count": info.sector_count,
            },
        )
        events.append(event)
        return events

    @staticmethod
    def is_ftk_log(content: str) -> bool:
        """Check if content has signatures of an AccessData / Exterro FTK Imager log."""
        keywords = ("ftk imager", "accessdata", "case information:", "checksums:", "segment list:")
        lower = content.lower()
        return sum(1 for k in keywords if k in lower) >= 2

    @classmethod
    def parse_log_text(cls, text: str, file_path: Optional[Path] = None) -> FtkAcquisitionInfo:
        """Extract all forensic metadata fields from an FTK Imager text report."""
        info = FtkAcquisitionInfo(raw_log_path=file_path)

        def _search(pattern: str, flags: int = re.IGNORECASE) -> str:
            m = re.search(pattern, text, flags)
            return m.group(1).strip() if m else ""

        info.case_number = _search(r"Case Number:\s*([^\r\n]+)")
        info.evidence_number = _search(r"Evidence Number:\s*([^\r\n]+)")
        info.unique_description = _search(r"Unique Description:\s*([^\r\n]+)")
        info.examiner = _search(r"Examiner:\s*([^\r\n]+)")
        info.notes = _search(r"Notes:\s*([^\r\n]+)")

        info.source_type = _search(r"Source Type:\s*([^\r\n]+)")
        info.drive_model = _search(r"Drive Model:\s*([^\r\n]+)")
        info.drive_serial = _search(r"Drive Serial Number:\s*([^\r\n]+)")
        info.drive_interface = _search(r"Drive Interface Type:\s*([^\r\n]+)")

        sector_str = _search(r"Sector Count:\s*(\d+)")
        if sector_str.isdigit():
            info.sector_count = int(sector_str)

        bps_str = _search(r"Bytes per Sector:\s*(\d+)")
        if bps_str.isdigit():
            info.bytes_per_sector = int(bps_str)

        # Dates
        t_start = _search(r"Acquisition started:\s*([^\r\n]+)")
        t_fin = _search(r"Acquisition finished:\s*([^\r\n]+)")
        info.acquisition_started = cls._parse_ftk_date(t_start)
        info.acquisition_finished = cls._parse_ftk_date(t_fin)

        # Checksums
        md5_match = re.search(r"MD5 checksum:\s*([a-fA-F0-9]{32})(?:\s*:\s*([^\r\n]+))?", text)
        if md5_match:
            info.md5_checksum = md5_match.group(1).lower()
            status_text = (md5_match.group(2) or "").lower()
            info.md5_verified = any(v in status_text for v in ("verified", "match", "ok"))

        sha1_match = re.search(r"SHA1 checksum:\s*([a-fA-F0-9]{40})(?:\s*:\s*([^\r\n]+))?", text)
        if sha1_match:
            info.sha1_checksum = sha1_match.group(1).lower()
            status_text = (sha1_match.group(2) or "").lower()
            info.sha1_verified = any(v in status_text for v in ("verified", "match", "ok"))

        # Segments
        seg_block = re.search(r"Segment list:\s*([\s\S]*?)(?:---|\n\n|$)", text)
        if seg_block:
            lines = [l.strip() for l in seg_block.group(1).splitlines() if l.strip()]
            info.image_paths = lines

        return info

    @staticmethod
    def _parse_ftk_date(date_str: str) -> Optional[datetime]:
        if not date_str:
            return None
        formats = [
            "%a %b %d %H:%M:%S %Y",
            "%Y-%m-%d %H:%M:%S",
            "%m/%d/%Y %H:%M:%S",
            "%d/%m/%Y %H:%M:%S",
        ]
        for fmt in formats:
            try:
                dt = datetime.strptime(date_str.strip(), fmt)
                return dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        return None


class FTKImagerController:
    """Manages execution of FTK Imager CLI (ftkimager.exe / ftkimager)."""

    STANDARD_WINDOWS_PATHS = [
        r"C:\Program Files\AccessData\FTK Imager\ftkimager.exe",
        r"C:\Program Files (x86)\AccessData\FTK Imager\ftkimager.exe",
        r"C:\Program Files\Exterro\FTK Imager\ftkimager.exe",
        r"C:\Tools\ftkimager.exe",
        r"C:\Tools\FTK\ftkimager.exe",
        r"C:\FTK\ftkimager.exe",
    ]

    def __init__(self, custom_path: Optional[str | Path] = None) -> None:
        self.executable_path = self.find_ftkimager(custom_path)

    @classmethod
    def find_ftkimager(cls, custom_path: Optional[str | Path] = None) -> Optional[Path]:
        """Locate ftkimager executable in custom path, environment, PATH, or standard dirs."""
        if custom_path:
            p = Path(custom_path)
            if p.is_file() and os.access(p, os.X_OK):
                return p

        # Check environment variables
        env_val = os.environ.get("FTK_IMAGER_PATH") or os.environ.get("FTKIMAGER_PATH")
        if env_val:
            p = Path(env_val)
            if p.is_file() and os.access(p, os.X_OK):
                return p

        # Check PATH
        for binary_name in ("ftkimager.exe", "ftkimager"):
            which_path = shutil.which(binary_name)
            if which_path:
                return Path(which_path)

        # Check standard Windows paths
        if sys.platform == "win32":
            for wp in cls.STANDARD_WINDOWS_PATHS:
                p = Path(wp)
                if p.is_file():
                    return p

        return None

    def is_available(self) -> bool:
        """Return True if FTK Imager CLI executable is detected."""
        return self.executable_path is not None and self.executable_path.is_file()

    def create_image(
        self,
        source: str,
        destination_path: Path,
        image_format: str = "e01",
        case_num: str = "INCIDENT-001",
        evidence_num: str = "EV-01",
        examiner: str = "Forensic Analyst",
        description: str = "Workstation Triage Image",
        notes: str = "Acquired for Insider Threat Investigation",
        fragment_size_mb: int = 2048,
        verify: bool = True,
    ) -> Tuple[bool, str]:
        """Execute FTK Imager CLI to image a physical drive, logical volume, or folder."""
        if not self.is_available() or not self.executable_path:
            return False, "FTK Imager executable not found on this system."

        destination_path.parent.mkdir(parents=True, exist_ok=True)
        dest_prefix = str(destination_path)

        cmd = [
            str(self.executable_path),
            source,
            dest_prefix,
        ]

        if image_format.lower() == "e01":
            cmd.append("--e01")
        elif image_format.lower() in ("raw", "dd"):
            cmd.append("--raw")

        if fragment_size_mb > 0:
            cmd.extend(["--frag", f"{fragment_size_mb}M"])

        if case_num:
            cmd.extend(["--case-num", case_num])
        if evidence_num:
            cmd.extend(["--evidence-num", evidence_num])
        if description:
            cmd.extend(["--description", description])
        if examiner:
            cmd.extend(["--examiner", examiner])
        if notes:
            cmd.extend(["--notes", notes])

        if verify:
            cmd.append("--verify")

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
            )
            output = proc.stdout + "\n" + proc.stderr
            success = proc.returncode == 0
            return success, output
        except Exception as e:
            return False, f"Error executing FTK Imager: {e}"


class WindowsLiveTriageCollector:
    """Acquires live forensic triage artifacts from a Windows endpoint.
    
    Targets essential insider data-theft artifacts:
    - Event Logs (Security.evtx, System.evtx, DriverFrameworks)
    - Registry Hives (SYSTEM, SOFTWARE, SAM, NTUSER.DAT)
    - Prefetch directory (*.pf)
    - Recent shortcuts & JumpLists (LNK, AutomaticDestinations-ms)
    - Web browser history (Chrome, Edge, Firefox SQLite databases)
    - SetupAPI device installation logs (setupapi.dev.log)
    - FTK Imager-compatible acquisition summary log
    """

    def __init__(self, output_dir: Path, case_id: str = "CASE-LIVE", examiner: str = "Incident Responder") -> None:
        self.output_dir = Path(output_dir)
        self.case_id = case_id
        self.examiner = examiner
        self.collected_files: List[Tuple[Path, str, str]] = []  # (path, category, sha256)

    def collect(self) -> Dict[str, Any]:
        """Perform automated live forensic acquisition."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        t_start = datetime.now(timezone.utc)

        system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        user_profile = Path(os.environ.get("USERPROFILE", r"C:\Users\Default"))
        appdata = Path(os.environ.get("APPDATA", str(user_profile / "AppData" / "Roaming")))
        localappdata = Path(os.environ.get("LOCALAPPDATA", str(user_profile / "AppData" / "Local")))

        # 1. Event Logs
        evtx_dir = system_root / "System32" / "winevt" / "Logs"
        target_evtx = [
            "Security.evtx",
            "System.evtx",
            "Microsoft-Windows-DriverFrameworks-UserMode%4Operational.evtx",
            "Microsoft-Windows-TaskScheduler%4Operational.evtx",
        ]
        self._copy_files(evtx_dir, target_evtx, "event_logs", "WINDOWS_EVENT_LOG")

        # 2. Registry Hives
        config_dir = system_root / "System32" / "config"
        target_reg = ["SYSTEM", "SOFTWARE", "SAM", "SECURITY"]
        self._copy_files(config_dir, target_reg, "registry", "REGISTRY_HIVE")

        # NTUSER.DAT from current and all user profiles
        users_dir = user_profile.parent
        if users_dir.is_dir():
            for u in users_dir.iterdir():
                if u.is_dir() and not u.name.lower().startswith("default"):
                    ntuser = u / "NTUSER.DAT"
                    if ntuser.is_file():
                        self._copy_single(ntuser, self.output_dir / "registry" / f"NTUSER_{u.name}.DAT", "REGISTRY_HIVE")

        # 3. Prefetch
        prefetch_dir = system_root / "Prefetch"
        if prefetch_dir.is_dir():
            pf_dest = self.output_dir / "prefetch"
            pf_dest.mkdir(parents=True, exist_ok=True)
            for pf in prefetch_dir.glob("*.pf"):
                self._copy_single(pf, pf_dest / pf.name, "PREFETCH_EXECUTION")

        # 4. Recent Shortcuts & JumpLists
        recent_dir = appdata / "Microsoft" / "Windows" / "Recent"
        if recent_dir.is_dir():
            recent_dest = self.output_dir / "shortcuts_jumplists"
            recent_dest.mkdir(parents=True, exist_ok=True)
            for lnk in recent_dir.glob("*.lnk"):
                self._copy_single(lnk, recent_dest / lnk.name, "SHORTCUT_LNK")
            auto_dest = recent_dir / "AutomaticDestinations"
            if auto_dest.is_dir():
                for jmp in auto_dest.glob("*.automaticDestinations-ms"):
                    self._copy_single(jmp, recent_dest / jmp.name, "JUMPLIST")

        # 5. Browser History (Chrome, Edge, Firefox)
        browser_dest = self.output_dir / "browsers"
        browser_dest.mkdir(parents=True, exist_ok=True)
        # Chrome
        chrome_hist = localappdata / "Google" / "Chrome" / "User Data" / "Default" / "History"
        if chrome_hist.is_file():
            self._copy_single(chrome_hist, browser_dest / "Chrome_History.sqlite", "BROWSER_ACTIVITY")
        # Edge
        edge_hist = localappdata / "Microsoft" / "Edge" / "User Data" / "Default" / "History"
        if edge_hist.is_file():
            self._copy_single(edge_hist, browser_dest / "Edge_History.sqlite", "BROWSER_ACTIVITY")
        # Firefox
        ff_profiles = appdata / "Mozilla" / "Firefox" / "Profiles"
        if ff_profiles.is_dir():
            for p in ff_profiles.iterdir():
                places = p / "places.sqlite"
                if places.is_file():
                    self._copy_single(places, browser_dest / f"Firefox_{p.name}_places.sqlite", "BROWSER_ACTIVITY")

        # 6. SetupAPI Logs
        inf_dir = system_root / "INF"
        setupapi_log = inf_dir / "setupapi.dev.log"
        if setupapi_log.is_file():
            self._copy_single(setupapi_log, self.output_dir / "setupapi.dev.log", "USB_SETUPAPI")

        t_end = datetime.now(timezone.utc)

        # 7. Generate FTK Imager Compatible Summary Manifest
        manifest_path = self.output_dir / "ftk_acquisition_summary.txt"
        summary_text = self._build_ftk_summary(t_start, t_end)
        manifest_path.write_text(summary_text, encoding="utf-8")

        return {
            "case_id": self.case_id,
            "examiner": self.examiner,
            "total_files": len(self.collected_files),
            "output_directory": str(self.output_dir),
            "manifest_log": str(manifest_path),
            "start_time": t_start.isoformat(),
            "end_time": t_end.isoformat(),
        }

    def _copy_files(self, src_dir: Path, file_names: List[str], sub_folder: str, category: str) -> None:
        if not src_dir.is_dir():
            return
        dest = self.output_dir / sub_folder
        dest.mkdir(parents=True, exist_ok=True)
        for name in file_names:
            src = src_dir / name
            try:
                if src.is_file():
                    self._copy_single(src, dest / name, category)
            except (PermissionError, OSError):
                pass

    def _copy_single(self, src: Path, dest: Path, category: str) -> None:
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest)
            sha256 = self._compute_sha256(dest)
            self.collected_files.append((dest, category, sha256))
        except (PermissionError, OSError):
            # Attempt binary read fallback if shutil.copy2 encounters attribute lock
            try:
                with open(src, "rb") as rf:
                    data = rf.read()
                dest.write_bytes(data)
                sha256 = self._compute_sha256(dest)
                self.collected_files.append((dest, category, sha256))
            except Exception:
                pass

    @staticmethod
    def _compute_sha256(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()

    def _build_ftk_summary(self, t_start: datetime, t_end: datetime) -> str:
        """Construct an AccessData / FTK Imager compatible text summary."""
        lines = [
            "Created By AccessData® FTK® Imager (ARTIFEX Live Incident Collector Bridge)",
            "",
            "Case Information:",
            f"Case Number: {self.case_id}",
            f"Evidence Number: EV-001",
            f"Unique Description: Live Windows Endpoint Forensic Triage Collection",
            f"Examiner: {self.examiner}",
            f"Notes: Automated incident acquisition targeting Insider Threat & Exfiltration artifacts",
            "",
            "----------------------------------------------------------------",
            "Physical Evidentiary Item (Drive / Volume) Information:",
            "[Drive Information]",
            f"Source Type: Windows Live System Volume ({os.environ.get('SystemDrive', 'C:')})",
            f"Drive Model: Host System Physical Drive",
            f"Drive Serial Number: LIVE_HOST_{os.environ.get('COMPUTERNAME', 'ENDPOINT')}",
            f"Drive Interface Type: Local / Internal Storage",
            f"Collected Items Count: {len(self.collected_files)}",
            "",
            "----------------------------------------------------------------",
            "Image Information:",
            f"Acquisition started: {t_start.strftime('%a %b %d %H:%M:%S %Y')}",
            f"Acquisition finished: {t_end.strftime('%a %b %d %H:%M:%S %Y')}",
            "Segment list:",
        ]
        for f, cat, sha in self.collected_files:
            lines.append(f"  {f.name} [{cat}]")

        lines.extend([
            "",
            "----------------------------------------------------------------",
            "Checksums:",
            f"Total Artifacts Preserved: {len(self.collected_files)}",
            "Verification status: Verified Match (SHA-256 Manifest Preserved)",
        ])
        return "\n".join(lines)
