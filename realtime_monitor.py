"""Real-Time Windows Insider Threat Monitoring Daemon for Removable Devices.

Continuously monitors live Windows telemetry without requiring manual snapshots:
1. Live Removable Storage Detection & VSN Extraction (Drive letter, VSN, FS, capacity)
2. Live Removable Drive File Activity & Exfiltration Interceptor (detects files copied to USB, computes SHA-256)
3. Live Windows Event Logs (DriverFrameworks 2003/2101, Storage-ClassPnP 507, Partition 1006, Security 4688/1102, System 104)
4. Live Windows Registry (HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR & MountedDevices)
5. Live Prefetch Execution Directory (C:\\Windows\\Prefetch\\*.pf)
6. Live User Recent Shortcuts & JumpLists (%APPDATA%\\Microsoft\\Windows\\Recent)
7. Chronological 5-stage data-theft reconstruction and dynamic report maintenance
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Terminal ANSI styling
C_CYAN = "\033[96m"
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_RED = "\033[91m"
C_WHITE = "\033[97m"
C_BOLD = "\033[1m"
C_DIM = "\033[90m"
C_RESET = "\033[0m"

if sys.platform == "win32":
    import winreg
else:
    winreg = None

_root = Path(__file__).resolve().parent
for _p in (_root, _root.parent):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from insider_forensics.core.engine import ForensicInvestigationEngine
from insider_forensics.core.models import (
    ArtifactType,
    EventCategory,
    FactLevel,
    ForensicAnomaly,
    ForensicEvent,
    IncidentHypothesis,
    IncidentStage,
    IncidentStep,
    StepStatus,
)


@dataclass
class RemovableDriveInfo:
    """Details of a connected removable storage drive."""
    drive_letter: str
    drive_root: str
    volume_name: str
    volume_serial: str
    file_system: str
    drive_type: str
    total_bytes: int = 0
    free_bytes: int = 0
    usb_vendor: Optional[str] = None
    usb_product: Optional[str] = None
    usb_serial: Optional[str] = None


@dataclass
class ExfiltratedFileInfo:
    """File copied or modified on a removable drive."""
    path: str
    file_name: str
    size_bytes: int
    sha256: str
    md5: str
    timestamp: datetime
    drive_letter: str
    volume_serial: str
    usb_serial: Optional[str]
    is_staging_archive: bool


class WindowsRemovableDriveWatcher:
    """Interacts directly with Windows Kernel32 & Registry to detect removable drives and VSNs."""

    STAGING_EXTS = {
        ".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz", ".cab", ".iso", ".vhd"
    }
    SENSITIVE_EXTS = {
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".csv",
        ".sql", ".db", ".sqlite", ".kdbx", ".key", ".pem", ".pst", ".eml",
        ".txt", ".py", ".c", ".cpp", ".rs", ".go", ".java", ".json", ".xml"
    }

    def __init__(self) -> None:
        self.is_windows = sys.platform == "win32"
        self._kernel32 = ctypes.windll.kernel32 if self.is_windows else None
        self._known_drives: Dict[str, RemovableDriveInfo] = {}

    def get_connected_removable_drives(self) -> List[RemovableDriveInfo]:
        """Enumerate all currently mounted removable drives with volume labels and VSNs."""
        drives: List[RemovableDriveInfo] = []
        if not self.is_windows or not self._kernel32:
            return drives

        try:
            bitmask = self._kernel32.GetLogicalDrives()
        except Exception:
            return drives

        usbstor_map = self._query_usbstor_registry()

        for i in range(26):
            if bitmask & (1 << i):
                letter = chr(65 + i) + ":"
                root = letter + "\\"
                try:
                    drive_type_code = self._kernel32.GetDriveTypeW(root)
                except Exception:
                    continue

                # 2 = DRIVE_REMOVABLE. Also check for external USB fixed drives (type 3 with USBSTOR serial)
                is_removable = (drive_type_code == 2)
                type_name = "Removable" if is_removable else ("Fixed" if drive_type_code == 3 else f"Type_{drive_type_code}")

                vol_name_buf = ctypes.create_unicode_buffer(261)
                fs_name_buf = ctypes.create_unicode_buffer(261)
                vsn_val = ctypes.c_ulong(0)

                vsn_str = ""
                vol_name = ""
                fs_name = ""

                res = self._kernel32.GetVolumeInformationW(
                    root, vol_name_buf, 260, ctypes.byref(vsn_val), None, None, fs_name_buf, 260
                )
                if res:
                    vsn_str = f"{vsn_val.value:08X}"
                    vol_name = vol_name_buf.value
                    fs_name = fs_name_buf.value

                # Get disk free space
                free_b = ctypes.c_ulonglong(0)
                total_b = ctypes.c_ulonglong(0)
                try:
                    self._kernel32.GetDiskFreeSpaceExW(root, ctypes.byref(free_b), ctypes.byref(total_b), None)
                except Exception:
                    pass

                # If removable or mapped to a USB device
                usb_info = usbstor_map.get(letter.upper(), {})
                if is_removable or usb_info or (drive_type_code == 2):
                    info = RemovableDriveInfo(
                        drive_letter=letter,
                        drive_root=root,
                        volume_name=vol_name or "Removable Disk",
                        volume_serial=vsn_str,
                        file_system=fs_name or "FAT32",
                        drive_type=type_name,
                        total_bytes=total_b.value,
                        free_bytes=free_b.value,
                        usb_vendor=usb_info.get("vendor"),
                        usb_product=usb_info.get("product"),
                        usb_serial=usb_info.get("serial"),
                    )
                    drives.append(info)

        return drives

    def _query_usbstor_registry(self) -> Dict[str, Dict[str, str]]:
        """Query HKLM USBSTOR and MountedDevices to map drive letters to USB hardware serials."""
        mapping: Dict[str, Dict[str, str]] = {}
        if winreg is None:
            return mapping

        devices: List[Dict[str, str]] = []
        base_key = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base_key) as root_key:
                idx = 0
                while True:
                    try:
                        dev_class = winreg.EnumKey(root_key, idx)
                        idx += 1
                    except OSError:
                        break

                    vendor, product = "USB", dev_class
                    if "Ven_" in dev_class and "Prod_" in dev_class:
                        parts = dev_class.split("&")
                        for p in parts:
                            if p.startswith("Ven_"):
                                vendor = p[4:].replace("_", " ")
                            elif p.startswith("Prod_"):
                                product = p[5:].replace("_", " ")

                    with winreg.OpenKey(root_key, dev_class) as class_key:
                        s_idx = 0
                        while True:
                            try:
                                raw_serial = winreg.EnumKey(class_key, s_idx)
                                s_idx += 1
                                serial = raw_serial.split("&")[0]
                                devices.append({"serial": serial, "vendor": vendor, "product": product})
                            except OSError:
                                break
        except OSError:
            pass

        # Try to correlate with MountedDevices \DosDevices\X:
        mounted_key = r"SYSTEM\MountedDevices"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, mounted_key) as m_key:
                m_idx = 0
                while True:
                    try:
                        name, val, val_type = winreg.EnumValue(m_key, m_idx)
                        m_idx += 1
                        if name.startswith("\\DosDevices\\"):
                            d_letter = name.split("\\")[-1].upper()
                            if isinstance(val, bytes):
                                val_str = val.decode("latin-1", errors="ignore")
                                for dev in devices:
                                    if dev["serial"].lower() in val_str.lower():
                                        mapping[d_letter] = dev
                                        break
                    except OSError:
                        break
        except OSError:
            pass

        # If any devices found and not mapped, provide the latest as fallback
        if devices and not mapping:
            mapping["default"] = devices[-1]

        return mapping


class LiveWindowsEventLogIngestor:
    """Reads recent and real-time Windows Event Logs via built-in wevtutil."""

    def __init__(self) -> None:
        self.is_windows = sys.platform == "win32"
        self._last_record_ids: Dict[str, int] = {}

    def fetch_live_events(self) -> List[ForensicEvent]:
        """Query active event log channels for USB arrival, process creation, and anti-forensics."""
        events: List[ForensicEvent] = []
        if not self.is_windows:
            return events

        # 1. DriverFrameworks-UserMode / Operational (USB PnP Lifecycle)
        events.extend(self._query_channel("Microsoft-Windows-DriverFrameworks-UserMode/Operational", count=10))

        # 2. Partition / Diagnostic (Partition & Volume Mount)
        events.extend(self._query_channel("Microsoft-Windows-Partition/Diagnostic", count=10))

        # 3. Security (Audit Clearing 1102 & Process 4688)
        events.extend(self._query_channel(
            "Security",
            query="*[System[(EventID=1102 or EventID=4688)]]",
            count=10
        ))

        # 4. System (Log Clearing 104)
        events.extend(self._query_channel(
            "System",
            query="*[System[(EventID=104)]]",
            count=10
        ))

        return events

    def _query_channel(self, channel: str, query: Optional[str] = None, count: int = 10) -> List[ForensicEvent]:
        events: List[ForensicEvent] = []
        cmd = ["wevtutil.exe", "qe", channel, f"/c:{count}", "/rd:true", "/f:xml"]
        if query:
            cmd.extend([f"/q:{query}"])

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=3, check=False)
            if res.returncode != 0 or not res.stdout.strip():
                return events

            raw_xml = f"<Root>{res.stdout}</Root>"
            root = ET.fromstring(raw_xml)
            for event_elem in root.findall(".//{http://schemas.microsoft.com/win/2004/08/events/event}Event"):
                ev = self._parse_event_element(event_elem, channel)
                if ev:
                    events.append(ev)
        except Exception:
            pass

        return events

    def _parse_event_element(self, elem: ET.Element, channel: str) -> Optional[ForensicEvent]:
        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
        sys_elem = elem.find("e:System", ns)
        if sys_elem is None:
            return None

        eid_elem = sys_elem.find("e:EventID", ns)
        time_elem = sys_elem.find("e:TimeCreated", ns)
        rec_elem = sys_elem.find("e:EventRecordID", ns)

        if eid_elem is None or time_elem is None:
            return None

        event_id = eid_elem.text or ""
        time_str = time_elem.get("SystemTime") or ""
        rec_id = int(rec_elem.text) if rec_elem is not None and rec_elem.text and rec_elem.text.isdigit() else 0

        # Check deduplication
        last_id = self._last_record_ids.get(channel, 0)
        if rec_id > 0 and rec_id <= last_id:
            return None
        if rec_id > 0:
            self._last_record_ids[channel] = max(last_id, rec_id)

        try:
            ts = datetime.fromisoformat(time_str.replace("Z", "+00:00"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
        except Exception:
            ts = datetime.now(timezone.utc)

        # Extract EventData elements
        event_data: Dict[str, str] = {}
        ed_elem = elem.find("e:EventData", ns)
        if ed_elem is not None:
            for d in ed_elem.findall("e:Data", ns):
                name = d.get("Name") or ""
                val = d.text or ""
                if name:
                    event_data[name] = val

        # Handle Anti-Forensic Clearing (1102 / 104)
        if event_id in ("1102", "104"):
            log_title = "Security Audit Log" if event_id == "1102" else "System Event Log"
            user = event_data.get("SubjectUserName") or "Unknown"
            return ForensicEvent(
                event_id=f"RT-LOG-{uuid.uuid4().hex[:8].upper()}",
                timestamp=ts,
                artifact_type=ArtifactType.EVENT_LOG_SECURITY if event_id == "1102" else ArtifactType.EVENT_LOG_SYSTEM,
                category=EventCategory.LOG_CLEARED,
                fact_level=FactLevel.DIRECT_OBSERVATION,
                summary=f"CRITICAL ANTI-FORENSICS: {log_title} was explicitly CLEARED by user '{user}' (Event ID {event_id})",
                user=user,
                evidence_id="LIVE_EVENT_LOG",
                record_id=str(rec_id),
                raw_metadata=event_data,
            )

        # Handle USB DriverFrameworks (2003, 2004, 2101, 2102)
        if event_id in ("2003", "2004", "2101", "2102"):
            is_attach = event_id in ("2003", "2101")
            cat = EventCategory.USB_ATTACH if is_attach else EventCategory.USB_DETACH
            action_desc = "connected / arrived" if is_attach else "disconnected / removed"
            lifetime = event_data.get("Lifetime") or str(event_data)

            serial = None
            m = re.search(r"USBSTOR[\\#].*?[\\#]([A-Za-z0-9\&\_\-\.]+)", lifetime)
            if m:
                serial = m.group(1).split("&")[0]

            return ForensicEvent(
                event_id=f"RT-DFW-{uuid.uuid4().hex[:8].upper()}",
                timestamp=ts,
                artifact_type=ArtifactType.EVENT_LOG_DRIVER_FRAMEWORKS,
                category=cat,
                fact_level=FactLevel.DIRECT_OBSERVATION,
                summary=f"USB device {action_desc} logged via DriverFrameworks (Event {event_id}, Serial: {serial or 'Unknown'})",
                usb_serial=serial,
                evidence_id="LIVE_DRIVER_FRAMEWORKS",
                record_id=str(rec_id),
                raw_metadata=event_data,
            )

        # Handle Security 4688 Process Creation
        if event_id == "4688":
            new_proc = event_data.get("NewProcessName") or ""
            cmd_line = event_data.get("CommandLine") or ""
            user = event_data.get("SubjectUserName") or ""
            proc_base = Path(new_proc).name.upper() if new_proc else ""

            is_staging = any(t in proc_base for t in ("7Z", "WINRAR", "TAR", "POWERSHELL", "ROBOCOPY", "XCOPY", "CERTUTIL"))
            return ForensicEvent(
                event_id=f"RT-PROC-{uuid.uuid4().hex[:8].upper()}",
                timestamp=ts,
                artifact_type=ArtifactType.EVENT_LOG_SECURITY,
                category=EventCategory.FILE_STAGING if is_staging else EventCategory.PROCESS_EXECUTION,
                fact_level=FactLevel.DIRECT_OBSERVATION,
                summary=f"Process created: {proc_base} (Command: {cmd_line or 'N/A'})",
                user=user,
                process_name=proc_base,
                command_line=cmd_line,
                evidence_id="LIVE_SECURITY_4688",
                record_id=str(rec_id),
                raw_metadata=event_data,
            )

        return None


class RealTimeArtifactMonitor:
    """High-performance real-time Windows incident monitor and reconstructor for removable devices."""

    def __init__(
        self,
        poll_interval_sec: float = 2.0,
        alert_threshold: float = 0.70,
        report_dir: Optional[Path] = None,
        case_id: str = "INC-REALTIME-001",
    ) -> None:
        self.poll_interval = poll_interval_sec
        self.alert_threshold = alert_threshold
        self.report_dir = Path(report_dir) if report_dir else Path("./realtime_alerts")
        self.case_id = case_id

        self.engine = ForensicInvestigationEngine()
        self.drive_watcher = WindowsRemovableDriveWatcher()
        self.event_log_ingestor = LiveWindowsEventLogIngestor()

        self.event_window: List[ForensicEvent] = []
        self._active_removable_drives: Dict[str, RemovableDriveInfo] = {}
        self._seen_usb_serials: Set[str] = set()
        self._seen_pf_mtimes: Dict[Path, float] = {}
        self._seen_recent_mtimes: Dict[Path, float] = {}
        self._seen_removable_files: Dict[str, float] = {}
        self.exfiltrated_files: List[ExfiltratedFileInfo] = []
        self._last_alert_signature: Optional[str] = None

    def seed_baseline(self) -> None:
        """Record baseline system state so existing files do not trigger false live alerts."""
        # 1. Existing USB storage in registry
        for serial, _, _ in self._query_historical_usbstor():
            self._seen_usb_serials.add(serial)

        # 2. Existing connected removable drives
        for drive in self.drive_watcher.get_connected_removable_drives():
            self._active_removable_drives[drive.drive_letter.upper()] = drive
            # Snapshot existing files on connected drive
            self._snapshot_drive_files(drive.drive_root)

        # 3. Existing Prefetch files
        system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        pf_dir = system_root / "Prefetch"
        if pf_dir.is_dir():
            for pf in pf_dir.glob("*.pf"):
                try:
                    self._seen_pf_mtimes[pf] = pf.stat().st_mtime
                except OSError:
                    pass

        # 4. Existing Recent shortcuts
        appdata = Path(os.environ.get("APPDATA", ""))
        recent_dir = appdata / "Microsoft" / "Windows" / "Recent"
        if recent_dir.is_dir():
            for item in recent_dir.rglob("*"):
                if item.is_file():
                    try:
                        self._seen_recent_mtimes[item] = item.stat().st_mtime
                    except OSError:
                        pass

    def _snapshot_drive_files(self, root_path: str) -> None:
        """Record files already present on the removable drive."""
        try:
            p = Path(root_path)
            for f in p.rglob("*"):
                if f.is_file():
                    try:
                        self._seen_removable_files[str(f).upper()] = f.stat().st_mtime
                    except OSError:
                        pass
        except Exception:
            pass

    def _query_historical_usbstor(self) -> List[Tuple[str, str, str]]:
        devices: List[Tuple[str, str, str]] = []
        if winreg is None:
            return devices

        base_key = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base_key) as root_key:
                idx = 0
                while True:
                    try:
                        dev_class = winreg.EnumKey(root_key, idx)
                        idx += 1
                    except OSError:
                        break

                    vendor, product = "USB", dev_class
                    if "Ven_" in dev_class and "Prod_" in dev_class:
                        for p in dev_class.split("&"):
                            if p.startswith("Ven_"):
                                vendor = p[4:].replace("_", " ")
                            elif p.startswith("Prod_"):
                                product = p[5:].replace("_", " ")

                    with winreg.OpenKey(root_key, dev_class) as class_key:
                        s_idx = 0
                        while True:
                            try:
                                raw_serial = winreg.EnumKey(class_key, s_idx)
                                s_idx += 1
                                serial = raw_serial.split("&")[0]
                                devices.append((serial, vendor, product))
                            except OSError:
                                break
        except OSError:
            pass
        return devices

    def poll_removable_devices(self) -> List[ForensicEvent]:
        """Detect live removable drive attachment and detachment events."""
        events: List[ForensicEvent] = []
        current_drives = {d.drive_letter.upper(): d for d in self.drive_watcher.get_connected_removable_drives()}
        now = datetime.now(timezone.utc)
        user = os.environ.get("USERNAME", "LIVE_USER")

        # 1. Newly attached drives
        for letter, drive in current_drives.items():
            if letter not in self._active_removable_drives:
                self._active_removable_drives[letter] = drive
                summary = (
                    f"USB Removable Storage connected: {drive.volume_name} "
                    f"(Drive: {drive.drive_letter}, VSN: {drive.volume_serial}, FS: {drive.file_system}, "
                    f"Vendor: {drive.usb_vendor or 'Unknown'}, Serial: {drive.usb_serial or 'Unknown'})"
                )
                ev = ForensicEvent(
                    event_id=f"RT-USB-{uuid.uuid4().hex[:8].upper()}",
                    timestamp=now,
                    artifact_type=ArtifactType.REGISTRY_USBSTOR,
                    category=EventCategory.USB_ATTACH,
                    fact_level=FactLevel.DIRECT_OBSERVATION,
                    summary=summary,
                    user=user,
                    usb_serial=drive.usb_serial,
                    usb_vendor=drive.usb_vendor,
                    usb_product=drive.usb_product,
                    drive_letter=drive.drive_letter,
                    volume_serial=drive.volume_serial,
                    evidence_id="LIVE_REMOVABLE_VOLUME",
                    raw_metadata={
                        "volume_name": drive.volume_name,
                        "file_system": drive.file_system,
                        "total_bytes": drive.total_bytes,
                        "free_bytes": drive.free_bytes,
                    },
                )
                events.append(ev)
                # Snapshot existing files on this drive so we only flag new writes
                self._snapshot_drive_files(drive.drive_root)

        # 2. Detached drives
        detached_letters = [l for l in self._active_removable_drives if l not in current_drives]
        for letter in detached_letters:
            old_drive = self._active_removable_drives.pop(letter)
            summary = f"USB Removable Storage removed / detached: Drive {letter} (VSN: {old_drive.volume_serial})"
            ev = ForensicEvent(
                event_id=f"RT-USBDET-{uuid.uuid4().hex[:8].upper()}",
                timestamp=now,
                artifact_type=ArtifactType.REGISTRY_USBSTOR,
                category=EventCategory.USB_DETACH,
                fact_level=FactLevel.DIRECT_OBSERVATION,
                summary=summary,
                user=user,
                usb_serial=old_drive.usb_serial,
                drive_letter=letter,
                volume_serial=old_drive.volume_serial,
                evidence_id="LIVE_REMOVABLE_VOLUME",
            )
            events.append(ev)

        return events

    def poll_removable_file_writes(self) -> List[ForensicEvent]:
        """Detect live file creation and copying directly onto the removable drive."""
        events: List[ForensicEvent] = []
        user = os.environ.get("USERNAME", "LIVE_USER")

        for letter, drive in self._active_removable_drives.items():
            root_path = Path(drive.drive_root)
            if not root_path.exists():
                continue

            try:
                for file_path in root_path.rglob("*"):
                    if not file_path.is_file():
                        continue

                    path_key = str(file_path).upper()
                    try:
                        mtime = file_path.stat().st_mtime
                        size = file_path.stat().st_size
                    except OSError:
                        continue

                    prev_mtime = self._seen_removable_files.get(path_key)
                    if prev_mtime is None or mtime > prev_mtime:
                        self._seen_removable_files[path_key] = mtime
                        now = datetime.fromtimestamp(mtime, tz=timezone.utc)

                        # Hash file on the fly for non-repudiation evidence
                        sha256_hash, md5_hash = self._hash_file_safely(file_path)

                        ext = file_path.suffix.lower()
                        is_staging = ext in WindowsRemovableDriveWatcher.STAGING_EXTS
                        is_sensitive = ext in WindowsRemovableDriveWatcher.SENSITIVE_EXTS

                        exf_info = ExfiltratedFileInfo(
                            path=str(file_path),
                            file_name=file_path.name,
                            size_bytes=size,
                            sha256=sha256_hash,
                            md5=md5_hash,
                            timestamp=now,
                            drive_letter=drive.drive_letter,
                            volume_serial=drive.volume_serial,
                            usb_serial=drive.usb_serial,
                            is_staging_archive=is_staging,
                        )
                        self.exfiltrated_files.append(exf_info)

                        tag = "[DATA THEFT STAGING]" if is_staging else ("[SENSITIVE EXFILTRATION]" if is_sensitive else "[FILE COPY]")
                        summary = (
                            f"{tag} File transferred to removable drive: {file_path.name} "
                            f"(Path: {file_path}, Size: {size:,} bytes, Drive: {drive.drive_letter}, "
                            f"VSN: {drive.volume_serial}, SHA-256: {sha256_hash[:16]}...)"
                        )

                        ev = ForensicEvent(
                            event_id=f"RT-FILE-{uuid.uuid4().hex[:8].upper()}",
                            timestamp=now,
                            artifact_type=ArtifactType.LNK_SHORTCUT,
                            category=EventCategory.FILE_TRANSFER_USB,
                            fact_level=FactLevel.DIRECT_OBSERVATION,
                            summary=summary,
                            user=user,
                            source_file_path=str(file_path),
                            target_file_path=str(file_path),
                            file_size_bytes=size,
                            drive_letter=drive.drive_letter,
                            volume_serial=drive.volume_serial,
                            usb_serial=drive.usb_serial,
                            evidence_id=f"REMOVABLE_{drive.drive_letter.replace(':', '')}",
                            raw_metadata={
                                "sha256": sha256_hash,
                                "md5": md5_hash,
                                "is_staging_archive": is_staging,
                                "is_sensitive_doc": is_sensitive,
                            },
                        )
                        events.append(ev)
            except Exception:
                pass

        return events

    def _hash_file_safely(self, path: Path) -> Tuple[str, str]:
        """Compute SHA-256 and MD5 without crashing on locked or partial files."""
        sha256 = hashlib.sha256()
        md5 = hashlib.md5()
        try:
            with open(path, "rb") as f:
                while chunk := f.read(65536):
                    sha256.update(chunk)
                    md5.update(chunk)
            return sha256.hexdigest(), md5.hexdigest()
        except Exception:
            return "UNREADABLE_OR_LOCKED", "UNREADABLE_OR_LOCKED"

    def poll_prefetch(self) -> List[ForensicEvent]:
        """Detect execution of staging and compression tools in real time via Prefetch."""
        events: List[ForensicEvent] = []
        system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        pf_dir = system_root / "Prefetch"
        if not pf_dir.is_dir():
            return events

        user = os.environ.get("USERNAME", "LIVE_USER")
        for pf in pf_dir.glob("*.pf"):
            try:
                mtime = pf.stat().st_mtime
            except OSError:
                continue

            prev = self._seen_pf_mtimes.get(pf)
            if prev is None or mtime > prev:
                self._seen_pf_mtimes[pf] = mtime
                parsed = self.engine.prefetch_parser.parse(pf)
                if parsed:
                    latest = parsed[-1]
                    latest.timestamp = datetime.fromtimestamp(mtime, tz=timezone.utc)
                    latest.user = latest.user or user
                    events.append(latest)
                else:
                    exe_name = pf.name.split("-")[0].upper()
                    is_staging = exe_name in self.engine.prefetch_parser.STAGING_TOOLS
                    events.append(
                        ForensicEvent(
                            event_id=f"RT-PF-{uuid.uuid4().hex[:8].upper()}",
                            timestamp=datetime.fromtimestamp(mtime, tz=timezone.utc),
                            artifact_type=ArtifactType.PREFETCH,
                            category=EventCategory.FILE_STAGING if is_staging else EventCategory.PROCESS_EXECUTION,
                            fact_level=FactLevel.DIRECT_OBSERVATION,
                            summary=f"[REAL-TIME] Process executed: {exe_name}",
                            user=user,
                            process_name=exe_name,
                            evidence_id="LIVE_PREFETCH",
                        )
                    )
        return events

    def poll_recent_shortcuts(self) -> List[ForensicEvent]:
        """Detect file access and VSN linkages via newly created .lnk files and JumpLists."""
        events: List[ForensicEvent] = []
        appdata = Path(os.environ.get("APPDATA", ""))
        recent_dir = appdata / "Microsoft" / "Windows" / "Recent"
        if not recent_dir.is_dir():
            return events

        user = os.environ.get("USERNAME", "LIVE_USER")
        for item in recent_dir.rglob("*"):
            if not item.is_file():
                continue
            if item.suffix.lower() not in (".lnk", ".automaticdestinations-ms", ".customdestinations-ms"):
                continue

            try:
                mtime = item.stat().st_mtime
            except OSError:
                continue

            prev = self._seen_recent_mtimes.get(item)
            if prev is None or mtime > prev:
                self._seen_recent_mtimes[item] = mtime
                parsed = self.engine.lnk_parser.parse(item)
                for ev in parsed:
                    ev.timestamp = datetime.fromtimestamp(mtime, tz=timezone.utc)
                    ev.user = ev.user or user
                    events.append(ev)
        return events

    def poll_all_telemetry(self) -> List[ForensicEvent]:
        """Single telemetry polling tick covering removable drives, files, logs, and staging."""
        batch: List[ForensicEvent] = []
        batch.extend(self.poll_removable_devices())
        batch.extend(self.poll_removable_file_writes())
        batch.extend(self.event_log_ingestor.fetch_live_events())
        batch.extend(self.poll_prefetch())
        batch.extend(self.poll_recent_shortcuts())
        return batch

    def evaluate_and_reconstruct(self) -> Optional[IncidentHypothesis]:
        """Run 5-pillar correlation, reconstruct 5-stage incident lifecycle, and update reports."""
        if not self.event_window:
            return None

        bundle = self.engine.correlator.correlate(self.event_window)
        hypothesis = self.engine.reconstructor.reconstruct(bundle)
        anomalies = self.engine.gap_analyzer.analyze(bundle)

        if not hypothesis:
            return None

        hypothesis.anomalies = anomalies
        hypothesis.confidence = self.engine.confidence_engine.evaluate(hypothesis, bundle, anomalies)

        # Check if alert condition is met
        if hypothesis.confidence.score >= self.alert_threshold:
            sig = f"{len(hypothesis.steps)}-{len(anomalies)}-{hypothesis.confidence.rating.value}-{len(self.exfiltrated_files)}"
            if sig != self._last_alert_signature:
                self._last_alert_signature = sig
                self._display_incident_alert(hypothesis, anomalies)
                self.maintain_reports(hypothesis, anomalies, bundle)

        return hypothesis

    def _display_incident_alert(self, hypothesis: IncidentHypothesis, anomalies: List[ForensicAnomaly]) -> None:
        """Display real-time incident alert banner with ANSI formatting in CLI."""
        print(f"\n{C_BOLD}{C_RED}+===================================================================================+{C_RESET}")
        print(f"{C_BOLD}{C_RED}| [ALERT] INSIDER DATA-THEFT RECONSTRUCTION TRIGGERED!                              |{C_RESET}")
        print(f"{C_BOLD}{C_RED}+===================================================================================+{C_RESET}")
        print(f"  {C_BOLD}Case Identifier:{C_RESET}     {self.case_id}")
        print(f"  {C_BOLD}Subject User:{C_RESET}        {hypothesis.subject_user or 'LIVE_USER'}")
        print(f"  {C_BOLD}Confidence Score:{C_RESET}    {C_GREEN}{hypothesis.confidence.score * 100:.0f}% ({hypothesis.confidence.rating.value}){C_RESET}")
        print(f"  {C_BOLD}Removable Drives:{C_RESET}    {', '.join(hypothesis.destination_devices) or 'Removable Media Detected'}")
        print(f"  {C_BOLD}Exfiltrated Files:{C_RESET}   {len(self.exfiltrated_files)} file(s) captured directly on removable drive\n")

        print(f"{C_BOLD}{C_WHITE}--- Chronological 5-Stage Reconstructed Sequence ---{C_RESET}")
        for step in hypothesis.steps:
            status_color = C_GREEN if step.status == StepStatus.CONFIRMED else C_YELLOW
            status_tag = f"[{step.status.value}]"
            ts_str = step.timestamp.strftime("%H:%M:%S") if step.timestamp else "--:--:--"
            print(f"  {step.step_number}. {step.stage.value:<24} {status_color}{status_tag:<14}{C_RESET} [{ts_str}] {step.description}")

        if anomalies:
            print(f"\n{C_BOLD}{C_YELLOW}--- Detected Anti-Forensics & Anomalies ({len(anomalies)}) ---{C_RESET}")
            for anom in anomalies:
                print(f"  * [{anom.severity.value:<8}] {anom.title}")

        print(f"\n{C_GREEN}[+] Dynamically maintaining incident report in: {self.report_dir}/REALTIME_INCIDENT_REPORT.md{C_RESET}\n")

    def maintain_reports(
        self,
        hypothesis: IncidentHypothesis,
        anomalies: List[ForensicAnomaly],
        bundle: Any,
    ) -> None:
        """Export and update all investigation deliverables in real time."""
        self.report_dir.mkdir(parents=True, exist_ok=True)

        # 1. Markdown Incident Report
        self._generate_realtime_markdown_report(hypothesis, anomalies, self.report_dir / "REALTIME_INCIDENT_REPORT.md")

        # 2. JSON structured findings
        self._generate_realtime_json(hypothesis, anomalies, self.report_dir / "realtime_findings.json")

        # 3. Super Timeline CSV
        all_events = bundle.all_events_sorted + bundle.inferred_events
        self.engine.csv_reporter.export(all_events, self.report_dir / "realtime_super_timeline.csv")

    def _generate_realtime_markdown_report(
        self, hypothesis: IncidentHypothesis, anomalies: List[ForensicAnomaly], output_file: Path
    ) -> None:
        lines: List[str] = []
        lines.append("# REAL-TIME FORENSIC INCIDENT INVESTIGATION REPORT")
        lines.append("## Windows Removable Device Artifact Analysis & Insider Data Theft")
        lines.append(f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  ")
        lines.append(f"**Case Number:** `{self.case_id}`  ")
        lines.append(f"**Subject of Investigation:** `{hypothesis.subject_user or 'LIVE_USER'}`  ")
        lines.append(f"**Threat Confidence:** **{hypothesis.confidence.rating.value}** ({hypothesis.confidence.score * 100:.1f}%)  ")
        lines.append(f"**Monitoring Mode:** Active Real-Time CLI Watcher  \n")

        lines.append("---")
        lines.append("### 1. Removable Device (Pendrive / USB) Exfiltration Dossier")
        if self._active_removable_drives or hypothesis.destination_devices:
            lines.append("| Drive Letter | Volume Label | Volume Serial (VSN) | File System | Hardware Serial | Vendor / Product |")
            lines.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
            for drive in self._active_removable_drives.values():
                lines.append(
                    f"| `{drive.drive_letter}` | **{drive.volume_name}** | `{drive.volume_serial}` | {drive.file_system} | `{drive.usb_serial or 'N/A'}` | {drive.usb_vendor or 'USB'} {drive.usb_product or 'Storage'} |"
                )
            if not self._active_removable_drives:
                for dev in hypothesis.destination_devices:
                    lines.append(f"| N/A | Removable Volume | Correlated | FAT32/exFAT | Serial Identified | {dev} |")
        else:
            lines.append("*(No active physical removable drive currently mounted)*\n")

        lines.append("\n#### Captured Exfiltrated Files on Removable Device:\n")
        if self.exfiltrated_files:
            lines.append("| File Name | Size (Bytes) | Transferred (UTC) | Removable Drive | SHA-256 Hash | Type |")
            lines.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
            for f in self.exfiltrated_files:
                f_type = "Staging Archive" if f.is_staging_archive else "Sensitive Data"
                lines.append(
                    f"| `{f.file_name}` | {f.size_bytes:,} | {f.timestamp.strftime('%H:%M:%S')} | `{f.drive_letter}` (VSN: {f.volume_serial}) | `{f.sha256[:20]}...` | **{f_type}** |"
                )
        else:
            lines.append("*(No direct file transfers recorded yet)*\n")

        lines.append("\n---")
        lines.append("### 2. Reconstructed Incident Sequence (5-Stage Attack Lifecycle)")
        lines.append("| Step | Stage | Verification Status | Timestamp (UTC) | Description |")
        lines.append("| :--- | :--- | :--- | :--- | :--- |")
        for step in hypothesis.steps:
            ts = step.timestamp.strftime("%Y-%m-%d %H:%M:%S") if step.timestamp else "N/A"
            lines.append(f"| {step.step_number} | `{step.stage.value}` | **{step.status.value}** | {ts} | {step.description} |")

        lines.append("\n---")
        lines.append(f"### 3. Forensic Tampering & Anti-Forensic Anomalies ({len(anomalies)})")
        for anom in anomalies:
            lines.append(f"#### ⚠️ [{anom.severity.value}] {anom.title}")
            lines.append(f"- **Explanation:** {anom.explanation}")
            lines.append(f"- **Investigative Impact:** {anom.investigative_impact}")
            if anom.recommended_action:
                lines.append(f"- **Action:** {anom.recommended_action}")
            lines.append("")

        lines.append("---")
        lines.append("### 4. Non-Repudiation Chain of Custody & Live Telemetry Manifest")
        lines.append("| Event ID | Timestamp (UTC) | Artifact Source | Fact Level | Summary |")
        lines.append("| :--- | :--- | :--- | :--- | :--- |")
        for ev in self.event_window[-30:]:
            lines.append(
                f"| `{ev.event_id}` | {ev.timestamp.strftime('%H:%M:%S')} | `{ev.artifact_type.value}` | **{ev.fact_level.value}** | {ev.summary[:80]}... |"
            )

        output_file.write_text("\n".join(lines), encoding="utf-8")

    def _generate_realtime_json(
        self, hypothesis: IncidentHypothesis, anomalies: List[ForensicAnomaly], output_file: Path
    ) -> None:
        data = {
            "case_id": self.case_id,
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "hypothesis": hypothesis.to_dict(),
            "anomalies": [a.to_dict() for a in anomalies],
            "removable_drives": [
                {
                    "letter": d.drive_letter,
                    "name": d.volume_name,
                    "vsn": d.volume_serial,
                    "fs": d.file_system,
                    "serial": d.usb_serial,
                }
                for d in self._active_removable_drives.values()
            ],
            "exfiltrated_files": [
                {
                    "file_name": f.file_name,
                    "path": f.path,
                    "size_bytes": f.size_bytes,
                    "sha256": f.sha256,
                    "md5": f.md5,
                    "timestamp": f.timestamp.isoformat(),
                    "drive": f.drive_letter,
                    "vsn": f.volume_serial,
                }
                for f in self.exfiltrated_files
            ],
        }
        output_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def run_forever(self) -> None:
        """Start continuous real-time monitoring loop."""
        print(f"{C_CYAN}[*] Seeding live Windows baseline (Removable drives, Prefetch, Recent LNKs, USBSTOR)...{C_RESET}")
        self.seed_baseline()
        print(
            f"{C_GREEN}[+] ARTIFEX Real-Time Removable Device Watcher ACTIVE{C_RESET} "
            f"(Interval: {self.poll_interval}s | Threshold: {self.alert_threshold * 100:.0f}%)"
        )
        print(f"{C_DIM}    Press Ctrl+C to stop real-time monitoring.{C_RESET}\n")

        try:
            while True:
                batch = self.poll_all_telemetry()
                if batch:
                    for ev in batch:
                        ts = ev.timestamp.strftime("%H:%M:%S")
                        cat_color = C_YELLOW if "TRANSFER" in ev.category.value else (C_RED if "LOG" in ev.category.value else C_CYAN)
                        print(f"  {C_DIM}[{ts}]{C_RESET} {cat_color}{ev.category.value:<20}{C_RESET} -> {ev.summary}")
                    self.event_window.extend(batch)
                    self.evaluate_and_reconstruct()

                time.sleep(self.poll_interval)
        except KeyboardInterrupt:
            print(f"\n{C_YELLOW}[!] Real-Time Monitor stopped by operator.{C_RESET}")
            if self.event_window:
                print(f"[*] Compiling final incident investigation deliverables into {self.report_dir}...")
                self.evaluate_and_reconstruct()


def simulate_live_incident(
    monitor: RealTimeArtifactMonitor,
    speed: float = 1.0,
) -> None:
    """Run an authentic real-time simulation of an insider data theft incident via removable media."""
    print(f"\n{C_BOLD}{C_CYAN}====================================================================================={C_RESET}")
    print(f"{C_BOLD}{C_CYAN}  STARTING AUTHENTIC REAL-TIME INCIDENT SIMULATION (REMOVABLE USB DATA THEFT)      {C_RESET}")
    print(f"{C_BOLD}{C_CYAN}====================================================================================={C_RESET}\n")

    user = os.environ.get("USERNAME", "Alex_Mercer")
    now = datetime.now(timezone.utc)

    # Stage 1: Reconnaissance
    print(f"{C_CYAN}[STAGE 1: RECONNAISSANCE] Subject browsing sensitive financial customer folders...{C_RESET}")
    time.sleep(1.0 * speed)
    ev1 = ForensicEvent(
        event_id=f"SIM-LNK-{uuid.uuid4().hex[:8].upper()}",
        timestamp=now,
        artifact_type=ArtifactType.LNK_SHORTCUT,
        category=EventCategory.RECON_ACCESS,
        fact_level=FactLevel.DIRECT_OBSERVATION,
        summary="User accessed sensitive files via Explorer: C:\\Confidential\\Q4_Financial_Client_Database.xlsx",
        user=user,
        source_file_path="C:\\Confidential\\Q4_Financial_Client_Database.xlsx",
        evidence_id="SIMULATED_RECON_LNK",
    )
    monitor.event_window.append(ev1)
    print(f"  {C_GREEN}[+]{C_RESET} Event emitted: {ev1.summary}")

    # Stage 2: Staging Archive
    print(f"\n{C_CYAN}[STAGE 2: STAGING] Subject executing compression tool to stage files...{C_RESET}")
    time.sleep(1.5 * speed)
    ev2 = ForensicEvent(
        event_id=f"SIM-PF-{uuid.uuid4().hex[:8].upper()}",
        timestamp=datetime.now(timezone.utc),
        artifact_type=ArtifactType.PREFETCH,
        category=EventCategory.FILE_STAGING,
        fact_level=FactLevel.DIRECT_OBSERVATION,
        summary="7Z.EXE executed from Prefetch, creating temporary container: C:\\Users\\user\\AppData\\Local\\Temp\\exfil_stage.zip",
        user=user,
        process_name="7Z.EXE",
        command_line="7z.exe a -tzip C:\\Users\\user\\AppData\\Local\\Temp\\exfil_stage.zip C:\\Confidential\\*",
        source_file_path="C:\\Users\\user\\AppData\\Local\\Temp\\exfil_stage.zip",
        evidence_id="SIMULATED_STAGING_PF",
    )
    monitor.event_window.append(ev2)
    print(f"  {C_GREEN}[+]{C_RESET} Event emitted: {ev2.summary}")

    # Stage 3: Removable Storage Device Attachment
    print(f"\n{C_CYAN}[STAGE 3: DEVICE PREPARATION] Unauthorized USB device inserted into workstation...{C_RESET}")
    time.sleep(1.5 * speed)
    sim_drive = RemovableDriveInfo(
        drive_letter="E:",
        drive_root="E:\\",
        volume_name="KINGSTON_32GB",
        volume_serial="A4B1C2D3",
        file_system="FAT32",
        drive_type="Removable",
        total_bytes=32_000_000_000,
        free_bytes=28_000_000_000,
        usb_vendor="Kingston",
        usb_product="DataTraveler 3.0",
        usb_serial="00187D0F9A82B05",
    )
    monitor._active_removable_drives["E:"] = sim_drive
    ev3 = ForensicEvent(
        event_id=f"SIM-USB-{uuid.uuid4().hex[:8].upper()}",
        timestamp=datetime.now(timezone.utc),
        artifact_type=ArtifactType.REGISTRY_USBSTOR,
        category=EventCategory.USB_ATTACH,
        fact_level=FactLevel.DIRECT_OBSERVATION,
        summary="USB Removable Storage connected: Kingston DataTraveler 3.0 (Serial: 00187D0F9A82B05, Drive: E:, VSN: A4B1C2D3, FS: FAT32)",
        user=user,
        usb_serial=sim_drive.usb_serial,
        usb_vendor=sim_drive.usb_vendor,
        usb_product=sim_drive.usb_product,
        drive_letter=sim_drive.drive_letter,
        volume_serial=sim_drive.volume_serial,
        evidence_id="SIMULATED_USBSTOR",
    )
    monitor.event_window.append(ev3)
    print(f"  {C_GREEN}[+]{C_RESET} Event emitted: {ev3.summary}")

    # Stage 4: Data Transfer to USB
    print(f"\n{C_CYAN}[STAGE 4: DATA TRANSFER] Staged archives and sensitive records written to USB drive E:...{C_RESET}")
    time.sleep(1.5 * speed)
    exf1 = ExfiltratedFileInfo(
        path="E:\\exfil_stage.zip",
        file_name="exfil_stage.zip",
        size_bytes=14_850_220,
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        md5="d41d8cd98f00b204e9800998ecf8427e",
        timestamp=datetime.now(timezone.utc),
        drive_letter="E:",
        volume_serial="A4B1C2D3",
        usb_serial="00187D0F9A82B05",
        is_staging_archive=True,
    )
    monitor.exfiltrated_files.append(exf1)
    ev4 = ForensicEvent(
        event_id=f"SIM-XFER-{uuid.uuid4().hex[:8].upper()}",
        timestamp=datetime.now(timezone.utc),
        artifact_type=ArtifactType.LNK_SHORTCUT,
        category=EventCategory.FILE_TRANSFER_USB,
        fact_level=FactLevel.DIRECT_OBSERVATION,
        summary=f"[DATA THEFT] File copied to removable drive: E:\\exfil_stage.zip (Size: 14.8 MB, VSN: A4B1C2D3, SHA-256: {exf1.sha256[:16]}...)",
        user=user,
        source_file_path="E:\\exfil_stage.zip",
        target_file_path="E:\\exfil_stage.zip",
        file_size_bytes=exf1.size_bytes,
        drive_letter="E:",
        volume_serial="A4B1C2D3",
        usb_serial="00187D0F9A82B05",
        evidence_id="SIMULATED_USB_FILE_WRITE",
    )
    monitor.event_window.append(ev4)
    print(f"  {C_GREEN}[+]{C_RESET} Event emitted: {ev4.summary}")

    # Stage 5: Anti-Forensic Tampering
    print(f"\n{C_CYAN}[STAGE 5: COVER-UP / ANTI-FORENSICS] Insider clearing Windows Security Event Logs...{C_RESET}")
    time.sleep(1.5 * speed)
    ev5 = ForensicEvent(
        event_id=f"SIM-CLEAR-{uuid.uuid4().hex[:8].upper()}",
        timestamp=datetime.now(timezone.utc),
        artifact_type=ArtifactType.EVENT_LOG_SECURITY,
        category=EventCategory.LOG_CLEARED,
        fact_level=FactLevel.DIRECT_OBSERVATION,
        summary="CRITICAL ANTI-FORENSICS: Security Audit Log was explicitly CLEARED by user Alex_Mercer (Security Event ID 1102)",
        user=user,
        evidence_id="SIMULATED_EVTX_CLEAR",
    )
    monitor.event_window.append(ev5)
    print(f"  {C_GREEN}[+]{C_RESET} Event emitted: {ev5.summary}")

    # Final reconstruction & reporting
    print(f"\n{C_BOLD}[*] Running 5-Pillar Reconstruction on Simulated Telemetry...{C_RESET}")
    monitor.evaluate_and_reconstruct()
    print(f"\n{C_GREEN}[+] Real-time incident simulation completed successfully!{C_RESET}")
    print(f"    Deliverables generated in: {monitor.report_dir}/")
    print(f"    - Report:   REALTIME_INCIDENT_REPORT.md")
    print(f"    - Findings: realtime_findings.json")
    print(f"    - Timeline: realtime_super_timeline.csv\n")