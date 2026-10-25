"""Synthetic Forensic Artifact Scenario Generator for Insider Threat Validation.

Generates realistic Windows forensic artifacts representing a multi-stage insider data theft:
1. Recon: User 'jdoe' accesses 'Client_Financials_Q4.xlsx' and 'Patents_TradeSecrets.docx' (LNK & JumpLists).
2. Staging: '7z.exe' executes, creating 'C:\\Users\\jdoe\\AppData\\Local\\Temp\\exfil_backup.7z' (Prefetch & USN Journal).
3. USB Arrival: SanDisk Cruzer USB thumb drive (Serial: 07018899AABB, Drive: E:, VSN: 4A8F201B) is inserted (USBSTOR & EventLog).
4. Transfer: 'exfil_backup.7z' transferred to USB (matching VSN 4A8F201B).
5. Cover-Up / Anti-Forensics:
   - 'exfil_backup.7z' deleted from local disk (USN Journal FILE_DELETE reason).
   - 'Client_Financials_Q4.xlsx' has its $STANDARD_INFORMATION timestomped to 2021 (NTFS MFT timestomp anomaly).
   - Windows Security Event Log is cleared (Security Event ID 1102).
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path


def generate_synthetic_scenario(output_dir: Path) -> Path:
    """Generate mock forensic evidence files into target directory."""
    output_dir.mkdir(parents=True, exist_ok=True)
    base_time = datetime(2026, 10, 24, 14, 0, 0, tzinfo=timezone.utc)

    # 1. USB Storage Artifact (USBSTOR + MountedDevices)
    usb_data = [
        {
            "timestamp": (base_time + timedelta(minutes=10)).isoformat(),
            "serial_number": "07018899AABB",
            "vendor": "SanDisk",
            "product": "Ultra_Cruzer",
            "drive_letter": "E:",
            "volume_serial": "4A8F201B",
            "user": "jdoe",
        }
    ]
    (output_dir / "usbstor_registry.json").write_text(json.dumps(usb_data, indent=2), encoding="utf-8")

    # 2. DriverFrameworks Event Log (USB Arrival)
    evtx_data = [
        {
            "EventId": "2003",
            "TimeCreated": (base_time + timedelta(minutes=10, seconds=5)).isoformat(),
            "user": "jdoe",
            "Message": "UMDF Host arrived for USBSTOR\\Disk&Ven_SanDisk&Prod_Ultra_Cruzer\\07018899AABB&0",
        },
        # Anti-forensics: Security Audit Log Cleared at the end of the operation!
        {
            "EventId": "1102",
            "TimeCreated": (base_time + timedelta(minutes=35)).isoformat(),
            "user": "jdoe",
            "Message": "The audit log was cleared.",
        },
    ]
    (output_dir / "security_driverframeworks_events.json").write_text(json.dumps(evtx_data, indent=2), encoding="utf-8")

    # 3. LNK & JumpList Shortcuts (Recon & Target File Access)
    lnk_data = [
        {
            "target_path": "C:\\Users\\jdoe\\Documents\\Confidential\\Client_Financials_Q4.xlsx",
            "timestamp": (base_time + timedelta(minutes=2)).isoformat(),
            "volume_serial": "8C901234",
            "drive_type": "Fixed",
        },
        {
            "target_path": "C:\\Users\\jdoe\\Documents\\Confidential\\Patents_TradeSecrets.docx",
            "timestamp": (base_time + timedelta(minutes=4)).isoformat(),
            "volume_serial": "8C901234",
            "drive_type": "Fixed",
        },
        # LNK pointing to the staging archive on the USB drive with matching VSN!
        {
            "target_path": "E:\\exfil_backup.7z",
            "timestamp": (base_time + timedelta(minutes=22)).isoformat(),
            "volume_serial": "4A8F201B",  # Exact VSN match with the SanDisk thumb drive!
            "drive_type": "Removable",
        },
    ]
    (output_dir / "recent_jumplist_entries.json").write_text(json.dumps(lnk_data, indent=2), encoding="utf-8")

    # 4. Prefetch Execution Logs (7-Zip Staging)
    prefetch_data = [
        {
            "executable": "7Z.EXE",
            "run_count": 3,
            "last_run_times": [(base_time + timedelta(minutes=8)).isoformat()],
            "loaded_files": [
                "C:\\Users\\jdoe\\Documents\\Confidential\\Client_Financials_Q4.xlsx",
                "C:\\Users\\jdoe\\AppData\\Local\\Temp\\exfil_backup.7z",
            ],
        }
    ]
    (output_dir / "prefetch_execution.json").write_text(json.dumps(prefetch_data, indent=2), encoding="utf-8")

    # 5. NTFS USN Journal Records ($UsnJrnl)
    usn_data = [
        {
            "file_name": "exfil_backup.7z",
            "timestamp": (base_time + timedelta(minutes=9)).isoformat(),
            "reason": "USN_REASON_FILE_CREATE",
            "usn": 1042001,
        },
        # Permanent Shift+Delete of the staging container!
        {
            "file_name": "exfil_backup.7z",
            "timestamp": (base_time + timedelta(minutes=28)).isoformat(),
            "reason": "USN_REASON_FILE_DELETE",
            "usn": 1042089,
        },
    ]
    (output_dir / "usn_journal_records.json").write_text(json.dumps(usn_data, indent=2), encoding="utf-8")

    # 6. NTFS MFT Records (With Timestomp Anomaly)
    mft_data = [
        {
            "file_name": "Client_Financials_Q4.xlsx",
            "timestamp": (base_time + timedelta(minutes=2)).isoformat(),
            "timestomp_detected": True,
            "reason": "$STANDARD_INFORMATION manipulated: Modified time backdated to 2021-01-01 while $FILE_NAME is 2026-10-24",
            "EntryNumber": 48201,
        }
    ]
    (output_dir / "mft_records.json").write_text(json.dumps(mft_data, indent=2), encoding="utf-8")

    # 7. Browser History (Cloud Upload Recon)
    browser_data = [
        {
            "url": "https://wetransfer.com/upload",
            "timestamp": (base_time + timedelta(minutes=15)).isoformat(),
            "title": "WeTransfer - Send Large Files",
        }
    ]
    (output_dir / "browser_history.json").write_text(json.dumps(browser_data, indent=2), encoding="utf-8")

    return output_dir
