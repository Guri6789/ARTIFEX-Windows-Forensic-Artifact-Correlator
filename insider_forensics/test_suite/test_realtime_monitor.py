"""Unit tests for Real-Time Removable Device Incident Monitoring & Reconstruction."""

from __future__ import annotations

import tempfile
import unittest
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from insider_forensics.core.models import (
    ArtifactType,
    EventCategory,
    FactLevel,
    IncidentStage,
    StepStatus,
)
from insider_forensics.realtime_monitor import (
    LiveWindowsEventLogIngestor,
    RealTimeArtifactMonitor,
    RemovableDriveInfo,
    WindowsRemovableDriveWatcher,
    simulate_live_incident,
)


class TestRealTimeMonitor(unittest.TestCase):
    """Test suite for Real-Time Removable Device Monitor & Event Reconstructor."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.report_dir = Path(self.temp_dir.name) / "alerts"
        self.monitor = RealTimeArtifactMonitor(
            poll_interval_sec=1.0,
            alert_threshold=0.60,
            report_dir=self.report_dir,
            case_id="TEST-INC-999",
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_removable_drive_watcher_detection(self) -> None:
        watcher = WindowsRemovableDriveWatcher()
        drives = watcher.get_connected_removable_drives()
        self.assertIsInstance(drives, list)

    def test_safe_file_hashing(self) -> None:
        test_file = Path(self.temp_dir.name) / "secret_finance.zip"
        content = b"PK\x03\x04CONFIDENTIAL_CUSTOMER_DATA_RECORDS"
        test_file.write_bytes(content)

        sha256, md5 = self.monitor._hash_file_safely(test_file)
        import hashlib
        expected_sha256 = hashlib.sha256(content).hexdigest()
        expected_md5 = hashlib.md5(content).hexdigest()

        self.assertEqual(sha256, expected_sha256)
        self.assertEqual(md5, expected_md5)

    def test_removable_file_write_polling(self) -> None:
        mock_usb_root = Path(self.temp_dir.name) / "MockUSB"
        mock_usb_root.mkdir(parents=True, exist_ok=True)

        mock_drive = RemovableDriveInfo(
            drive_letter="F:",
            drive_root=str(mock_usb_root),
            volume_name="TEST_PENDRIVE",
            volume_serial="99AA88BB",
            file_system="FAT32",
            drive_type="Removable",
            usb_vendor="SanDisk",
            usb_product="Ultra USB 3.0",
            usb_serial="4C53000123456789",
        )
        self.monitor._active_removable_drives["F:"] = mock_drive

        # Write a sensitive staging archive into the removable drive
        staged_file = mock_usb_root / "staged_client_records.zip"
        staged_file.write_bytes(b"PK\x03\x04CONFIDENTIAL_TEST_DATA")

        events = self.monitor.poll_removable_file_writes()
        self.assertTrue(len(events) >= 1)

        ev = events[0]
        self.assertEqual(ev.category, EventCategory.FILE_TRANSFER_USB)
        self.assertEqual(ev.fact_level, FactLevel.DIRECT_OBSERVATION)
        self.assertEqual(ev.volume_serial, "99AA88BB")
        self.assertEqual(ev.usb_serial, "4C53000123456789")
        self.assertEqual(ev.drive_letter, "F:")
        self.assertTrue("staged_client_records.zip" in ev.summary)
        self.assertEqual(len(self.monitor.exfiltrated_files), 1)

    def test_live_event_log_xml_parsing(self) -> None:
        ingestor = LiveWindowsEventLogIngestor()

        # Mock Security Event 1102 (Log Cleared)
        xml_1102 = (
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
            "<System><EventID>1102</EventID><TimeCreated SystemTime='2026-11-18T10:00:00Z'/><EventRecordID>9001</EventRecordID></System>"
            "<EventData><Data Name='SubjectUserName'>Infiltrator_V</Data></EventData>"
            "</Event>"
        )
        elem = ET.fromstring(xml_1102)
        ev = ingestor._parse_event_element(elem, "Security")

        self.assertIsNotNone(ev)
        self.assertEqual(ev.category, EventCategory.LOG_CLEARED)
        self.assertEqual(ev.user, "Infiltrator_V")
        self.assertIn("CRITICAL ANTI-FORENSICS", ev.summary)

        # Mock DriverFrameworks Event 2003 (USB connection)
        xml_2003 = (
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
            "<System><EventID>2003</EventID><TimeCreated SystemTime='2026-11-18T10:05:00Z'/><EventRecordID>9002</EventRecordID></System>"
            "<EventData><Data Name='Lifetime'>USBSTOR#Disk&amp;Ven_Kingston&amp;Prod_DT3.0#00187D0F9A82B05&amp;0</Data></EventData>"
            "</Event>"
        )
        elem_2003 = ET.fromstring(xml_2003)
        ev_usb = ingestor._parse_event_element(elem_2003, "Microsoft-Windows-DriverFrameworks-UserMode/Operational")

        self.assertIsNotNone(ev_usb)
        self.assertEqual(ev_usb.category, EventCategory.USB_ATTACH)
        self.assertEqual(ev_usb.usb_serial, "00187D0F9A82B05")

    def test_realtime_reconstruction_and_deliverables(self) -> None:
        # Simulate an incident lifecycle directly
        simulate_live_incident(self.monitor, speed=0.01)

        self.assertTrue(len(self.monitor.event_window) >= 5)

        # Verify deliverables were created
        report_md = self.report_dir / "REALTIME_INCIDENT_REPORT.md"
        findings_json = self.report_dir / "realtime_findings.json"
        timeline_csv = self.report_dir / "realtime_super_timeline.csv"

        self.assertTrue(report_md.exists(), f"Missing {report_md}")
        self.assertTrue(findings_json.exists(), f"Missing {findings_json}")
        self.assertTrue(timeline_csv.exists(), f"Missing {timeline_csv}")

        # Check content of report
        md_text = report_md.read_text(encoding="utf-8")
        self.assertIn("REAL-TIME FORENSIC INCIDENT INVESTIGATION REPORT", md_text)
        self.assertIn("Removable Device (Pendrive / USB) Exfiltration Dossier", md_text)
        self.assertIn("A4B1C2D3", md_text)
        self.assertIn("exfil_stage.zip", md_text)

        # Check JSON
        import json
        data = json.loads(findings_json.read_text(encoding="utf-8"))
        self.assertEqual(data["case_id"], "TEST-INC-999")
        self.assertTrue(len(data["exfiltrated_files"]) >= 1)
        self.assertEqual(data["exfiltrated_files"][0]["file_name"], "exfil_stage.zip")


if __name__ == "__main__":
    unittest.main()
