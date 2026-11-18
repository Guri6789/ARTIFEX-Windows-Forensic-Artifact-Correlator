"""Unit tests for binary Windows artifacts parsing (EVTX, Registry REGF, Prefetch SCCA)."""

from __future__ import annotations

import shutil
import struct
import sys
import tempfile
import unittest
from pathlib import Path

# Add project root to sys.path for direct test execution
_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from insider_forensics.core.models import ArtifactType, EventCategory
from insider_forensics.parsers.eventlog_parser import WindowsEventLogParser
from insider_forensics.parsers.prefetch_parser import PrefetchParser
from insider_forensics.parsers.usbstor_parser import UsbArtifactParser
from insider_forensics.provenance.tracker import EvidenceTracker


class TestRealBinaryArtifacts(unittest.TestCase):
    """Verifies binary parsing of real Windows artifacts."""

    def setUp(self) -> None:
        self.temp_dir = Path(tempfile.mkdtemp(prefix="test_binary_art_"))
        self.tracker = EvidenceTracker()

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_binary_evtx_parser(self) -> None:
        """Verify binary EVTX chunk and record parsing."""
        evtx_file = self.temp_dir / "Security.evtx"

        # Build mock binary EVTX with ElfFile header + 1 chunk + 1 record
        header = bytearray(4096)
        header[:8] = b"ElfFile\x00"

        chunk = bytearray(65536)
        chunk[:8] = b"ElfChnk\x00"

        # Record at offset 512
        rec_offset = 512
        ft = 133500000000000000

        # BinXml payload with Security 1102 (Log Cleared)
        payload = (
            "<Event><System><EventID>1102</EventID><TimeCreated SystemTime='2026-10-24T14:15:00Z'/>"
            "<Security UserID='CORP\\target_user'/></System></Event>"
        ).encode("utf-16le")

        rec_size = 24 + len(payload)
        chunk[rec_offset:rec_offset + 4] = b"\x2a\x2a\x00\x00"
        chunk[rec_offset + 4:rec_offset + 8] = struct.pack("<I", rec_size)
        chunk[rec_offset + 8:rec_offset + 16] = struct.pack("<Q", 501)
        chunk[rec_offset + 16:rec_offset + 24] = struct.pack("<Q", ft)
        chunk[rec_offset + 24:rec_offset + rec_size] = payload

        evtx_file.write_bytes(header + chunk)

        parser = WindowsEventLogParser(self.tracker)
        events = parser.parse(evtx_file)

        self.assertGreaterEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev.category, EventCategory.LOG_CLEARED)
        self.assertEqual(ev.artifact_type, ArtifactType.EVENT_LOG_SECURITY)
        self.assertIn("CLEARED", ev.summary)

    def test_binary_registry_hive_parser(self) -> None:
        """Verify binary REGF hive parsing for USBSTOR devices and drive mappings."""
        hive_file = self.temp_dir / "SYSTEM"

        data = bytearray(8192)
        data[:4] = b"regf"

        # Inject USBSTOR key string and MountedDevices string
        usbstor_key = b"Disk&Ven_SanDisk&Prod_ExtremePRO&Rev_1.00\\AA998877665544&0"
        data[4100:4100 + len(usbstor_key)] = usbstor_key

        mounted_dev = b"\\DosDevices\\E:"
        data[4500:4500 + len(mounted_dev)] = mounted_dev
        # Volume signature
        data[4500 + len(mounted_dev):4500 + len(mounted_dev) + 4] = struct.pack("<I", 0xA1B2C3D4)

        hive_file.write_bytes(data)

        parser = UsbArtifactParser(self.tracker)
        events = parser.parse(hive_file)

        self.assertGreaterEqual(len(events), 1)
        usb_events = [e for e in events if e.usb_serial == "AA998877665544"]
        self.assertEqual(len(usb_events), 1)
        self.assertIn("SanDisk", usb_events[0].usb_vendor)
        self.assertIn("ExtremePRO", usb_events[0].usb_product)

    def test_binary_scca_prefetch_parser(self) -> None:
        """Verify uncompressed SCCA prefetch header and timestamp parsing."""
        pf_file = self.temp_dir / "7Z.EXE-ABCD1234.pf"

        data = bytearray(512)
        # SCCA v30 (Windows 10/11)
        data[0:4] = struct.pack("<I", 30)
        data[4:8] = b"SCCA"

        # Executable name at offset 0x10: "7Z.EXE"
        name_bytes = "7Z.EXE".encode("utf-16le")
        data[0x10:0x10 + len(name_bytes)] = name_bytes

        # Run count at offset 0xD0: 5
        data[0xD0:0xD4] = struct.pack("<I", 5)

        # Execution timestamp at offset 0x80
        ft = 133500000000000000
        data[0x80:0x88] = struct.pack("<Q", ft)

        pf_file.write_bytes(data)

        parser = PrefetchParser(self.tracker)
        events = parser.parse(pf_file)

        self.assertGreaterEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev.process_name, "7Z.EXE")
        self.assertEqual(ev.raw_metadata["run_count"], 5)
        self.assertEqual(ev.category, EventCategory.FILE_STAGING)


# Backward compatibility alias
TestRealArtifactParsers = TestRealBinaryArtifacts


if __name__ == "__main__":
    unittest.main()
