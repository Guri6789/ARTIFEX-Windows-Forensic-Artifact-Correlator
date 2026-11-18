"""Windows Prefetch (.pf) Decompressor and Execution Parser.

Supports:
- Windows 10/11 MAM-compressed Prefetch files (XPRESS Huffman decompression via ntdll on Windows or pure-Python fallback)
- Uncompressed SCCA prefetch formats (Version 17, 23, 26, 30)
- Execution counts and extraction of the last 8 execution timestamps
- Extraction of loaded file metrics and strings (proves files touched by staging processes)
- Structured prefetch triage exports (JSON format)
"""

from __future__ import annotations

import json
import re
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

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
from insider_forensics.parsers.base import BaseArtifactParser, filetime_to_datetime


class PrefetchParser(BaseArtifactParser):
    """Parses binary or exported Windows Prefetch execution artifacts."""

    PARSER_NAME = "PrefetchParser"
    PARSER_VERSION = "2.0.0"

    MAM_MAGIC = b"MAM\x04"
    SCCA_MAGIC = b"SCCA"

    STAGING_TOOLS = {
        "7Z.EXE", "7ZG.EXE", "WINRAR.EXE", "RAR.EXE", "TAR.EXE", "ZIP.EXE",
        "RCLONE.EXE", "MEGASYNC.EXE", "POWERSHELL.EXE", "PWSH.EXE", "CMD.EXE",
        "CERTUTIL.EXE", "BITSADMIN.EXE", "CURL.EXE", "ROBOCOPY.EXE"
    }

    def parse(self, file_path: Path) -> List[ForensicEvent]:
        evidence = self.register_file(file_path, "PREFETCH_EXECUTION")
        events: List[ForensicEvent] = []

        # Case 1: Structured JSON export
        if file_path.suffix.lower() == ".json":
            return self._parse_json_export(file_path, evidence.evidence_id)

        # Case 2: Binary .pf file
        try:
            raw_bytes = file_path.read_bytes()
            if not raw_bytes:
                return events

            decompressed = self._decompress_if_mam(raw_bytes)
            events.extend(self._parse_scca_binary(decompressed, file_path.name, evidence.evidence_id))
        except Exception:
            pass

        return events

    def _decompress_if_mam(self, data: bytes) -> bytes:
        """Decompress MAM-compressed prefetch using Windows ntdll or fallback."""
        if len(data) <= 8 or data[:4] != self.MAM_MAGIC:
            return data

        uncompressed_size = struct.unpack("<I", data[4:8])[0]

        # Method 1: Windows ntdll RtlDecompressBufferEx
        if sys.platform == "win32":
            try:
                import ctypes
                from ctypes import wintypes
                ntdll = ctypes.windll.ntdll
                buf = ctypes.create_string_buffer(uncompressed_size)
                final_size = wintypes.ULONG(0)
                work_space_size = wintypes.ULONG(0)
                frag_work_space_size = wintypes.ULONG(0)
                # 4 = COMPRESSION_FORMAT_XPRESS_HUFF
                res = ntdll.RtlGetCompressionWorkSpaceSize(4, ctypes.byref(work_space_size), ctypes.byref(frag_work_space_size))
                if res == 0:
                    work_space = ctypes.create_string_buffer(work_space_size.value)
                    status = ntdll.RtlDecompressBufferEx(
                        4,
                        buf,
                        uncompressed_size,
                        data[8:],
                        len(data) - 8,
                        ctypes.byref(final_size),
                        work_space,
                    )
                    if status == 0:
                        return buf.raw[:final_size.value]
            except Exception:
                pass

        # Method 2: Pure Python Xpress Huffman decompression fallback
        decompressed = self._xpress_huffman_decompress(data[8:], uncompressed_size)
        if decompressed:
            return decompressed

        # Fallback to payload slice
        return data[8:]

    def _xpress_huffman_decompress(self, compressed_data: bytes, expected_size: int) -> Optional[bytes]:
        """Pure-Python Xpress Huffman decompressor for Windows 10/11 MAM Prefetch."""
        try:
            output = bytearray()
            pos = 0
            n_compressed = len(compressed_data)

            while pos < n_compressed and len(output) < expected_size:
                # Read 256-byte Huffman code length table (512 4-bit nibbles)
                if pos + 256 > n_compressed:
                    break
                table_bytes = compressed_data[pos:pos + 256]
                pos += 256

                # Build lengths
                lengths = [0] * 512
                for i in range(256):
                    b = table_bytes[i]
                    lengths[2 * i] = b & 0x0F
                    lengths[2 * i + 1] = (b >> 4) & 0x0F

                # Build prefix decode tree
                tree = self._build_huffman_tree(lengths)
                if not tree:
                    break

                # Bitstream reader for 64KB block
                block_target = min(len(output) + 65536, expected_size)
                bit_buf = 0
                bit_count = 0

                while len(output) < block_target and (pos < n_compressed or bit_count > 0):
                    while bit_count <= 16 and pos < n_compressed:
                        bit_buf |= (compressed_data[pos] << bit_count)
                        pos += 1
                        bit_count += 8

                    symbol, bits_used = self._decode_symbol(tree, bit_buf, bit_count)
                    if bits_used == 0:
                        break

                    bit_buf >>= bits_used
                    bit_count -= bits_used

                    if symbol < 256:
                        # Literal byte
                        output.append(symbol)
                    else:
                        # Match: pointer length and offset
                        match_symbol = symbol - 256
                        match_len = (match_symbol & 0x0F) + 3
                        offset_bits = match_symbol >> 4

                        while bit_count < offset_bits and pos < n_compressed:
                            bit_buf |= (compressed_data[pos] << bit_count)
                            pos += 1
                            bit_count += 8

                        match_offset = (1 << offset_bits) | (bit_buf & ((1 << offset_bits) - 1)) if offset_bits > 0 else 1
                        bit_buf >>= offset_bits
                        bit_count -= offset_bits

                        src_pos = len(output) - match_offset
                        if src_pos < 0:
                            break
                        for _ in range(match_len):
                            output.append(output[src_pos])
                            src_pos += 1

            if len(output) >= expected_size // 2:
                return bytes(output)
            return None
        except Exception:
            return None

    @staticmethod
    def _build_huffman_tree(lengths: List[int]) -> Dict[Tuple[int, int], int]:
        """Build canonical prefix code lookup table: (code, bit_len) -> symbol."""
        tree = {}
        bl_count = [0] * 16
        for l in lengths:
            if l > 0:
                bl_count[l] += 1

        code = 0
        next_code = [0] * 16
        for bits in range(1, 16):
            code = (code + bl_count[bits - 1]) << 1
            next_code[bits] = code

        for symbol, l in enumerate(lengths):
            if l != 0:
                c = next_code[l]
                tree[(c, l)] = symbol
                next_code[l] += 1
        return tree

    @staticmethod
    def _decode_symbol(tree: Dict[Tuple[int, int], int], bit_buf: int, bit_count: int) -> Tuple[int, int]:
        """Decode next symbol from bit buffer."""
        curr = 0
        for bits in range(1, min(16, bit_count + 1)):
            curr = (curr << 1) | ((bit_buf >> (bits - 1)) & 1)
            if (curr, bits) in tree:
                return tree[(curr, bits)], bits
        return 0, 0

    def _parse_scca_binary(self, data: bytes, filename: str, evidence_id: str) -> List[ForensicEvent]:
        """Parse uncompressed SCCA prefetch structure (Versions 17, 23, 26, 30)."""
        events: List[ForensicEvent] = []
        if len(data) < 84:
            return events

        # SCCA magic can be at offset 0 or offset 4
        magic = data[:4] if data[:4] == self.SCCA_MAGIC else data[4:8]
        if magic != self.SCCA_MAGIC:
            return events

        # Version
        version = struct.unpack("<I", data[:4])[0] if data[:4] != self.SCCA_MAGIC else struct.unpack("<I", data[4:8])[0]

        # Executable name: offset 0x10, 60 bytes UTF-16LE
        raw_name = data[0x10:0x4C]
        try:
            exe_name = raw_name.decode("utf-16le", errors="ignore").split("\x00")[0].upper().strip()
        except Exception:
            exe_name = ""

        if not exe_name:
            exe_name = filename.split("-")[0].upper()

        run_count = 1
        timestamps: List[datetime] = []

        # Version 30 (Windows 10 / 11)
        if version == 30 and len(data) >= 0xD4:
            run_count = struct.unpack("<I", data[0xD0:0xD4])[0]
            for i in range(8):
                off = 0x80 + (i * 8)
                ft = struct.unpack("<Q", data[off:off + 8])[0]
                dt = filetime_to_datetime(ft)
                if dt:
                    timestamps.append(dt)

        # Version 26 (Windows 8 / 8.1)
        elif version == 26 and len(data) >= 0xD4:
            run_count = struct.unpack("<I", data[0xD0:0xD4])[0]
            for i in range(8):
                off = 0x78 + (i * 8)
                ft = struct.unpack("<Q", data[off:off + 8])[0]
                dt = filetime_to_datetime(ft)
                if dt:
                    timestamps.append(dt)

        # Version 23 (Windows 7)
        elif version == 23 and len(data) >= 0x9C:
            run_count = struct.unpack("<I", data[0x98:0x9C])[0]
            ft = struct.unpack("<Q", data[0x80:0x88])[0]
            dt = filetime_to_datetime(ft)
            if dt:
                timestamps.append(dt)

        # Version 17 (Windows XP)
        elif version == 17 and len(data) >= 0x4C:
            run_count = struct.unpack("<I", data[0x44:0x48])[0]
            ft = struct.unpack("<Q", data[0x48:0x50])[0]
            dt = filetime_to_datetime(ft)
            if dt:
                timestamps.append(dt)

        if not timestamps:
            timestamps.append(datetime.now(timezone.utc))

        # Extract referenced strings (file metrics)
        referenced_files = self._extract_referenced_files(data)

        # Build events for each execution timestamp
        is_staging = exe_name in self.STAGING_TOOLS
        cat = EventCategory.FILE_STAGING if is_staging else EventCategory.PROCESS_EXECUTION

        for ts in timestamps:
            summary = (
                f"Execution verified via Prefetch: {exe_name} (Run Count: {run_count}, "
                f"Referenced: {len(referenced_files)} file paths)"
            )
            event = self.create_event(
                timestamp=ts,
                artifact_type=ArtifactType.PREFETCH,
                category=cat,
                summary=summary,
                evidence_id=evidence_id,
                fact_level=FactLevel.DIRECT_OBSERVATION,
                process_name=exe_name,
                raw_metadata={
                    "run_count": run_count,
                    "source_file": filename,
                    "version": version,
                    "referenced_files": referenced_files[:10],
                },
            )
            events.append(event)

        return events

    def _extract_referenced_files(self, data: bytes) -> List[str]:
        """Carve referenced file paths from prefetch string table / binary stream."""
        paths: List[str] = []
        for m in re.finditer(rb"(?:(?:[A-Za-z]\x00:\x00|\\\x00D\x00E\x00V\x00I\x00C\x00E\x00)[^\x00]{2,300})", data):
            try:
                s = m.group(0).decode("utf-16le", errors="ignore").split("\x00")[0]
                if s and len(s) > 4:
                    paths.append(s)
            except Exception:
                pass
        return paths[:50]

    def _parse_json_export(self, file_path: Path, evidence_id: str) -> List[ForensicEvent]:
        """Parse structured prefetch JSON export."""
        events: List[ForensicEvent] = []
        try:
            data = json.loads(file_path.read_text(encoding="utf-8"))
            records = data if isinstance(data, list) else data.get("prefetch", [data])
            for rec in records:
                proc = (rec.get("process_name") or rec.get("executable") or "").upper().strip()
                count = rec.get("run_count", 1)
                ts_list = rec.get("timestamps") or [rec.get("timestamp") or rec.get("last_run")]
                ref_files = rec.get("referenced_files") or []

                is_staging = proc in self.STAGING_TOOLS
                cat = EventCategory.FILE_STAGING if is_staging else EventCategory.PROCESS_EXECUTION

                for t_val in ts_list:
                    if not t_val:
                        continue
                    try:
                        ts = datetime.fromisoformat(str(t_val).replace("Z", "+00:00"))
                        if ts.tzinfo is None:
                            ts = ts.replace(tzinfo=timezone.utc)
                    except ValueError:
                        continue

                    summary = f"Execution verified via Prefetch: {proc} (Run Count: {count})"
                    event = self.create_event(
                        timestamp=ts,
                        artifact_type=ArtifactType.PREFETCH,
                        category=cat,
                        summary=summary,
                        evidence_id=evidence_id,
                        fact_level=FactLevel.DIRECT_OBSERVATION,
                        process_name=proc,
                        raw_metadata={"run_count": count, "referenced_files": ref_files, "record": rec},
                    )
                    events.append(event)
        except Exception:
            pass
        return events
