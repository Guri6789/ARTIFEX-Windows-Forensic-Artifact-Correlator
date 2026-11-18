# ARTIFEX: Windows Forensic Artifact Correlator

> **Insider Data Theft & Exfiltration Forensic Investigation Engine**  
> *Core Forensics & Live Incident Response — Zero GUI, Pure High-Performance CLI & Correlator*

---

## 🌟 The 5 Core Unique Forensic Pillars + FTK Imager Integration

### 1. FTK Imager Live Acquisition & Manifest Corroboration Engine
- **Automated FTK Imager CLI Bridge:** Executes `ftkimager.exe` for bitstream physical (`\\.\PhysicalDrive0`) or logical volume (`\\.\C:`) forensic disk imaging in Expert Witness (`.E01`) or raw (`.dd`) formats.
- **AccessData Audit Manifest Ingestion:** Parses FTK Imager acquisition logs (`*.txt`, `Image_Summary.txt`), extracting verified hardware serial numbers, examiner notes, sector counts, and SHA-1/MD5 checksums directly into the non-repudiation chain of custody.
- **Hardware-to-Registry Corroboration:** Cross-correlates physical drive serial numbers verified by FTK Imager with Windows `USBSTOR` registry keys and Volume Serial Numbers (VSN) in Shell Links.
- **Live Windows Triage Collector:** Native incident response collector for Windows endpoints that preserves Event Logs, Registry hives, Prefetch, LNKs, JumpLists, Browser databases, and SetupAPI logs into an FTK Imager-compatible manifest.

---

### 2. Data-Theft Reconstruction and USB Correlation Engine
- **Sequence Reconstruction:** Automates chronological reconstruction of the insider attack lifecycle across 5 stages:
  1. `RECONNAISSANCE` (File access via Shellbags / LNK / JumpLists)
  2. `FILE_STAGING` (Compression utility execution + temporary archive creation via Prefetch and USN Journal)
  3. `DEVICE_PREPARATION` (Removable media arrival and volume mounting via USBSTOR / DriverFrameworks)
  4. `DATA_TRANSFER` (Direct copy to USB / VSN match / Cloud upload)
  5. `COVER_UP_ANTI_FORENSICS` (Shift+Delete, timestomping, and event log clearing)
- **USB-to-File Correlation:** Links physical device serial numbers with drive letters and **Volume Serial Numbers (VSN)** embedded in `.lnk` files and Shellbags.
- **Fact Level Separation:** Formally categorizes every finding into `CONFIRMED` (backed by direct evidence) vs `UNCONFIRMED` (inferred relationships with clear gap notes).

---

### 3. Forensic Anomaly and Evidence-Gap Analyzer
- **Anti-Forensics Detection:** Automatically flags explicit event log clearings (Security Event ID 1102, System Event ID 104).
- **Timestomp Detection:** Compares user-space `$STANDARD_INFORMATION` (SI) timestamps against NTFS kernel-protected `$FILE_NAME` (FN) timestamps to flag backdated file tampering and sub-second nanosecond zeroing (`.0000000`).
- **Ghost Staging Recovery:** Reconstructs temporary staging containers (`.zip`, `.7z`) that were permanently purged (`Shift+Delete`) using immutable append-only NTFS `$UsnJrnl` (`$J`) change records.
- **Cross-Artifact Contradictions:** Flags execution proof in Prefetch that is missing corresponding Security 4688 records.
- **Investigative Explanations:** Explains the exact investigative impact and recommended follow-up for every detected anomaly.

---

### 4. Evidence Integrity and Provenance Tracking
- **Cryptographic Hashing:** Computes SHA-256 and SHA-1 hashes for all acquired triage files before ingestion.
- **Event Provenance:** Tags every single `ForensicEvent` with its source `evidence_id`, record ID, and parser version.
- **Non-Repudiation Audit:** Provides an automated `--verify-integrity` audit function that re-hashes all evidence files to prove zero post-acquisition tampering.
- **Chain of Custody Manifest:** Exports a cryptographic evidence manifest in Markdown and JSON.

---

### 5. Cross-Artifact Evidence Correlation Engine
- **Real Binary Format Support:** Native pure-Python binary parsers for:
  - Windows Event Logs: Binary `.evtx` (`ElfFile` / `ElfChnk` chunks, record headers with FILETIME decoding)
  - Windows Registry Hives: Binary `SYSTEM`, `SOFTWARE`, `NTUSER.DAT` (`regf` cells, `USBSTOR`, `MountedDevices`)
  - Windows Prefetch: Windows 10/11 MAM-compressed bitstreams and SCCA binary headers (v17/v23/v26/v30)
  - Shell Links & JumpLists: Binary `.lnk` structures and OLE CFBF `AutomaticDestinations-ms`
  - NTFS Filesystem Metadata: Raw binary `$MFT` (1024-byte records) and `$UsnJrnl:$J` streams
  - Browser Databases: SQLite `History` and `places.sqlite`
- **Multi-Dimensional Grouping:** Groups events across temporal sliding windows, canonical file paths, device serials, and user accounts.

---

## 📂 Project Architecture

```
ARTIFEX/
├── cli.py                         # Master CLI entrypoint (analyze, acquire, verify-ftk, simulate)
├── acquire_live_incident.ps1      # PowerShell Administrator live triage launcher
├── acquire_live_incident.bat      # Windows batch elevated launcher
├── imager/
│   ├── __init__.py                # Imager exports
│   └── ftk_imager.py              # FTKImagerController, FtkImagerLogParser & WindowsLiveTriageCollector
├── core/
│   ├── models.py                  # ForensicEvent, FactLevel, ConfidenceRating dataclasses
│   └── engine.py                  # Master coordination engine & magic-byte scanner
├── provenance/
│   └── tracker.py                 # Pillar 3: Evidence integrity & SHA-256 tracker
├── parsers/
│   ├── base.py                    # Base parser with FILETIME decoder & provenance hook
│   ├── usbstor_parser.py          # Binary REGF hive parser, USBSTOR, MountedDevices & SetupAPI
│   ├── prefetch_parser.py         # Binary SCCA parser & Windows 10/11 MAM decompressor
│   ├── lnk_jumplist_parser.py     # Binary LNK headers, VSNs & CFBF JumpLists
│   ├── mft_usn_parser.py          # $MFT (SI vs FN) & $UsnJrnl ghost staging recovery
│   ├── eventlog_parser.py         # Binary EVTX chunk scanner (Security, System, DriverFrameworks)
│   └── browser_parser.py          # Chromium / Firefox SQLite cloud upload endpoints
├── correlation/
│   ├── cross_correlator.py        # Pillar 4: Cross-artifact event grouping & VSN correlation
│   └── reconstruction.py          # Pillar 1: 5-stage data theft sequence synthesizer
├── anomaly/
│   └── gap_analyzer.py            # Pillar 2: Timestomp, ghost staging & gap analyzer
├── intelligence/
│   └── confidence_engine.py       # Pillar 5: Explainable confidence & alternative hypotheses
├── reporters/
│   ├── markdown_reporter.py       # Formal investigation dossier generator
│   ├── json_reporter.py           # Machine-readable JSON exporter
│   └── csv_timeline.py            # Super Timeline CSV exporter (Timeline Explorer/Plaso)
└── test_suite/
    ├── generator.py               # Synthetic realistic insider threat scenario generator
    ├── sample_ftk_summary.txt     # Authentic FTK Imager acquisition log sample
    ├── test_ftk_imager.py         # Automated tests for FTK Imager integration
    ├── test_real_artifacts.py     # Automated tests for binary EVTX, Registry & Prefetch
    ├── test_realtime_monitor.py   # Automated tests for real-time USB monitoring & reconstruction
    └── test_forensics.py          # Automated unit test suite verifying all 5 pillars
```

---

## 🚀 Quickstart & Real-Life Usage

### 1. Real-Time Removable Device (USB / Pendrive) Incident Monitoring
Continuously monitor live Windows endpoint telemetry for removable drive attachments, live file copies, staging, and anti-forensics:

```bash
# Live background monitoring on endpoint
python cli.py watch --output ./realtime_alerts --interval 2.0 --threshold 0.70

# Or run an authentic live incident simulation for demonstration/training:
python cli.py watch --output ./realtime_alerts --simulate
```

During live monitoring, ARTIFEX:
- Intercepts removable drive mounting via Windows Kernel32 APIs (`GetDriveTypeW`, `GetVolumeInformationW`).
- Extracts Volume Serial Numbers (VSN) and maps them to physical `USBSTOR` vendor, model, and hardware serials.
- Intercepts files written to the removable drive, computing on-the-fly SHA-256 / MD5 hashes.
- Ingests DriverFrameworks, Storage-ClassPnP, Partition, and Security Event Logs in real-time.
- Automatically reconstructs the 5-stage insider attack lifecycle and dynamically updates:
  - `REALTIME_INCIDENT_REPORT.md` (Executive dossier & device transfer table)
  - `realtime_findings.json` (Structured SIEM/SOAR findings)
  - `realtime_super_timeline.csv` (Super Timeline)

### 2. Dedicated Interactive Console REPL
Launch the zero-dependency forensic command-line shell:

```bash
python cli.py console
# Inside ARTIFEX console:
artifex> watch --simulate
artifex> status
artifex> simulate
artifex> test all
```

### 3. Live Windows Incident Triage Acquisition
Run as **Administrator** on the target Windows endpoint:

```powershell
.\acquire_live_incident.ps1 -CaseId "INC-2026-001" -Examiner "Lead Investigator" -AutoAnalyze
```

Or using the Python CLI directly:
```bash
python cli.py acquire --output ./evidence_dump --tool auto --case-id "INC-2026-001" --auto-analyze
```

### 4. Ingest & Correlate Real Forensic Triage / FTK Imager Exports
Analyze a folder of triage artifacts acquired with FTK Imager, KAPE, or Velociraptor:

```bash
python cli.py analyze --source /path/to/acquired_triage --output ./forensic_reports
```

### 5. Verify FTK Imager Acquisition Log Integrity
Verify an authentic FTK Imager `.txt` or `Image_Summary.txt` log manifest:

```bash
python cli.py verify-ftk --log /path/to/Image_Summary.txt
```

### 6. Run Automated Scenario Simulation
Run the built-in simulation for verification, training, and demonstrations:

```bash
python cli.py simulate --workspace ./simulated_case
```

### 7. Run Automated Unit Tests
```bash
python -m unittest discover -s test_suite -p "test_*.py"
```

---

## 📊 Investigation Deliverables Generated

Every investigation run automatically produces three formal artifacts:
1. `FORENSIC_REPORT.md` — Formal executive and technical investigation dossier with chain-of-custody manifest.
2. `forensic_findings.json` — Machine-readable structured findings for SIEM / SOAR automation.
3. `super_timeline.csv` — Standardized Super Timeline compatible with **Eric Zimmerman's Timeline Explorer** and **Plaso**.
