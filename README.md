# ARTIFEX: Windows Forensic Artifact Correlator

> **Insider Data Theft & Exfiltration Forensic Investigation Engine**  
> *Core Forensics Implementation — Zero GUI, Pure High-Performance CLI & Correlator*

---

## 🌟 The 5 Core Unique Forensic Pillars

### 1. Data-Theft Reconstruction and USB Correlation Engine
- **Sequence Reconstruction:** Automates chronological reconstruction of the insider attack lifecycle across 5 stages:
  1. `RECONNAISSANCE` (File access via Shellbags / LNK / JumpLists)
  2. `FILE_STAGING` (Compression utility execution + temporary archive creation via Prefetch and USN Journal)
  3. `DEVICE_PREPARATION` (Removable media arrival and volume mounting via USBSTOR / DriverFrameworks)
  4. `DATA_TRANSFER` (Direct copy to USB / VSN match / Cloud upload)
  5. `COVER_UP_ANTI_FORENSICS` (Shift+Delete, timestomping, and event log clearing)
- **USB-to-File Correlation:** Links physical device serial numbers with drive letters and **Volume Serial Numbers (VSN)** embedded in `.lnk` files and Shellbags.
- **Fact Level Separation:** Formally categorizes every finding into `CONFIRMED` (backed by direct evidence) vs `UNCONFIRMED` (inferred relationships with clear gap notes).

---

### 2. Forensic Anomaly and Evidence-Gap Analyzer
- **Anti-Forensics Detection:** Automatically flags explicit event log clearings (Security Event ID 1102, System Event ID 104).
- **Timestomp Detection:** Compares user-space `$STANDARD_INFORMATION` (SI) timestamps against NTFS kernel-protected `$FILE_NAME` (FN) timestamps to flag backdated file tampering and sub-second nanosecond zeroing (`.0000000`).
- **Ghost Staging Recovery:** Reconstructs temporary staging containers (`.zip`, `.7z`) that were permanently purged (`Shift+Delete`) using immutable append-only NTFS `$UsnJrnl` (`$J`) change records.
- **Cross-Artifact Contradictions:** Flags execution proof in Prefetch that is missing corresponding Security 4688 records.
- **Investigative Explanations:** Explains the exact investigative impact and recommended follow-up for every detected anomaly.

---

### 3. Evidence Integrity and Provenance Tracking
- **Cryptographic Hashing:** Computes SHA-256 and SHA-1 hashes for all acquired triage files before ingestion.
- **Event Provenance:** Tags every single `ForensicEvent` with its source `evidence_id`, record ID, and parser version.
- **Non-Repudiation Audit:** Provides an automated `--verify-integrity` audit function that re-hashes all evidence files to prove zero post-acquisition tampering.
- **Chain of Custody Manifest:** Exports a cryptographic evidence manifest in Markdown and JSON.

---

### 4. Cross-Artifact Evidence Correlation Engine
- **Multi-Source Connectivity:** Unifies Windows Event Logs, Registry (`USBSTOR`, `MountedDevices`), Shell Link (`.lnk`) files, JumpLists (`AutomaticDestinations-ms` CFBF), NTFS filesystem metadata (`$MFT`, `$UsnJrnl`), and browser databases.
- **Multi-Dimensional Grouping:** Groups events across temporal sliding windows, canonical file paths, device serials, and user accounts.
- **Fact Level Labeling:** Distinguishes observed physical facts (`DIRECT_OBSERVATION`) from analytical deductions (`INFERRED_RELATIONSHIP`).

---

### 5. Explainable Investigation and Confidence Engine
- **Weighted Mathematical Scoring:** Weights sources based on kernel reliability (EVTX: 0.95, USN: 0.90, Prefetch: 0.90, SI timestamp: 0.50).
- **Rule Explainability:** Documents which forensic rules triggered (`RULE_MALICIOUS_ANTI_FORENSICS_CORROBORATION`, `RULE_STAGING_DURING_REMOVABLE_MEDIA_SESSION`, etc.).
- **Alternative Explanations:** Evaluates benign alternative hypotheses (e.g., legitimate administrative backup, routine storage cleanup, phone charging).
- **Identified Evidence Gaps:** Explicitly lists missing data sources (e.g., Removable Storage Auditing Event 4663, physical thumb drive bitstream image).

---

## 📂 Project Architecture

```
insider_forensics/
├── cli.py                         # Master CLI entrypoint
├── core/
│   ├── models.py                  # ForensicEvent, FactLevel, ConfidenceRating dataclasses
│   └── engine.py                  # Master coordination engine
├── provenance/
│   └── tracker.py                 # Pillar 3: Evidence integrity & SHA-256 tracker
├── parsers/
│   ├── base.py                    # Base parser with FILETIME decoder & provenance hook
│   ├── usbstor_parser.py          # USBSTOR, MountedDevices, SetupAPI & EventLogs
│   ├── prefetch_parser.py         # .pf execution parsing & MAM decompression check
│   ├── lnk_jumplist_parser.py     # Binary LNK headers, VSNs & CFBF JumpLists
│   ├── mft_usn_parser.py          # $MFT (SI vs FN) & $UsnJrnl ghost staging recovery
│   ├── eventlog_parser.py         # Security, System & DriverFrameworks EVTX logs
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
    └── test_forensics.py          # Automated unit test suite verifying all 5 pillars
```

---

## 🚀 Quickstart & Usage

### 1. Run Built-in Automated Scenario Simulation
Run the end-to-end simulation to generate a realistic multi-artifact case, parse it, correlate the events, and produce reports:

```bash
python3 insider_forensics/cli.py simulate --workspace ./simulated_case
```

### 2. Analyze an Acquired Triage Folder
To analyze acquired Windows forensic files (e.g. from KAPE, Velociraptor, or CyLR):

```bash
python3 insider_forensics/cli.py analyze --source /path/to/triage_artifacts --output ./forensic_reports
```

### 3. Run Automated Unit Tests
```bash
python3 -m unittest discover -s insider_forensics/test_suite -p "test_*.py"
```

---

## 📊 Investigation Deliverables Generated

Every investigation run automatically produces three formal artifacts:
1. `FORENSIC_REPORT.md` — Formal executive and technical investigation dossier with chain-of-custody manifest.
2. `forensic_findings.json` — Machine-readable structured findings for SIEM / SOAR automation.
3. `super_timeline.csv` — Standardized Super Timeline compatible with **Eric Zimmerman's Timeline Explorer** and **Plaso**.
