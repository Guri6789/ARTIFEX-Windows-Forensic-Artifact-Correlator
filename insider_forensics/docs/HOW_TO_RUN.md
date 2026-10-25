# Aegis-IDF: Complete Operator & Execution Guide

> **How to Run, Analyze, and Interpret Forensic Investigations**  
> *Windows Forensic Artifact Analysis Engine for Insider Data Theft*

---

## 1. System Requirements

- **Operating System:** Linux (Ubuntu/Debian/Arch/RHEL), macOS, or Windows 10/11
- **Python Version:** Python **3.9 or newer** (tested and verified on Python **3.13**)
- **Dependencies:** **Zero external compiled binaries required.** The core engine runs entirely on standard Python modules (`hashlib`, `struct`, `sqlite3`, `json`, `csv`, `pathlib`, `typing`, `dataclasses`).

---

## 2. Quick Verification (Run the Test Suite)

Before processing live triage cases, verify that all 5 forensic engines are operating correctly on your system:

```bash
python3 -m unittest discover -s insider_forensics/test_suite -p "test_*.py"
```

**Expected output:**
```
.....
----------------------------------------------------------------------
Ran 5 tests in 0.014s

OK
```

All 5 tests verify:
1. `test_pillar_1_data_theft_reconstruction`: Reconstructs 5-stage attack lifecycle and distinguishes confirmed vs unconfirmed steps.
2. `test_pillar_2_forensic_anomalies_and_gaps`: Detects timestomping, ghost staging deletion, and event log clearing.
3. `test_pillar_3_evidence_integrity_and_provenance`: Verifies SHA-256 calculation and non-repudiation audit.
4. `test_pillar_4_cross_artifact_correlation`: Verifies USB device session mapping to Volume Serial Numbers.
5. `test_pillar_5_explainable_confidence_and_reporting`: Validates rule documentation, alternative hypotheses, and report exports.

---

## 3. Execution Mode 1: Automated Scenario Simulation

If you want an immediate end-to-end demonstration of the 5 pillars without having an external Windows disk image ready:

```bash
python3 insider_forensics/cli.py simulate --workspace ./simulated_case
```

### What this does:
1. Creates realistic synthetic Windows forensic artifacts in `./simulated_case/synthetic_evidence/`:
   - `usbstor_registry.json` (SanDisk Cruzer USB serial & VSN)
   - `security_driverframeworks_events.json` (USB arrival Event 2003 + Audit Log Cleared Event 1102)
   - `recent_jumplist_entries.json` (LNK shortcuts to confidential spreadsheets with matching VSN)
   - `prefetch_execution.json` (7-Zip execution proofs)
   - `usn_journal_records.json` (NTFS USN file creation and Shift+Delete destruction)
   - `mft_records.json` (Timestomped $STANDARD_INFORMATION record)
   - `browser_history.json` (WeTransfer upload endpoint)
2. Automatically parses all 7 files and computes their SHA-256 hashes.
3. Reconstructs the 5-stage lifecycle.
4. Detects 4 forensic anomalies (timestomp, ghost staging, log wipe, missing removable storage auditing).
5. Outputs the full Markdown, JSON, and Super Timeline reports to `./simulated_case/reports/`.

---

## 4. Execution Mode 2: Analyzing Real-World Triage Dumps

To analyze a directory of acquired Windows forensic artifacts (e.g. collected via **KAPE**, **Velociraptor**, **CyLR**, or **FTK Imager**):

```bash
python3 insider_forensics/cli.py analyze --source /path/to/triage_folder --output ./my_investigation_reports
```

### Supported File Formats:
The parser auto-detects and processes:
- **Registry Dumps:** `USBSTOR`, `MountedDevices`, `UserAssist`, `Shellbags` (`.json`, text, or REG exports)
- **Event Logs:** `Security.evtx`, `System.evtx`, `Microsoft-Windows-DriverFrameworks-UserMode/Operational.evtx` (Binary `.evtx` or EvtxECmd JSON)
- **Prefetch:** `C:\Windows\Prefetch\*.pf` (MAM-compressed, SCCA binary, or PECmd JSON)
- **Shortcuts & JumpLists:** `*.lnk`, `*.automaticDestinations-ms` (Binary CFBF, LNK binary, or LECmd/JLECmd JSON)
- **NTFS Metadata:** Raw `$MFT`, `$UsnJrnl:$J` (Binary stream or MFTECmd JSON)
- **Browser Databases:** Chrome/Edge `History` SQLite, Firefox `places.sqlite`, or JSON export
- **SetupAPI Logs:** `setupapi.dev.log` (Raw text)

---

## 5. Execution Mode 3: Evidence Integrity Audit

By default, the `--verify-integrity` flag is enabled during analysis. To explicitly ensure that preserved evidence files have not been modified or corrupted post-collection:

```bash
python3 insider_forensics/cli.py analyze --source ./evidence_dir --output ./reports --verify-integrity
```

The tool prints:
```
[*] Re-verifying evidence integrity hashes against files on disk...
[*] Evidence Integrity Check: PASSED (Zero Alterations)
```
If an evidence file was modified by a single byte, it will immediately alert:
```
[!] Evidence Integrity Check: FAILED (Tampering Detected!)
    • EV-DB63C78D8CC8 [TAMPERED_HASH_MISMATCH]
```

---

## 6. Understanding the 3 Output Deliverables

After running an analysis, the output directory contains three court-defensible deliverables:

### 1. `FORENSIC_REPORT.md` (Formal Investigation Dossier)
- **Executive Summary:** High-level summary for legal counsel, HR, and executives.
- **5-Stage Reconstructed Sequence:**
  - Table of steps with `[CONFIRMED]` vs `[UNCONFIRMED]` badges.
  - Detailed breakdown of each step with corroborating event IDs and timestamps.
- **Forensic Anomalies & Evidence Gaps:**
  - Critical/High severity callouts for timestomping, log clearing, and ghost staging.
  - Investigative impact and recommended follow-up actions.
- **Explainable Confidence Assessment:**
  - Exact formula score and rating (`VERY_HIGH`, `HIGH`, etc.).
  - Triggered decision rules.
  - Plausible alternative explanations evaluated.
  - Missing evidence gaps.
- **Chain of Custody Manifest:** Table listing every evidence file, size in bytes, and SHA-256 hash.

### 2. `forensic_findings.json` (Machine-Readable Findings)
- Complete, structured JSON export of the incident hypothesis, step sequence, all anomalies, and evidence provenance.
- Ready for automated ingestion into SIEM platforms (Splunk, Elastic, Sentinel) or SOAR playbooks.

### 3. `super_timeline.csv` (Super Timeline)
- Standardized, chronological Super Timeline compatible with **Eric Zimmerman's Timeline Explorer** and **Plaso / log2timeline**.
- **Columns:**
  `Timestamp_UTC`, `Artifact_Source`, `Fact_Level`, `Event_Category`, `Summary`, `User`, `Process_Name`, `Command_Line`, `Source_File_Path`, `Volume_Serial`, `USB_Serial`, `Drive_Letter`, `Evidence_ID`, `Record_ID`.

To inspect the timeline in Linux terminal:
```bash
column -s, -t < ./simulated_case/reports/super_timeline.csv | less -S
```

---

## 7. CLI Command-Line Reference

```
usage: cli.py [-h] {analyze,simulate} ...

Windows Forensic Artifact Analysis Engine for Insider Data Theft (Aegis-IDF)

positional arguments:
  {analyze,simulate}
    analyze           Analyze a directory of acquired Windows artifacts
    simulate          Generate a realistic scenario and run full 5-pillar analysis

options:
  -h, --help          Show this help message and exit
```

### Options for `analyze`:
| Flag | Description | Default |
| :--- | :--- | :--- |
| `--source`, `-s` | Path to directory containing triage files or single file | *Required* |
| `--output`, `-o` | Output directory where reports will be saved | `./forensic_reports` |
| `--verify-integrity` | Calculate and verify SHA-256 hashes against disk files | `True` |

### Options for `simulate`:
| Flag | Description | Default |
| :--- | :--- | :--- |
| `--workspace`, `-w` | Directory where test evidence and reports will be created | `./simulated_case` |

---

## 8. Troubleshooting & FAQs

### Q1: Can I move the `insider_forensics` directory to my Desktop or another folder?
**Yes.** The project is completely self-contained. You can copy or move the entire folder:
```bash
cp -r insider_forensics ~/Desktop/
cd ~/Desktop/insider_forensics
python3 cli.py simulate
```

### Q2: Why does Step 4 (Data Transfer) say `UNCONFIRMED`?
This is intentional and forensically accurate. Standard Windows installations do not log file-level copy operations to USB drives unless **Removable Storage Auditing (Event ID 4663)** is enabled in Group Policy. Aegis-IDF proves data transfer circumstantially via Volume Serial Number (VSN) matches, and explicitly informs the investigator of the audit gap so findings remain court-defensible.

### Q3: What if I have raw binary `.pf` and `.lnk` files instead of JSON?
Aegis-IDF's binary parsers ([`prefetch_parser.py`](file:///home/guri/Desktop/honeypot-banking/insider_forensics/parsers/prefetch_parser.py) and [`lnk_jumplist_parser.py`](file:///home/guri/Desktop/honeypot-banking/insider_forensics/parsers/lnk_jumplist_parser.py)) directly parse raw binary files using native struct unpacking and XPRESS decompression checks.
