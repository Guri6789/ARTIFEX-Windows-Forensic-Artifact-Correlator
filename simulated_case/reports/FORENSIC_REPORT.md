# DIGITAL FORENSIC INVESTIGATION REPORT
## Windows Forensic Artifact Analysis: Insider Data Exfiltration
**Generated:** 2026-10-25 08:07:35 UTC  
**Investigation Case ID:** `HYP-E0B14132`  
**Subject of Investigation:** `jdoe`  
**Incident Time Window:** `2026-10-24 14:02:00 UTC` to `2026-10-24 14:35:00 UTC`  
**Confidence Rating:** **VERY_HIGH** (Score: 99.0%)  

---
### 1. Executive Summary
Forensic examination of Windows system artifacts identified a coordinated multi-stage data exfiltration sequence targeting **3 sensitive file(s)**. The activity involved temporary staging container creation (exfil_backup.7z), attachment of unauthorized removable storage (SanDisk (Serial: 07018899AABB, Drive: E:), USB (Serial: 07018899AABB, Drive: N/A)), followed by deliberate anti-forensic tampering (4 anomalies detected).

---
### 2. Reconstructed Incident Sequence (5-Stage Lifecycle)
The table below details each chronological stage of the incident, distinguishing directly verified facts from analytical inferences:

| Step | Stage | Verification Status | Timestamp (UTC) | Description |
| :--- | :--- | :--- | :--- | :--- |
| 1 | `RECONNAISSANCE` | **CONFIRMED** | 2026-10-24 14:02:00 | Insider accessed or browsed 3 sensitive file(s) via Explorer/LNK/JumpLists. |
| 2 | `FILE_STAGING` | **CONFIRMED** | 2026-10-24 14:08:00 | Data staging activity detected: Archive containers identified (exfil_backup.7z) corroborated by Prefetch and NTFS USN Journal. |
| 3 | `DEVICE_PREPARATION` | **CONFIRMED** | 2026-10-24 14:10:00 | External storage device mounted: SanDisk (Serial: 07018899AABB, Drive: E:), USB (Serial: 07018899AABB, Drive: N/A). |
| 4 | `DATA_TRANSFER` | **UNCONFIRMED** | 2026-10-24 14:15:00 | Data exfiltration via Removable USB Storage (VSN Correlated) and Web Cloud Storage Upload |
| 5 | `COVER_UP_ANTI_FORENSICS` | **CONFIRMED** | 2026-10-24 14:02:00 | Evidence tampering and cleanup activities detected (file deletion, timestomping, or log clearing). |

#### Detailed Step Analysis & Supporting Artifacts:

##### Step 1: [RECONNAISSANCE] - Status: CONFIRMED
- **Summary:** Insider accessed or browsed 3 sensitive file(s) via Explorer/LNK/JumpLists.
- **Corroborating Forensic Events (3):**
  - `[14:02:00]` **LNK_SHORTCUT** (DIRECT_OBSERVATION): Recent file access recorded in JumpList/LNK: C:\Users\jdoe\Documents\Confidential\Client_Financials_Q4.xlsx (VSN: 8C901234)
  - `[14:04:00]` **LNK_SHORTCUT** (DIRECT_OBSERVATION): Recent file access recorded in JumpList/LNK: C:\Users\jdoe\Documents\Confidential\Patents_TradeSecrets.docx (VSN: 8C901234)
  - `[14:22:00]` **LNK_SHORTCUT** (DIRECT_OBSERVATION): Recent file access recorded in JumpList/LNK: E:\exfil_backup.7z (VSN: 4A8F201B)

##### Step 2: [FILE_STAGING] - Status: CONFIRMED
- **Summary:** Data staging activity detected: Archive containers identified (exfil_backup.7z) corroborated by Prefetch and NTFS USN Journal.
- **Corroborating Forensic Events (2):**
  - `[14:08:00]` **PREFETCH** (DIRECT_OBSERVATION): Prefetch execution recorded: 7Z.EXE (Runs: 3)
  - `[14:09:00]` **NTFS_USN_JOURNAL** (DIRECT_OBSERVATION): Staging archive created: exfil_backup.7z

##### Step 3: [DEVICE_PREPARATION] - Status: CONFIRMED
- **Summary:** External storage device mounted: SanDisk (Serial: 07018899AABB, Drive: E:), USB (Serial: 07018899AABB, Drive: N/A).
- **Corroborating Forensic Events (2):**
  - `[14:10:00]` **REGISTRY_USBSTOR** (DIRECT_OBSERVATION): USB Removable Storage connected: SanDisk Ultra_Cruzer (Serial: 07018899AABB, Drive: E:, VSN: 4A8F201B)
  - `[14:10:05]` **EVENT_LOG_DRIVER_FRAMEWORKS** (DIRECT_OBSERVATION): USB device connected / arrived logged via DriverFrameworks (Event 2003, Serial: 07018899AABB)

##### Step 4: [DATA_TRANSFER] - Status: UNCONFIRMED
- **Summary:** Data exfiltration via Removable USB Storage (VSN Correlated) and Web Cloud Storage Upload
- ⚠️ **Investigative Note on Unconfirmed Action:** Windows does not natively log raw file copy payload transfers to USB without Removable Storage Auditing (Event ID 4663). Transfer inferred from Volume Serial Number (VSN) linkage and contemporaneous device attachment.
- **Corroborating Forensic Events (2):**
  - `[14:15:00]` **BROWSER_SQLITE** (DIRECT_OBSERVATION): Cloud upload endpoint visited (WeTransfer Direct Upload): https://wetransfer.com/upload
  - `[14:09:00]` **LNK_SHORTCUT** (INFERRED_RELATIONSHIP): INFERRED LINKAGE: File 'exfil_backup.7z' was physically present on USB device (SanDisk Serial: 07018899AABB) based on exact Volume Serial Number match (VSN: 4A8F201B)

##### Step 5: [COVER_UP_ANTI_FORENSICS] - Status: CONFIRMED
- **Summary:** Evidence tampering and cleanup activities detected (file deletion, timestomping, or log clearing).
- **Corroborating Forensic Events (3):**
  - `[14:02:00]` **NTFS_MFT** (DIRECT_OBSERVATION): Anti-forensic timestomp detected on Client_Financials_Q4.xlsx
  - `[14:28:00]` **NTFS_USN_JOURNAL** (DIRECT_OBSERVATION): File permanently deleted via NTFS USN: exfil_backup.7z
  - `[14:35:00]` **EVENT_LOG_SECURITY** (DIRECT_OBSERVATION): CRITICAL ANTI-FORENSICS: Security Audit Log was explicitly CLEARED by user: jdoe

---
### 3. Forensic Anomalies & Evidence Gap Analysis
The forensic anomaly analyzer detected **4 inconsistency or tampering indicator(s)**:

#### ⚠️ [CRITICAL] Anti-Forensic Event Log Clearing (Security)
- **Anomaly Type:** `LOG_TAMPERING_CLEARED`
- **Finding Explanation:** The Security event log was deliberately wiped by user 'jdoe' at 2026-10-24T14:35:00+00:00. Windows Event ID: N/A.
- **Investigative Impact:** Historical audit records, logon session history, and process execution events prior to this timestamp were permanently erased, destroying evidence of pre-attack reconnaissance.
- **Recommended Follow-up:** Examine Volume Shadow Copies (VSS) or SIEM forwarders for preserved pre-clear logs.

#### ⚠️ [HIGH] Timestomp Anomaly Detected on Client_Financials_Q4.xlsx
- **Anomaly Type:** `TIMESTAMP_CONTRADICTION_TIMESTOMP`
- **Finding Explanation:** Inconsistency detected between NTFS $STANDARD_INFORMATION (user-modifiable) and $FILE_NAME (NTFS kernel-protected). Modified timestamp was altered by 0 seconds.
- **Investigative Impact:** The target file was manipulated to appear older than it actually is, designed to bypass date-bounded triage acquisition scripts and mislead timeline analysis.
- **Recommended Follow-up:** Rely on kernel-enforced $FILE_NAME timestamps and $UsnJrnl change logs rather than Explorer timestamps.

#### ⚠️ [HIGH] Ghost Staging Archive Destroyed: 'exfil_backup.7z'
- **Anomaly Type:** `GHOST_STAGING_REMOVAL`
- **Finding Explanation:** Staging archive container 'exfil_backup.7z' was actively populated/accessed and subsequently deleted via Shift+Delete/programmatic purge as evidenced by NTFS USN Journal records.
- **Investigative Impact:** The actual payload container is absent from disk, preventing direct hash verification of file contents. However, metadata traces confirm its temporary existence during the incident.
- **Recommended Follow-up:** Attempt file carving on unallocated NTFS clusters corresponding to the USN Journal FRN record.

#### ⚠️ [MEDIUM] Evidence Gap: Removable Storage Object Auditing Disabled
- **Anomaly Type:** `EVIDENCE_GAP_UNAUDITED_TRANSFER`
- **Finding Explanation:** Removable device connection was observed, but granular File Read/Write events on the removable drive (Event ID 4663) were not recorded by Windows Security Auditing.
- **Investigative Impact:** Exact byte-by-byte file copy actions must be proven through circumstantial correlation (Volume Serial Numbers in LNK files and temporal windowing) rather than direct transfer logs.
- **Recommended Follow-up:** Enable 'Audit Removable Storage' in Group Policy Object (GPO) for enterprise hosts.

---
### 4. Explainable Confidence Assessment & Alternative Explanations
- **Overall Confidence Score:** `99.0%` (VERY_HIGH)
- **Triggered Forensic Decision Rules:**
  - `RULE_MALICIOUS_ANTI_FORENSICS_CORROBORATION`
  - `RULE_STAGING_DURING_REMOVABLE_MEDIA_SESSION`
  - `RULE_USB_VOLUME_SERIAL_EXFILTRATION_CORRELATION`
  - `RULE_EVIDENCE_PURGE_AND_COVER_UP_SEQUENCE`

- **Corroborating Evidence Sources:**
  - REGISTRY_USBSTOR (Reliability Weight: 0.85)
  - BROWSER_SQLITE (Reliability Weight: 0.80)
  - NTFS_MFT (Reliability Weight: 0.75)
  - EVENT_LOG_SECURITY (Reliability Weight: 0.95)
  - LNK_SHORTCUT (Reliability Weight: 0.85)
  - NTFS_USN_JOURNAL (Reliability Weight: 0.90)
  - EVENT_LOG_DRIVER_FRAMEWORKS (Reliability Weight: 0.95)
  - PREFETCH (Reliability Weight: 0.90)

- **Plausible Alternative Explanations Evaluated:**
  - ℹ️ Accidental Multi-Tasking: Removable drive was connected for charging or personal media while work documents were simultaneously open.

- **Identified Evidence Gaps:**
  - 🔍 Exact File Copy Payload: Windows Removable Storage Auditing (Event 4663) or DLP agent logs not present.
  - 🔍 Physical Removable Storage Device: The physical USB thumb drive has not been seized for forensic bitstream imaging.

---
### 5. Chain of Custody & Cryptographic Evidence Manifest
All parsed forensic artifact containers have been verified with SHA-256 and SHA-1 cryptographic hashes:

| Evidence ID | Artifact File | Size (Bytes) | SHA-256 Hash | Integrity Status |
| :--- | :--- | :--- | :--- | :--- |
| `EV-3D9B7CAA0322` | `browser_history.json` | 146 | `3d9b7caa03223b16ed75...` | **VERIFIED_UNCHANGED** |
| `EV-406653A91835` | `mft_records.json` | 281 | `406653a91835d2bd8d53...` | **VERIFIED_UNCHANGED** |
| `EV-3B8463A356C2` | `security_driverframeworks_events.json` | 345 | `3b8463a356c29226d121...` | **VERIFIED_UNCHANGED** |
| `EV-BA99F30AF9A8` | `recent_jumplist_entries.json` | 570 | `ba99f30af9a80d64c909...` | **VERIFIED_UNCHANGED** |
| `EV-96D88FB1E2EB` | `usn_journal_records.json` | 302 | `96d88fb1e2eb9c6f5ede...` | **VERIFIED_UNCHANGED** |
| `EV-188DE5643111` | `prefetch_execution.json` | 292 | `188de56431117a3f6f3f...` | **VERIFIED_UNCHANGED** |
| `EV-DB63C78D8CC8` | `usbstor_registry.json` | 228 | `db63c78d8cc88efa146c...` | **VERIFIED_UNCHANGED** |