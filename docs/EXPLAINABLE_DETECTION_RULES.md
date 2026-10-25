# Aegis-IDF: Explainable Forensic Detection Rules & Confidence Engine

> **Reference Specification for Incident Responders, Forensic Examiners, and Legal Review**  
> *Version 1.0.0 — Non-Black-Box Forensic Correlation Specification*

---

## 1. Philosophy of Explainable Forensics (X-DFIR)

Traditional security tools often output arbitrary "risk scores" (e.g., *"Risk Level: 87/100"*) based on opaque heuristics or machine-learning models. In digital forensics and legal proceedings, **black-box scores are inadmissible and indefensible**. 

A court-defensible forensic investigation requires:
1. **Evidentiary Provenance:** Every finding must cite the exact underlying physical artifact, record ID, byte offset, and acquisition SHA-256 hash.
2. **Separation of Fact Levels:** Explicitly distinguishing between what was **directly observed** (e.g., USB device plugged in at 14:10:00 UTC) versus what was **analytically inferred** (e.g., file copy deduced from Volume Serial Number correlation and temporal windowing).
3. **Rule Transparency:** Documenting the exact boolean and temporal conditions that caused a rule to trigger.
4. **Alternative Explanations:** Actively evaluating plausible benign explanations to prevent investigator confirmation bias.
5. **Evidence Gap Accounting:** Acknowledging missing data sources that prevent 100% indisputable certainty.

---

## 2. Mathematical Confidence Scoring Model

Aegis-IDF assigns a **Confidence Score (0.0 to 1.0)** and a categorical rating (`VERY_HIGH`, `HIGH`, `MEDIUM`, `LOW`, `TENTATIVE`) to each reconstructed incident hypothesis.

### 2.1 Source Reliability Weighting Table
Artifacts are mathematically weighted based on their resistance to user-space tampering:

| Artifact Source | Weight ($w_i$) | Architectural Justification |
| :--- | :---: | :--- |
| **`EVENT_LOG_DRIVER_FRAMEWORKS`** | **0.95** | Cryptographically signed Windows kernel Plug-and-Play (PnP) driver log. |
| **`EVENT_LOG_SECURITY`** | **0.95** | Core Windows security event auditing (requires SYSTEM/Admin privileges to clear). |
| **`EVENT_LOG_SYSTEM`** | **0.95** | Windows kernel subsystem logs. |
| **`NTFS_USN_JOURNAL`** | **0.90** | Immutable, append-only circular transaction journal managed by the NTFS kernel driver (`ntfs.sys`). |
| **`PREFETCH`** | **0.90** | Managed by Windows Memory/Cache Manager; stores run counts and last 8 launch timestamps. |
| **`JUMP_LIST`** | **0.85** | Application-specific OLE CFBF container (`AutomaticDestinations-ms`) recording MRU access. |
| **`LNK_SHORTCUT`** | **0.85** | Shell Link binary holding Volume Serial Numbers, file sizes, and network MAC addresses. |
| **`REGISTRY_USBSTOR`** | **0.85** | Windows device enumeration hive tracking unique hardware serial numbers. |
| **`BROWSER_SQLITE`** | **0.80** | Application SQLite database recording cloud upload endpoints. |
| **`NTFS_MFT` ($STANDARD_INFO)** | **0.50** | **Vulnerable to timestomping** via standard Win32 user-space APIs (`SetFileTime`). |
| **`NTFS_MFT` ($FILE_NAME)** | **0.95** | Protected by NTFS kernel; updated only during file creation, rename, or relocation. |

### 2.2 Mathematical Formula

$$\text{Base Score} = \frac{\sum_{i=1}^{N} \left( w_i \times \text{FactMultiplier}_i \right)}{\sum_{i=1}^{N} 1}$$

Where:
- $\text{FactMultiplier}_i = 1.0$ for `DIRECT_OBSERVATION`
- $\text{FactMultiplier}_i = 0.8$ for `INFERRED_RELATIONSHIP`

### 2.3 Multi-Artifact Corroboration Boost
Having multiple independent forensic artifact sources corroborating the same event sequence exponentially reduces false positive rates:

$$\text{Final Score} = \min\left( \text{Base Score} + \min(U \times 0.05, 0.20) + \text{AnomalyBonus}, \; 0.99 \right)$$

- $U$: Number of distinct, independent artifact types supporting the incident.
- $\text{AnomalyBonus} = +0.05$ if deliberate anti-forensic tampering (e.g., Event Log cleared or timestomping) is proven.

### 2.4 Categorical Confidence Ratings

| Range | Rating | Investigative Interpretation |
| :--- | :--- | :--- |
| **$\ge 0.90$** | **`VERY_HIGH`** | Multiple immutable kernel sources corroborate the sequence; anti-forensics or direct VSN matches present. Court-defensible. |
| **$0.75 - 0.89$** | **`HIGH`** | Clear multi-artifact alignment (e.g., Prefetch + USB + LNK), but relies on inferred transfer without Event 4663. |
| **$0.60 - 0.74$** | **`MEDIUM`** | Sequence supported by 1–2 sources with moderate temporal proximity. Requires additional corroboration. |
| **$0.40 - 0.59$** | **`LOW`** | Weak correlation or isolated artifact; plausible benign explanations dominate. |
| **$< 0.40$** | **`TENTATIVE`** | Speculative hypothesis with significant evidence gaps. |

---

## 3. Catalog of Explainable Detection Rules

### Rule 1: `RULE_STAGING_DURING_REMOVABLE_MEDIA_SESSION`
- **Category:** Staging & Exfiltration Preparation
- **Trigger Conditions:**
  1. An external storage device (`USBSTOR` or `DriverFrameworks` Event 2003) is attached to the system.
  2. While the device remains connected ($T_{\text{attach}} \le t \le T_{\text{detach}}$), an archiving tool (`7z.exe`, `winrar.exe`, `tar.exe`) executes according to Prefetch.
  3. A new archive container (`.zip`, `.7z`, `.rar`, `.tar`) is created according to NTFS USN Journal ($J) records.
- **Why It Matters:** Legitimate users rarely compress work files immediately after inserting a personal thumb drive unless preparing a bundled payload for exfiltration.
- **Benign Alternative Evaluated:** User was performing an authorized local system backup or compressing large folders purely to save local SSD capacity.

---

### Rule 2: `RULE_USB_VOLUME_SERIAL_EXFILTRATION_CORRELATION`
- **Category:** USB Correlation & Attribution
- **Trigger Conditions:**
  1. A Windows Shell Link (`.lnk`) or JumpList entry references a file path.
  2. The embedded **Volume Serial Number (VSN)** in the LNK `VolumeID` block matches the Volume Serial Number associated with an attached USB drive (`MountedDevices`).
- **Why It Matters:** Suspects frequently claim *"I only plugged in my thumb drive to charge my phone, or to listen to music."* Extracting an identical Volume Serial Number from a shortcut created during the session proves that files were accessed or written to that specific physical volume.
- **Investigative Limitation:** If the USB drive was formatted as FAT32, the VSN is a 32-bit random number generated at format time. Proof is mathematically robust ($1 \text{ in } 4.29 \times 10^9$ chance of collision).

---

### Rule 3: `RULE_MALICIOUS_ANTI_FORENSICS_CORROBORATION`
- **Category:** Tampering & Evidence Destruction
- **Trigger Conditions:**
  1. Windows Security Event Log contains **Event ID 1102** (*"The audit log was cleared"*), OR
  2. Windows System Event Log contains **Event ID 104** (*"The system log file was cleared"*).
- **Why It Matters:** Standard employees do not clear Windows Security logs. Doing so requires administrative privileges and is a high-confidence indicator of deliberate guilt and cover-up.
- **Investigative Impact:** Erases historical logon sessions and process execution (Event 4688) records preceding the event.

---

### Rule 4: `RULE_TIMESTOMP_SI_FN_CONTRADICTION`
- **Category:** Anti-Forensic Anomaly Detection
- **Trigger Conditions:**
  1. Master File Table (`$MFT`) record for a file is analyzed.
  2. The `$STANDARD_INFORMATION` (SI) Modified timestamp is strictly earlier than the `$FILE_NAME` (FN) Modified timestamp:
     $$\text{Timestamp}_{\text{SI-Modified}} < \text{Timestamp}_{\text{FN-Modified}}$$
  3. OR the SI timestamp contains sub-second nanosecond zeroing (`.0000000`).
- **Why It Matters:** Win32 APIs like `SetFileTime` allow user-space tools (`timestomp`, PowerShell) to alter SI timestamps to make stolen files appear months or years old. However, the Windows NTFS kernel driver (`ntfs.sys`) only updates FN timestamps during genuine file creation or rename operations. A discrepancy is conclusive proof of timestomping.

---

### Rule 5: `RULE_GHOST_STAGING_REMOVAL`
- **Category:** Deleted Artifact Recovery
- **Trigger Conditions:**
  1. NTFS `$UsnJrnl` (`$J`) records show a file created with an archive extension (`.7z`, `.zip`, `.tar`).
  2. The same journal records a subsequent `USN_REASON_FILE_DELETE` within the same incident window.
  3. The file no longer exists in active MFT records or on disk.
- **Why It Matters:** Insiders commonly create `backup.zip`, copy it to their flash drive, and press `Shift+Delete` to leave no file on the desktop. The USN Journal preserves the record of its creation, write, and destruction.

---

### Rule 6: `RULE_CROSS_ARTIFACT_OMISSION`
- **Category:** Audit Policy Discrepancy
- **Trigger Conditions:**
  1. Prefetch confirms execution of an archiving or data-staging utility (`7Z.EXE`, `WINRAR.EXE`).
  2. Windows Security Event Log (Event ID 4688) contains **zero** process creation records for that executable during the incident window.
- **Why It Matters:** Identifies that either Process Creation Auditing was deliberately disabled in Local Security Policy, or that specific security logs were selectively deleted.

---

### Rule 7: `RULE_CLOUD_STORAGE_EXFILTRATION_ENDPOINT`
- **Category:** Web / Cloud Exfiltration
- **Trigger Conditions:**
  1. Browser SQLite history (Chrome, Edge, Firefox) records a visit to a known upload endpoint (`wetransfer.com/upload`, `mega.nz`, `drive.google.com/upload`, `dropbox.com`).
  2. The upload access occurs within $\pm 15\text{ minutes}$ of sensitive file access or staging archive creation.
- **Why It Matters:** Detects exfiltration channels that bypass physical USB restrictions.

---

## 4. Alternative Explanations Evaluated

To avoid investigative bias, Aegis-IDF systematically evaluates and reports plausible benign explanations:

1. **Authorized IT Administration:** The user was conducting an approved administrative migration, database backup, or routine maintenance script.
2. **Accidental Multi-Tasking:** The user plugged in a personal USB drive solely to charge their phone or play music while legitimately working on confidential documents simultaneously.
3. **Routine Storage Management:** The user compressed large folders to reclaim disk space without any intention of exfiltration.

---

## 5. Defense Questions & Evidentiary Gaps

When presenting findings to legal counsel or human resources, Aegis-IDF explicitly outlines the questions that opposing counsel will ask:

| Defense Challenge | How Aegis-IDF Resolves / Documents It |
| :--- | :--- |
| *"You can't prove my client copied the file to USB; Windows doesn't log copies."* | **Aegis-IDF explicitly marks the step as `UNCONFIRMED`** and notes: *"Windows requires Removable Storage Auditing (Event 4663) to prove raw bytes; however, Volume Serial Number linkage and active session window provide strong circumstantial proof."* |
| *"The timestamps show this file was created in 2021, long before the incident."* | **Aegis-IDF cites the MFT Anomaly:** *"$STANDARD_INFORMATION was manipulated to 2021, but kernel-enforced $FILE_NAME timestamps prove creation on 2026-10-24."* |
| *"Someone else plugged in that USB drive."* | **Aegis-IDF correlates user identity:** Cites Security Event 4624 (Logon ID), user SID in registry hives, and `NTUSER.DAT` UserAssist / Shellbags paths. |
