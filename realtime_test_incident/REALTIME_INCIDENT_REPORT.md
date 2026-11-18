# REAL-TIME FORENSIC INCIDENT INVESTIGATION REPORT
## Windows Removable Device Artifact Analysis & Insider Data Theft
**Generated:** 2026-11-18 07:31:16 UTC  
**Case Number:** `INC-REALTIME-001`  
**Subject of Investigation:** `gurpr`  
**Threat Confidence:** **VERY_HIGH** (99.0%)  
**Monitoring Mode:** Active Real-Time CLI Watcher  

---
### 1. Removable Device (Pendrive / USB) Exfiltration Dossier
| Drive Letter | Volume Label | Volume Serial (VSN) | File System | Hardware Serial | Vendor / Product |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `E:` | **KINGSTON_32GB** | `A4B1C2D3` | FAT32 | `00187D0F9A82B05` | Kingston DataTraveler 3.0 |

#### Captured Exfiltrated Files on Removable Device:

| File Name | Size (Bytes) | Transferred (UTC) | Removable Drive | SHA-256 Hash | Type |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `exfil_stage.zip` | 14,850,220 | 07:31:15 | `E:` (VSN: A4B1C2D3) | `e3b0c44298fc1c149afb...` | **Staging Archive** |

---
### 2. Reconstructed Incident Sequence (5-Stage Attack Lifecycle)
| Step | Stage | Verification Status | Timestamp (UTC) | Description |
| :--- | :--- | :--- | :--- | :--- |
| 1 | `RECONNAISSANCE` | **CONFIRMED** | 2026-11-18 07:31:09 | Insider accessed or browsed 1 sensitive file(s) via Explorer/LNK/JumpLists. |
| 2 | `FILE_STAGING` | **CONFIRMED** | 2026-11-18 07:31:12 | Data staging activity detected: Archive containers identified (exfil_stage.zip) corroborated by Prefetch and NTFS USN Journal. |
| 3 | `DEVICE_PREPARATION` | **CONFIRMED** | 2026-11-18 07:31:13 | External storage device mounted: Kingston (Serial: 00187D0F9A82B05, Drive: E:). |
| 4 | `DATA_TRANSFER` | **UNCONFIRMED** | 2026-11-18 07:31:15 | Data exfiltration via Removable USB Storage (VSN Correlated) |
| 5 | `COVER_UP_ANTI_FORENSICS` | **CONFIRMED** | 2026-11-18 07:31:16 | Evidence tampering and cleanup activities detected (file deletion, timestomping, or log clearing). |

---
### 3. Forensic Tampering & Anti-Forensic Anomalies (2)
#### ⚠️ [CRITICAL] Anti-Forensic Event Log Clearing (Security)
- **Explanation:** The Security event log was deliberately wiped by user 'gurpr' at 2026-11-18T07:31:16.858832+00:00. Windows Event ID: 1102/104.
- **Investigative Impact:** Historical audit records, logon session history, and process execution events prior to this timestamp were permanently erased, destroying evidence of pre-attack reconnaissance.
- **Action:** Examine Volume Shadow Copies (VSS) or SIEM forwarders for preserved pre-clear logs.

#### ⚠️ [MEDIUM] Evidence Gap: Removable Storage Object Auditing Disabled
- **Explanation:** Removable device connection was observed, but granular File Read/Write events on the removable drive (Event ID 4663) were not recorded by Windows Security Auditing.
- **Investigative Impact:** Exact byte-by-byte file copy actions must be proven through circumstantial correlation (Volume Serial Numbers in LNK files and temporal windowing) rather than direct transfer logs.
- **Action:** Enable 'Audit Removable Storage' in Group Policy Object (GPO) for enterprise hosts.

---
### 4. Non-Repudiation Chain of Custody & Live Telemetry Manifest
| Event ID | Timestamp (UTC) | Artifact Source | Fact Level | Summary |
| :--- | :--- | :--- | :--- | :--- |
| `SIM-LNK-15CBC7C8` | 07:31:09 | `LNK_SHORTCUT` | **DIRECT_OBSERVATION** | User accessed sensitive files via Explorer: C:\Confidential\Q4_Financial_Client_... |
| `SIM-PF-3CF983DD` | 07:31:12 | `PREFETCH` | **DIRECT_OBSERVATION** | 7Z.EXE executed from Prefetch, creating temporary container: C:\Users\user\AppDa... |
| `SIM-USB-69CDC13C` | 07:31:13 | `REGISTRY_USBSTOR` | **DIRECT_OBSERVATION** | USB Removable Storage connected: Kingston DataTraveler 3.0 (Serial: 00187D0F9A82... |
| `SIM-XFER-FA83B852` | 07:31:15 | `LNK_SHORTCUT` | **DIRECT_OBSERVATION** | [DATA THEFT] File copied to removable drive: E:\exfil_stage.zip (Size: 14.8 MB, ... |
| `SIM-CLEAR-BE6DEBBD` | 07:31:16 | `EVENT_LOG_SECURITY` | **DIRECT_OBSERVATION** | CRITICAL ANTI-FORENSICS: Security Audit Log was explicitly CLEARED by user Alex_... |