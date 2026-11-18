# REAL-TIME FORENSIC INCIDENT INVESTIGATION REPORT
## Windows Removable Device Artifact Analysis & Insider Data Theft
**Generated:** 2026-11-18 08:16:14 UTC  
**Case Number:** `INC-REALTIME-001`  
**Subject of Investigation:** `gurpr`  
**Threat Confidence:** **VERY_HIGH** (95.0%)  
**Monitoring Mode:** Active Real-Time CLI Watcher  

---
### 1. Removable Device (Pendrive / USB) Exfiltration Dossier
| Drive Letter | Volume Label | Volume Serial (VSN) | File System | Hardware Serial | Vendor / Product |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `F:` | **Removable Disk** | `9A7652BB` | FAT32 | `N/A` | USB Storage |

#### Captured Exfiltrated Files on Removable Device:

| File Name | Size (Bytes) | Transferred (UTC) | Removable Drive | SHA-256 Hash | Type |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `implementa1ion_plan.md` | 8,057 | 07:09:04 | `F:` (VSN: 9A7652BB) | `ce685894b5991cb231fe...` | **Sensitive Data** |

---
### 2. Reconstructed Incident Sequence (5-Stage Attack Lifecycle)
| Step | Stage | Verification Status | Timestamp (UTC) | Description |
| :--- | :--- | :--- | :--- | :--- |
| 1 | `RECONNAISSANCE` | **CONFIRMED** | 2026-11-18 08:16:13 | Insider accessed or browsed 26 sensitive file(s) via Explorer/LNK/JumpLists. |
| 2 | `DATA_TRANSFER` | **CONFIRMED** | 2026-11-18 07:09:04 | Data exfiltration via Removable USB Storage (VSN Correlated) |

---
### 3. Forensic Tampering & Anti-Forensic Anomalies (0)
---
### 4. Non-Repudiation Chain of Custody & Live Telemetry Manifest
| Event ID | Timestamp (UTC) | Artifact Source | Fact Level | Summary |
| :--- | :--- | :--- | :--- | :--- |
| `RT-FILE-35DA6EF1` | 07:09:04 | `LNK_SHORTCUT` | **DIRECT_OBSERVATION** | [FILE COPY] File transferred to removable drive: implementa1ion_plan.md (Path: F... |
| `EVT-FC987D09DE` | 08:16:13 | `JUMP_LIST` | **DIRECT_OBSERVATION** | File opened/shortcut referenced via LNK: C:\Users\gurpr\OneDrive\Desktop (VSN: B... |
| `EVT-D040ACC641` | 08:16:13 | `JUMP_LIST` | **DIRECT_OBSERVATION** | File opened/shortcut referenced via LNK: C:\Users\gurpr\Downloads (VSN: B224CD66... |
| `EVT-ED5181E798` | 08:16:13 | `JUMP_LIST` | **DIRECT_OBSERVATION** | File opened/shortcut referenced via LNK: C:\Users\gurpr\OneDrive\Documents (VSN:... |
| `EVT-7FF7B405D1` | 08:16:13 | `JUMP_LIST` | **DIRECT_OBSERVATION** | File opened/shortcut referenced via LNK: C:4 (VSN: B224CD66, DriveType: Fixed)... |
| `EVT-F4DA0C0381` | 08:16:13 | `JUMP_LIST` | **DIRECT_OBSERVATION** | File opened/shortcut referenced via LNK: C:\Users\gurpr\Music (VSN: B224CD66, Dr... |
| `EVT-9C7E3FCD32` | 08:16:13 | `JUMP_LIST` | **DIRECT_OBSERVATION** | File opened/shortcut referenced via LNK: C:\Users\gurpr\Videos (VSN: B224CD66, D... |
| `EVT-5D69EA60BC` | 08:16:13 | `JUMP_LIST` | **DIRECT_OBSERVATION** | File opened/shortcut referenced via LNK: D:\SEM II\web tech\labs folders (VSN: 3... |
| `EVT-EFBB3B1289` | 08:16:13 | `JUMP_LIST` | **DIRECT_OBSERVATION** | File opened/shortcut referenced via LNK: D:\SEM III\Design Patterns\CODE (VSN: 3... |
| `EVT-D04A57A20A` | 08:16:13 | `JUMP_LIST` | **DIRECT_OBSERVATION** | File opened/shortcut referenced via LNK: D:\ (VSN: 30E8E458, DriveType: Fixed)... |
| `EVT-246AB7F0BE` | 08:16:13 | `JUMP_LIST` | **DIRECT_OBSERVATION** | File opened/shortcut referenced via LNK: D:\SEM II\web tech\experiments (VSN: 30... |
| `EVT-E81B63807E` | 08:16:13 | `JUMP_LIST` | **DIRECT_OBSERVATION** | File opened/shortcut referenced via LNK: D:\SEM II\web tech\APPS (VSN: 30E8E458,... |
| `EVT-E619567A01` | 08:16:13 | `JUMP_LIST` | **DIRECT_OBSERVATION** | File opened/shortcut referenced via LNK: C:\Users\gurpr\Downloads\metasploitable... |
| `EVT-F10792BFDD` | 08:16:13 | `JUMP_LIST` | **DIRECT_OBSERVATION** | File opened/shortcut referenced via LNK: C:\windows\System32 (VSN: B224CD66, Dri... |
| `EVT-E84AD6A412` | 08:16:13 | `JUMP_LIST` | **DIRECT_OBSERVATION** | File opened/shortcut referenced via LNK: D:\New (VSN: 30E8E458, DriveType: Fixed... |
| `EVT-10EB79FC84` | 08:16:13 | `JUMP_LIST` | **DIRECT_OBSERVATION** | File opened/shortcut referenced via LNK: E:\ENTERTAINMENT (VSN: 68987622, DriveT... |
| `EVT-CA29DB2ED3` | 08:16:13 | `JUMP_LIST` | **DIRECT_OBSERVATION** | File opened/shortcut referenced via LNK: D:\SEM III\Advanced DF (VSN: 30E8E458, ... |
| `EVT-A6A1AAC15F` | 08:16:13 | `JUMP_LIST` | **DIRECT_OBSERVATION** | File opened/shortcut referenced via LNK: D:\MINOR PROJECT (VSN: 30E8E458, DriveT... |
| `EVT-E2F95F923F` | 08:16:13 | `JUMP_LIST` | **DIRECT_OBSERVATION** | File opened/shortcut referenced via LNK: D:\MINOR PROJECT\SELF PROGRESS (VSN: 30... |
| `EVT-E20AADE2A2` | 08:16:13 | `JUMP_LIST` | **DIRECT_OBSERVATION** | File opened/shortcut referenced via LNK: C:\Users\gurpr\Downloads\ARTIFEL (VSN: ... |
| `EVT-1ACD24752F` | 08:16:13 | `JUMP_LIST` | **DIRECT_OBSERVATION** | File opened/shortcut referenced via LNK: C:\windows\System32\DriverStore\FileRep... |
| `EVT-28A1CA1646` | 08:16:13 | `JUMP_LIST` | **DIRECT_OBSERVATION** | File opened/shortcut referenced via LNK: e (VSN: 30E8E458, DriveType: Fixed)... |
| `EVT-01BCB86675` | 08:16:13 | `JUMP_LIST` | **DIRECT_OBSERVATION** | File opened/shortcut referenced via LNK: D:\SEM III (VSN: 30E8E458, DriveType: F... |
| `EVT-F64450BECC` | 08:16:13 | `JUMP_LIST` | **DIRECT_OBSERVATION** | File opened/shortcut referenced via LNK: D:\Placement PREP material (VSN: 30E8E4... |
| `EVT-7CB2F007DB` | 08:16:13 | `JUMP_LIST` | **DIRECT_OBSERVATION** | File opened/shortcut referenced via LNK: C:\Program Files\Git (VSN: B224CD66, Dr... |
| `EVT-64442B4AF7` | 08:16:13 | `JUMP_LIST` | **DIRECT_OBSERVATION** | File opened/shortcut referenced via LNK: C:\Users\gurpr\Downloads\ARTIFEX_17nov\... |
| `EVT-883772ACE6` | 08:16:13 | `JUMP_LIST` | **DIRECT_OBSERVATION** | File opened/shortcut referenced via LNK: E:\ (VSN: 68987622, DriveType: Fixed)... |