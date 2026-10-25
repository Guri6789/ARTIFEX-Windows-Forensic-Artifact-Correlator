"""Core forensic data models and domain abstractions.

Defines standardized data classes for multi-artifact normalization,
fact levels (direct observation vs inferred relationship), provenance references,
and incident reconstruction structures.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


class FactLevel(str, enum.Enum):
    """Distinguishes directly observed physical evidence from analytical inferences."""
    DIRECT_OBSERVATION = "DIRECT_OBSERVATION"
    INFERRED_RELATIONSHIP = "INFERRED_RELATIONSHIP"


class ConfidenceRating(str, enum.Enum):
    """Categorical confidence rating based on source reliability and corroboration."""
    VERY_HIGH = "VERY_HIGH"   # Multiple independent immutable sources (e.g. EVTX + USN + LNK)
    HIGH = "HIGH"             # Two independent sources or one highly reliable cryptographic record
    MEDIUM = "MEDIUM"         # Single source without contradiction, or inferred with strong temporal proximity
    LOW = "LOW"               # Single weakly protected source (e.g. user-modifiable timestamp)
    TENTATIVE = "TENTATIVE"   # Hypothesis with gaps or uncorroborated inference


class ArtifactType(str, enum.Enum):
    """Known Windows forensic artifact sources."""
    REGISTRY_USBSTOR = "REGISTRY_USBSTOR"
    REGISTRY_MOUNTED_DEVICES = "REGISTRY_MOUNTED_DEVICES"
    REGISTRY_USER_ASSIST = "REGISTRY_USER_ASSIST"
    REGISTRY_SHELLBAGS = "REGISTRY_SHELLBAGS"
    EVENT_LOG_DRIVER_FRAMEWORKS = "EVENT_LOG_DRIVER_FRAMEWORKS"
    EVENT_LOG_SECURITY = "EVENT_LOG_SECURITY"
    EVENT_LOG_SYSTEM = "EVENT_LOG_SYSTEM"
    EVENT_LOG_POWERSHELL = "EVENT_LOG_POWERSHELL"
    PREFETCH = "PREFETCH"
    LNK_SHORTCUT = "LNK_SHORTCUT"
    JUMP_LIST = "JUMP_LIST"
    NTFS_MFT = "NTFS_MFT"
    NTFS_USN_JOURNAL = "NTFS_USN_JOURNAL"
    BROWSER_SQLITE = "BROWSER_SQLITE"


class EventCategory(str, enum.Enum):
    """Categorization of insider threat actions."""
    RECON_ACCESS = "RECON_ACCESS"                   # Browsing sensitive directories, Shellbags
    FILE_STAGING = "FILE_STAGING"                   # Creating archives (.zip, .7z, .tar)
    PROCESS_EXECUTION = "PROCESS_EXECUTION"         # 7z, WinRAR, rclone, powershell execution
    USB_ATTACH = "USB_ATTACH"                       # Removable drive plugged in
    USB_DETACH = "USB_DETACH"                       # Removable drive removed
    FILE_TRANSFER_USB = "FILE_TRANSFER_USB"         # File copied/saved to removable volume
    CLOUD_UPLOAD = "CLOUD_UPLOAD"                   # Web browser POST/upload to cloud service
    FILE_DELETION = "FILE_DELETION"                 # Shift+Delete, USN delete record, ghost archive
    LOG_CLEARED = "LOG_CLEARED"                     # Anti-forensics: Security 1102 / System 104
    TIMESTOMP_DETECTED = "TIMESTOMP_DETECTED"       # Anti-forensics: SI vs FN discrepancy
    SUSPICIOUS_COMMAND = "SUSPICIOUS_COMMAND"       # CLI copy, certutil, bitsadmin


class IncidentStage(str, enum.Enum):
    """Stages of an insider data theft lifecycle."""
    RECONNAISSANCE = "RECONNAISSANCE"
    FILE_STAGING = "FILE_STAGING"
    DEVICE_PREPARATION = "DEVICE_PREPARATION"
    DATA_TRANSFER = "DATA_TRANSFER"
    COVER_UP_ANTI_FORENSICS = "COVER_UP_ANTI_FORENSICS"


class StepStatus(str, enum.Enum):
    """Verification status of a reconstructed incident step."""
    CONFIRMED = "CONFIRMED"           # Backed by direct multi-source forensic evidence
    UNCONFIRMED = "UNCONFIRMED"       # Logical step in chain but missing direct record
    CONTRADICTED = "CONTRADICTED"     # Evidence explicitly contradicts this action


class AnomalySeverity(str, enum.Enum):
    """Severity classification for forensic inconsistencies and anti-forensics."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class ForensicEvent:
    """Normalized forensic event extracted from any Windows artifact."""
    event_id: str
    timestamp: datetime
    artifact_type: ArtifactType
    category: EventCategory
    fact_level: FactLevel
    summary: str

    # Identity and context
    user: Optional[str] = None
    process_name: Optional[str] = None
    command_line: Optional[str] = None

    # File and path details
    source_file_path: Optional[str] = None
    target_file_path: Optional[str] = None
    file_size_bytes: Optional[int] = None

    # Hardware and volume details
    volume_serial: Optional[str] = None
    drive_letter: Optional[str] = None
    usb_serial: Optional[str] = None
    usb_vendor: Optional[str] = None
    usb_product: Optional[str] = None

    # Provenance tracking
    evidence_id: str = "UNKNOWN_EVIDENCE"
    record_id: Optional[str] = None
    byte_offset: Optional[int] = None
    raw_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dictionary."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "artifact_type": self.artifact_type.value,
            "category": self.category.value,
            "fact_level": self.fact_level.value,
            "summary": self.summary,
            "user": self.user,
            "process_name": self.process_name,
            "command_line": self.command_line,
            "source_file_path": self.source_file_path,
            "target_file_path": self.target_file_path,
            "file_size_bytes": self.file_size_bytes,
            "volume_serial": self.volume_serial,
            "drive_letter": self.drive_letter,
            "usb_serial": self.usb_serial,
            "usb_vendor": self.usb_vendor,
            "usb_product": self.usb_product,
            "evidence_id": self.evidence_id,
            "record_id": self.record_id,
            "byte_offset": self.byte_offset,
            "raw_metadata": self.raw_metadata,
        }


@dataclass
class IncidentStep:
    """A specific chronological step in a reconstructed data-theft sequence."""
    step_number: int
    stage: IncidentStage
    status: StepStatus
    description: str
    timestamp: Optional[datetime] = None
    supporting_events: List[ForensicEvent] = field(default_factory=list)
    unconfirmed_notes: Optional[str] = None
    confidence_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_number": self.step_number,
            "stage": self.stage.value,
            "status": self.status.value,
            "description": self.description,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "supporting_events_count": len(self.supporting_events),
            "supporting_event_ids": [e.event_id for e in self.supporting_events],
            "unconfirmed_notes": self.unconfirmed_notes,
            "confidence_score": round(self.confidence_score, 2),
        }


@dataclass
class ForensicAnomaly:
    """An inconsistency, evidence gap, or detected anti-forensic action."""
    anomaly_id: str
    anomaly_type: str
    severity: AnomalySeverity
    title: str
    explanation: str
    investigative_impact: str
    affected_artifacts: List[ArtifactType]
    supporting_events: List[ForensicEvent] = field(default_factory=list)
    recommended_action: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "anomaly_id": self.anomaly_id,
            "anomaly_type": self.anomaly_type,
            "severity": self.severity.value,
            "title": self.title,
            "explanation": self.explanation,
            "investigative_impact": self.investigative_impact,
            "affected_artifacts": [a.value for a in self.affected_artifacts],
            "supporting_event_ids": [e.event_id for e in self.supporting_events],
            "recommended_action": self.recommended_action,
        }


@dataclass
class ConfidenceExplanation:
    """Detailed explainable assessment of finding confidence."""
    score: float  # 0.0 to 1.0
    rating: ConfidenceRating
    triggered_rules: List[str]
    corroborating_sources: List[str]
    alternative_explanations: List[str]
    missing_evidence_gaps: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": round(self.score, 2),
            "rating": self.rating.value,
            "triggered_rules": self.triggered_rules,
            "corroborating_sources": self.corroborating_sources,
            "alternative_explanations": self.alternative_explanations,
            "missing_evidence_gaps": self.missing_evidence_gaps,
        }


@dataclass
class IncidentHypothesis:
    """The master reconstructed data theft narrative with confidence and gaps."""
    hypothesis_id: str
    title: str
    subject_user: Optional[str]
    time_window_start: datetime
    time_window_end: datetime
    target_files: List[str]
    staging_containers: List[str]
    destination_devices: List[str]
    steps: List[IncidentStep]
    anomalies: List[ForensicAnomaly]
    confidence: ConfidenceExplanation

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "title": self.title,
            "subject_user": self.subject_user,
            "time_window_start": self.time_window_start.isoformat(),
            "time_window_end": self.time_window_end.isoformat(),
            "target_files": self.target_files,
            "staging_containers": self.staging_containers,
            "destination_devices": self.destination_devices,
            "steps": [s.to_dict() for s in self.steps],
            "anomalies": [a.to_dict() for a in self.anomalies],
            "confidence": self.confidence.to_dict(),
        }
