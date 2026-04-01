"""
Pydantic data models for the Airport Security System.
"""
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum
import uuid


def generate_id() -> str:
    return str(uuid.uuid4())[:8]


class ThreatLevel(str, Enum):
    CRIMINAL = "Criminal"
    SUSPICIOUS = "Suspicious"
    SAFE = "Safe"


class CriminalRecord(BaseModel):
    id: str = Field(default_factory=generate_id)
    name: str
    crime: str
    case_id: str
    status: str = "Wanted"
    danger_level: str = "High"
    description: str = ""
    images: List[str] = []
    last_seen: Optional[str] = None
    added_at: str = Field(default_factory=lambda: datetime.now().isoformat())


class Detection(BaseModel):
    id: str = Field(default_factory=generate_id)
    person_name: str = "Unknown"
    threat_level: ThreatLevel = ThreatLevel.SAFE
    confidence: float = 0.0
    distance: float = 1.0
    camera_id: str = "CAM-001"
    camera_location: str = "Unknown"
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())
    facial_area: Dict[str, int] = {}
    criminal_id: Optional[str] = None


class Alert(BaseModel):
    id: str = Field(default_factory=generate_id)
    alert_type: str = "criminal_detected"
    threat_level: ThreatLevel = ThreatLevel.CRIMINAL
    person_name: str = "Unknown"
    confidence: float = 0.0
    distance: float = 1.0
    camera_id: str = "CAM-001"
    camera_location: str = "Unknown"
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())
    details: str = ""
    acknowledged: bool = False
    snapshot_base64: Optional[str] = None


class CameraConfig(BaseModel):
    camera_id: str
    location: str
    source: Any
    status: str = "active"


class BehaviorEvent(BaseModel):
    id: str = Field(default_factory=generate_id)
    person_id: str
    behavior_type: str
    camera_id: str
    camera_location: str = ""
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())
    details: str = ""
    position: Dict[str, int] = {}


class SystemStats(BaseModel):
    total_cameras: int = 0
    active_cameras: int = 0
    total_detections: int = 0
    total_alerts: int = 0
    unacknowledged_alerts: int = 0
    criminals_in_db: int = 0
    uptime_seconds: float = 0
    fps: float = 0.0


class AddCriminalRequest(BaseModel):
    name: str
    crime: str
    case_id: str
    status: str = "Wanted"
    danger_level: str = "High"
    description: str = ""
