"""
Alert system for real-time security notifications.
Includes verification layer to prevent false alerts.
"""
import json
from typing import List, Optional
from datetime import datetime
from pathlib import Path
from .config import ALERT_LOG, CONFIDENCE_ALERT_THRESHOLD
from .models import Alert, ThreatLevel, Detection, BehaviorEvent, generate_id


class AlertSystem:
    def __init__(self):
        self.alerts: List[Alert] = []
        self.websocket_clients = []
        self._load_history()

    def _load_history(self):
        if ALERT_LOG.exists():
            try:
                with open(ALERT_LOG, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            data = json.loads(line)
                            self.alerts.append(Alert(**data))
            except Exception:
                pass

    def _persist(self, alert: Alert):
        ALERT_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(ALERT_LOG, "a", encoding="utf-8") as f:
            f.write(alert.model_dump_json() + "\n")

    def create_from_detection(self, detection: Detection) -> Optional[Alert]:
        """
        Create alert ONLY if detection passes strict verification:
        - Safe detections → no alert
        - Criminal alerts require confidence >= CONFIDENCE_ALERT_THRESHOLD (90%)
        - Criminal alerts require multi-frame verification (name starts with CONFIRMED)
        - Suspicious alerts require confidence >= 50%
        - 60-second deduplication window
        """
        # Rule 1: Safe → never alert
        if detection.threat_level == ThreatLevel.SAFE:
            return None

        # Rule 2: Criminal alerts — STRICT requirements
        if detection.threat_level == ThreatLevel.CRIMINAL:
            # Must be multi-frame verified (name will contain "CONFIRMED")
            if "CONFIRMED" not in detection.person_name:
                return None
            # Must have high confidence
            if detection.confidence < CONFIDENCE_ALERT_THRESHOLD:
                return None

        # Rule 3: Suspicious — moderate confidence requirement
        if detection.threat_level == ThreatLevel.SUSPICIOUS:
            if detection.confidence < 50.0:
                return None

        alert = Alert(
            id=generate_id(),
            alert_type="criminal_detected" if detection.threat_level == ThreatLevel.CRIMINAL else "suspicious_person",
            threat_level=detection.threat_level,
            person_name=detection.person_name,
            confidence=detection.confidence,
            distance=detection.distance,
            camera_id=detection.camera_id,
            camera_location=detection.camera_location,
            timestamp=datetime.now().isoformat(),
            details=f"{detection.threat_level.value} detected at {detection.camera_location} "
                    f"(confidence: {detection.confidence}%, distance: {detection.distance})"
        )

        # Rule 4: Extended dedup — don't alert same person within 60 seconds
        for existing in reversed(self.alerts[-30:]):
            if (existing.person_name == alert.person_name
                    and existing.camera_id == alert.camera_id):
                try:
                    t1 = datetime.fromisoformat(existing.timestamp)
                    t2 = datetime.fromisoformat(alert.timestamp)
                    if (t2 - t1).total_seconds() < 60:
                        return None
                except Exception:
                    pass

        self.alerts.append(alert)
        self._persist(alert)
        return alert

    def create_from_behavior(self, event: BehaviorEvent) -> Alert:
        alert = Alert(
            id=generate_id(),
            alert_type=f"behavior_{event.behavior_type}",
            threat_level=ThreatLevel.SUSPICIOUS,
            person_name=event.person_id,
            confidence=0,
            distance=0,
            camera_id=event.camera_id,
            camera_location=event.camera_location,
            timestamp=datetime.now().isoformat(),
            details=event.details
        )
        self.alerts.append(alert)
        self._persist(alert)
        return alert

    def acknowledge(self, alert_id: str) -> bool:
        for a in self.alerts:
            if a.id == alert_id:
                a.acknowledged = True
                return True
        return False

    def get_all(self, limit: int = 100) -> List[Alert]:
        return list(reversed(self.alerts[-limit:]))

    def get_unacknowledged(self) -> List[Alert]:
        return [a for a in self.alerts if not a.acknowledged]

    def get_stats(self) -> dict:
        total = len(self.alerts)
        unack = len([a for a in self.alerts if not a.acknowledged])
        by_type = {}
        for a in self.alerts:
            by_type[a.alert_type] = by_type.get(a.alert_type, 0) + 1
        return {"total": total, "unacknowledged": unack, "by_type": by_type}

    def clear_all(self):
        self.alerts.clear()
        if ALERT_LOG.exists():
            ALERT_LOG.unlink()
