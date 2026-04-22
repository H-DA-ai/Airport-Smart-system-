"""
Alert system — only generates alerts for confirmed CRIMINAL detections.
No suspicious alerts. Includes police dispatch, evidence attachment,
and strict deduplication (max 2 evidence photos, 60s dedup window).
"""
import json
import time
from typing import List, Optional, Dict
from datetime import datetime
from pathlib import Path
from .config import ALERT_LOG, POLICE_LOG, CONFIDENCE_ALERT_THRESHOLD, \
    ALERT_DEDUP_SECONDS, POLICE_ALERT_COOLDOWN
from .models import Alert, ThreatLevel, Detection, PoliceDispatch, generate_id


class AlertSystem:
    def __init__(self):
        self.alerts: List[Alert] = []
        self._police_last_sent: Dict[str, float] = {}  # criminal_id → timestamp
        self._load_history()

    def _load_history(self):
        if ALERT_LOG.exists():
            try:
                with open(ALERT_LOG, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            data = json.loads(line)
                            # Handle legacy alerts that may have old threat levels
                            if data.get("threat_level") == "Suspicious":
                                data["threat_level"] = "Safe"
                            try:
                                self.alerts.append(Alert(**data))
                            except Exception:
                                pass
            except Exception:
                pass

    def _persist(self, alert: Alert):
        ALERT_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(ALERT_LOG, "a", encoding="utf-8") as f:
            f.write(alert.model_dump_json() + "\n")

    def _persist_police(self, dispatch: PoliceDispatch):
        POLICE_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(POLICE_LOG, "a", encoding="utf-8") as f:
            f.write(dispatch.model_dump_json() + "\n")

    def create_from_detection(self, detection: Detection,
                               evidence_images: List[str] = None) -> Optional[Alert]:
        """
        Create alert ONLY for confirmed CRIMINAL detections.
        - Must be verified (person_name contains "CONFIRMED")
        - Must meet confidence threshold
        - 60-second deduplication window per criminal per camera
        - Max 2 evidence images attached
        """
        # Only act on CRIMINAL detections
        if detection.threat_level != ThreatLevel.CRIMINAL:
            return None

        # Must be multi-frame verified
        if "CONFIRMED" not in detection.person_name:
            return None

        # Must have sufficient confidence
        if detection.confidence < CONFIDENCE_ALERT_THRESHOLD:
            return None

        # Deduplication: don't re-alert same criminal within 60 seconds
        for existing in reversed(self.alerts[-50:]):
            if (existing.criminal_id == detection.criminal_id
                    and existing.camera_id == detection.camera_id):
                try:
                    t1 = datetime.fromisoformat(existing.timestamp)
                    t2 = datetime.now()
                    if (t2 - t1).total_seconds() < ALERT_DEDUP_SECONDS:
                        return None
                except Exception:
                    pass

        alert = Alert(
            id=generate_id(),
            alert_type="criminal_detected",
            threat_level=ThreatLevel.CRIMINAL,
            person_name=detection.person_name,
            confidence=detection.confidence,
            distance=detection.distance,
            camera_id=detection.camera_id,
            camera_location=detection.camera_location,
            timestamp=datetime.now().isoformat(),
            details=f"Criminal detected at {detection.camera_location} "
                    f"(confidence: {detection.confidence}%, "
                    f"cam: {detection.camera_id})",
            criminal_id=detection.criminal_id,
            evidence_images=evidence_images or [],
            police_alerted=False
        )

        self.alerts.append(alert)
        self._persist(alert)
        return alert

    def send_police_alert(self, alert: Alert) -> Optional[PoliceDispatch]:
        """
        Send police dispatch for a criminal alert.
        Enforces POLICE_ALERT_COOLDOWN per criminal to avoid spam.
        Returns the dispatch record, or None if cooldown active.
        """
        criminal_id = alert.criminal_id or alert.person_name
        now = time.time()

        # Check police cooldown
        last_sent = self._police_last_sent.get(criminal_id, 0)
        if now - last_sent < POLICE_ALERT_COOLDOWN:
            return None

        self._police_last_sent[criminal_id] = now

        dispatch = PoliceDispatch(
            id=generate_id(),
            alert_id=alert.id,
            criminal_name=alert.person_name.replace("CONFIRMED: ", ""),
            criminal_id=alert.criminal_id,
            camera_id=alert.camera_id,
            camera_location=alert.camera_location,
            confidence=alert.confidence,
            timestamp=datetime.now().isoformat(),
            action="LOCKDOWN_INITIATED",
            gates_locked=["Gate A", "Gate B", "Gate C", "Terminal Exit"]
        )

        # Mark alert as police-alerted
        alert.police_alerted = True
        self._persist_police(dispatch)
        return dispatch

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

    def get_police_dispatches(self, limit: int = 50) -> List[Dict]:
        dispatches = []
        if POLICE_LOG.exists():
            try:
                with open(POLICE_LOG, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            dispatches.append(json.loads(line))
            except Exception:
                pass
        return list(reversed(dispatches[-limit:]))

    def clear_all(self):
        self.alerts.clear()
        if ALERT_LOG.exists():
            ALERT_LOG.unlink()
