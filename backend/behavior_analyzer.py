"""
Behavior analysis for anomaly detection.
Detects loitering, running, and restricted area entry.
"""
import time
import math
from typing import Dict, List, Tuple
from collections import defaultdict
from .config import (
    LOITER_TIME_SECONDS, LOITER_RADIUS_PIXELS,
    RUNNING_SPEED_THRESHOLD, RESTRICTED_AREAS
)
from .models import BehaviorEvent, generate_id


class PersonTracker:
    def __init__(self, person_id: str, pos: Tuple[int, int]):
        self.person_id = person_id
        self.positions = [(pos[0], pos[1], time.time())]
        self.first_seen = time.time()
        self.last_seen = time.time()
        self.is_active = True

    def update(self, pos: Tuple[int, int]):
        self.positions.append((pos[0], pos[1], time.time()))
        self.last_seen = time.time()
        if len(self.positions) > 300:
            self.positions = self.positions[-300:]

    def get_speed(self, window: float = 1.5) -> float:
        now = time.time()
        recent = [(x, y, t) for x, y, t in self.positions if now - t <= window]
        if len(recent) < 2:
            return 0.0
        total = sum(
            math.sqrt((recent[i][0]-recent[i-1][0])**2 + (recent[i][1]-recent[i-1][1])**2)
            for i in range(1, len(recent))
        )
        elapsed = recent[-1][2] - recent[0][2]
        return total / elapsed if elapsed > 0 else 0.0

    def get_displacement(self) -> float:
        if len(self.positions) < 2:
            return 0.0
        s, e = self.positions[0], self.positions[-1]
        return math.sqrt((e[0]-s[0])**2 + (e[1]-s[1])**2)

    def get_dwell_time(self) -> float:
        return time.time() - self.first_seen

    def get_centroid(self) -> Tuple[int, int]:
        if self.positions:
            return (self.positions[-1][0], self.positions[-1][1])
        return (0, 0)


class BehaviorAnalyzer:
    def __init__(self):
        self.trackers: Dict[str, PersonTracker] = {}
        self.events: List[BehaviorEvent] = []
        self._loiter_alerted: set = set()
        self._restricted_alerted: set = set()
        self.restricted_areas = RESTRICTED_AREAS

    def update_person(self, person_id: str, centroid: Tuple[int, int]):
        if person_id in self.trackers:
            self.trackers[person_id].update(centroid)
        else:
            self.trackers[person_id] = PersonTracker(person_id, centroid)

    def analyze(self, camera_id: str = "CAM-001", camera_location: str = "") -> List[BehaviorEvent]:
        new_events = []
        now = time.time()

        stale = [p for p, t in self.trackers.items() if now - t.last_seen > 10]
        for p in stale:
            self._loiter_alerted.discard(p)
            self._restricted_alerted.discard(p)
            del self.trackers[p]

        for pid, tracker in self.trackers.items():
            if not tracker.is_active:
                continue

            # Loitering detection
            if pid not in self._loiter_alerted:
                if (tracker.get_dwell_time() > LOITER_TIME_SECONDS
                        and tracker.get_displacement() < LOITER_RADIUS_PIXELS):
                    cx, cy = tracker.get_centroid()
                    new_events.append(BehaviorEvent(
                        person_id=pid, behavior_type="loitering",
                        camera_id=camera_id, camera_location=camera_location,
                        details=f"Loitering {tracker.get_dwell_time():.0f}s",
                        position={"x": cx, "y": cy}
                    ))
                    self._loiter_alerted.add(pid)

            # Running detection
            speed = tracker.get_speed()
            if speed > RUNNING_SPEED_THRESHOLD:
                cx, cy = tracker.get_centroid()
                new_events.append(BehaviorEvent(
                    person_id=pid, behavior_type="running",
                    camera_id=camera_id, camera_location=camera_location,
                    details=f"Running at {speed:.0f} px/s",
                    position={"x": cx, "y": cy}
                ))

            # Restricted area detection
            if pid not in self._restricted_alerted:
                cx, cy = tracker.get_centroid()
                for area in self.restricted_areas:
                    if (area["x1"] <= cx <= area["x2"]
                            and area["y1"] <= cy <= area["y2"]
                            and area.get("camera_id", camera_id) == camera_id):
                        new_events.append(BehaviorEvent(
                            person_id=pid, behavior_type="restricted_area",
                            camera_id=camera_id, camera_location=camera_location,
                            details=f"Entered: {area.get('name', 'Restricted Zone')}",
                            position={"x": cx, "y": cy}
                        ))
                        self._restricted_alerted.add(pid)
                        break

        self.events.extend(new_events)
        return new_events

    def get_all_events(self) -> List[BehaviorEvent]:
        return self.events

    def get_active_count(self) -> int:
        return len(self.trackers)
