"""
Multi-camera management with threaded capture and person tracking.
"""
import cv2
import time
import threading
import base64
import numpy as np
from typing import Dict, List, Optional, Tuple
from collections import defaultdict
from datetime import datetime
from .config import DEFAULT_CAMERAS, FRAME_WIDTH, FRAME_HEIGHT, PROCESS_EVERY_N_FRAMES


class CameraStream:
    def __init__(self, camera_id: str, source, location: str):
        self.camera_id = camera_id
        self.source = source
        self.location = location
        self.cap = None
        self.frame = None
        self.annotated_frame = None
        self.running = False
        self.thread = None
        self.lock = threading.Lock()
        self.frame_count = 0
        self.fps = 0.0
        self._last_fps_time = time.time()
        self._fps_counter = 0

    def start(self):
        if self.running:
            return
        self.cap = cv2.VideoCapture(self.source)
        if self.cap.isOpened():
            self.cap.set(cv2.CAP_PROP_FRAME_WIDTH, FRAME_WIDTH)
            self.cap.set(cv2.CAP_PROP_FRAME_HEIGHT, FRAME_HEIGHT)
            self.running = True
            self.thread = threading.Thread(target=self._capture_loop, daemon=True)
            self.thread.start()
            print(f"Camera {self.camera_id} ({self.location}) started")
        else:
            print(f"Failed to open camera {self.camera_id}")

    def _capture_loop(self):
        while self.running:
            ret, frame = self.cap.read()
            if ret:
                with self.lock:
                    self.frame = frame
                    self.frame_count += 1
                self._fps_counter += 1
                now = time.time()
                if now - self._last_fps_time >= 1.0:
                    self.fps = self._fps_counter / (now - self._last_fps_time)
                    self._fps_counter = 0
                    self._last_fps_time = now
            else:
                time.sleep(0.01)

    def get_frame(self) -> Optional[np.ndarray]:
        with self.lock:
            return self.frame.copy() if self.frame is not None else None

    def set_annotated(self, frame: np.ndarray):
        with self.lock:
            self.annotated_frame = frame

    def get_annotated(self) -> Optional[np.ndarray]:
        with self.lock:
            if self.annotated_frame is not None:
                return self.annotated_frame.copy()
            return self.frame.copy() if self.frame is not None else None

    def should_process(self) -> bool:
        return self.frame_count % PROCESS_EVERY_N_FRAMES == 0

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        if self.cap:
            self.cap.release()
        print(f"Camera {self.camera_id} stopped")

    @property
    def status(self) -> str:
        return "active" if self.running and self.cap and self.cap.isOpened() else "offline"


class CameraManager:
    def __init__(self):
        self.cameras: Dict[str, CameraStream] = {}
        self.person_tracks: Dict[str, List[Dict]] = defaultdict(list)

    def initialize(self):
        for cam_cfg in DEFAULT_CAMERAS:
            self.add_camera(cam_cfg["camera_id"], cam_cfg["source"], cam_cfg["location"])

    def add_camera(self, camera_id: str, source, location: str):
        if camera_id in self.cameras:
            self.cameras[camera_id].stop()
        stream = CameraStream(camera_id, source, location)
        stream.start()
        self.cameras[camera_id] = stream

    def remove_camera(self, camera_id: str):
        if camera_id in self.cameras:
            self.cameras[camera_id].stop()
            del self.cameras[camera_id]

    def get_camera(self, camera_id: str) -> Optional[CameraStream]:
        return self.cameras.get(camera_id)

    def get_all_cameras(self) -> List[Dict]:
        return [
            {"camera_id": c.camera_id, "location": c.location,
             "status": c.status, "fps": round(c.fps, 1)}
            for c in self.cameras.values()
        ]

    def record_person_movement(self, person_id: str, camera_id: str,
                                location: str, position: Tuple[int, int]):
        self.person_tracks[person_id].append({
            "camera_id": camera_id, "location": location,
            "position": {"x": position[0], "y": position[1]},
            "timestamp": datetime.now().isoformat()
        })
        if len(self.person_tracks[person_id]) > 100:
            self.person_tracks[person_id] = self.person_tracks[person_id][-100:]

    def get_person_history(self, person_id: str) -> List[Dict]:
        return self.person_tracks.get(person_id, [])

    def generate_mjpeg(self, camera_id: str):
        camera = self.cameras.get(camera_id)
        if not camera:
            return
        while camera.running:
            frame = camera.get_annotated()
            if frame is not None:
                _, buffer = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 80])
                yield (b'--frame\r\nContent-Type: image/jpeg\r\n\r\n'
                       + buffer.tobytes() + b'\r\n')
            time.sleep(0.033)

    def get_snapshot_base64(self, camera_id: str) -> Optional[str]:
        camera = self.cameras.get(camera_id)
        if not camera:
            return None
        frame = camera.get_annotated()
        if frame is not None:
            _, buf = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 70])
            return base64.b64encode(buf.tobytes()).decode()
        return None

    def stop_all(self):
        for cam in self.cameras.values():
            cam.stop()

    @property
    def active_count(self) -> int:
        return sum(1 for c in self.cameras.values() if c.status == "active")
