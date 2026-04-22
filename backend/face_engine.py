"""
Face detection and recognition engine.
Binary classification only: CRIMINAL or SAFE.
- Safe faces: blurred on live video feed (privacy protection)
- Criminal faces: clear, red bounding box, triggers alert + evidence capture
"""
import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

import numpy as np
import cv2
import time
import base64
from typing import List, Dict, Tuple, Optional
from collections import defaultdict, deque
from datetime import datetime
from .config import (
    FACE_DETECTION_BACKEND, FACE_RECOGNITION_MODEL,
    CRIMINAL_THRESHOLD, IMAGES_DIR, EMBEDDINGS_DIR, EVIDENCE_DIR,
    VERIFICATION_FRAME_COUNT, VERIFICATION_MIN_MATCHES,
    CONFIDENCE_ALERT_THRESHOLD, TOP_K_MATCHES, TOP_K_MARGIN,
    FACE_MIN_SIZE, MAX_EVIDENCE_SNAPSHOTS
)
from .models import Detection, ThreatLevel, generate_id


class MultiFrameVerifier:
    """
    Tracks face match results across multiple frames to prevent
    single-frame false positives. A face is confirmed as CRIMINAL
    only when it matches consistently across VERIFICATION_MIN_MATCHES
    out of VERIFICATION_FRAME_COUNT consecutive frames.
    Everything else is SAFE.
    """

    def __init__(self):
        self.tracks: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=VERIFICATION_FRAME_COUNT)
        )
        self.track_positions: Dict[str, Tuple[int, int]] = {}
        self.track_last_seen: Dict[str, float] = {}

    def get_track_id(self, cx: int, cy: int) -> str:
        best_id = None
        best_dist = float('inf')
        now = time.time()

        # Clean stale tracks (not seen in 5 seconds)
        stale = [k for k, t in self.track_last_seen.items() if now - t > 5.0]
        for k in stale:
            self.tracks.pop(k, None)
            self.track_positions.pop(k, None)
            self.track_last_seen.pop(k, None)

        for tid, (tx, ty) in self.track_positions.items():
            dist = ((cx - tx) ** 2 + (cy - ty) ** 2) ** 0.5
            if dist < 120 and dist < best_dist:
                best_dist = dist
                best_id = tid

        if best_id is None:
            best_id = f"face_{generate_id()}"

        self.track_positions[best_id] = (cx, cy)
        self.track_last_seen[best_id] = now
        return best_id

    def add_result(self, track_id: str, match_id: Optional[str],
                   distance: float, confidence: float):
        self.tracks[track_id].append({
            "match_id": match_id,
            "distance": distance,
            "confidence": confidence,
            "time": time.time()
        })

    def get_verified_result(self, track_id: str) -> Dict:
        """
        Analyze frame history. Returns CRIMINAL only if:
        - Matched in >= VERIFICATION_MIN_MATCHES frames
        - Average confidence >= CONFIDENCE_ALERT_THRESHOLD
        Otherwise returns SAFE.
        """
        history = self.tracks.get(track_id, deque())

        if len(history) < 2:
            return {
                "verified": False,
                "threat_level": ThreatLevel.SAFE,
                "person_name": "Scanning...",
                "confidence": 0.0,
                "match_count": 0,
                "total_frames": len(history),
                "reason": "Insufficient frames"
            }

        match_counts: Dict[str, List[Dict]] = defaultdict(list)

        for entry in history:
            mid = entry["match_id"]
            if mid is not None:
                match_counts[mid].append(entry)

        total_frames = len(history)

        if not match_counts:
            return {
                "verified": True,
                "threat_level": ThreatLevel.SAFE,
                "person_name": "Passenger",
                "confidence": 0.0,
                "match_count": 0,
                "total_frames": total_frames,
                "reason": "No database match"
            }

        best_crim_id = max(match_counts, key=lambda k: len(match_counts[k]))
        best_entries = match_counts[best_crim_id]
        match_count = len(best_entries)
        avg_confidence = sum(e["confidence"] for e in best_entries) / len(best_entries)
        avg_distance = sum(e["distance"] for e in best_entries) / len(best_entries)

        has_enough_matches = match_count >= VERIFICATION_MIN_MATCHES
        high_enough_confidence = avg_confidence >= CONFIDENCE_ALERT_THRESHOLD
        close_enough = avg_distance < CRIMINAL_THRESHOLD

        if has_enough_matches and high_enough_confidence and close_enough:
            return {
                "verified": True,
                "threat_level": ThreatLevel.CRIMINAL,
                "criminal_id": best_crim_id,
                "confidence": round(avg_confidence, 1),
                "avg_distance": round(avg_distance, 4),
                "match_count": match_count,
                "total_frames": total_frames,
                "reason": f"CONFIRMED: {match_count}/{total_frames} frames, "
                          f"conf={avg_confidence:.1f}%, dist={avg_distance:.3f}"
            }
        else:
            return {
                "verified": True,
                "threat_level": ThreatLevel.SAFE,
                "person_name": "Passenger",
                "confidence": round(avg_confidence, 1) if best_entries else 0.0,
                "match_count": match_count,
                "total_frames": total_frames,
                "reason": f"Safe: {match_count}/{total_frames} matched "
                          f"(need {VERIFICATION_MIN_MATCHES}), conf={avg_confidence:.1f}%"
            }


class FaceEngine:
    """
    Face detection and recognition engine.
    - Safe passengers: blurred faces on video
    - Criminals: clear face, red box, evidence captured
    """

    def __init__(self):
        self.model_name = FACE_RECOGNITION_MODEL
        self.detector_backend = FACE_DETECTION_BACKEND
        self.criminal_embeddings: Dict[str, Dict] = {}
        self.model_loaded = False
        self._fps = 0.0
        self._process_time = 0.0
        self.verifier = MultiFrameVerifier()
        self._debug_info: List[Dict] = []
        # Track evidence snapshot count per criminal_id
        self.evidence_counts: Dict[str, int] = defaultdict(int)

    def initialize(self):
        try:
            from deepface import DeepFace
            dummy = np.zeros((160, 160, 3), dtype=np.uint8)
            dummy[50:110, 50:110] = 200
            DeepFace.represent(
                img_path=dummy,
                model_name=self.model_name,
                detector_backend="skip",
                enforce_detection=False
            )
            self.model_loaded = True
            print(f"Face model '{self.model_name}' loaded")
        except Exception as e:
            print(f"Model warm-up note: {e}")
            self.model_loaded = True

    def precompute_embeddings(self, criminals: List[Dict]):
        from deepface import DeepFace
        print("Computing criminal face embeddings...")
        count = 0
        for criminal in criminals:
            crim_id = criminal.get("id", criminal.get("name", "unknown"))
            embeddings = []

            cache_path = EMBEDDINGS_DIR / f"{crim_id}.npy"
            if cache_path.exists():
                try:
                    cached = np.load(str(cache_path), allow_pickle=True)
                    embeddings = list(cached)
                except Exception:
                    pass

            if not embeddings:
                for img_name in criminal.get("images", []):
                    img_path = IMAGES_DIR / img_name
                    if not img_path.exists():
                        continue
                    try:
                        results = DeepFace.represent(
                            img_path=str(img_path),
                            model_name=self.model_name,
                            detector_backend=self.detector_backend,
                            enforce_detection=False
                        )
                        for face_data in results:
                            embeddings.append(np.array(face_data["embedding"]))
                            count += 1
                    except Exception as e:
                        print(f"  Error processing {img_name}: {e}")

                if embeddings:
                    try:
                        np.save(str(cache_path), np.array(embeddings))
                    except Exception:
                        pass

            if embeddings:
                self.criminal_embeddings[crim_id] = {
                    "embeddings": embeddings,
                    "name": criminal["name"],
                    "crime": criminal.get("crime", "Unknown"),
                    "case_id": criminal.get("case_id", ""),
                    "status": criminal.get("status", "Wanted"),
                    "danger_level": criminal.get("danger_level", "High"),
                    "id": crim_id
                }
        print(f"Loaded {count} embeddings for {len(self.criminal_embeddings)} criminals")

    def reload_embeddings(self, criminals: List[Dict]):
        self.criminal_embeddings.clear()
        self.evidence_counts.clear()
        for f in EMBEDDINGS_DIR.glob("*.npy"):
            try:
                f.unlink()
            except Exception:
                pass
        self.precompute_embeddings(criminals)

    def _get_top_k_matches(self, embedding: np.ndarray) -> List[Dict]:
        all_matches = []
        for crim_id, crim_data in self.criminal_embeddings.items():
            best_dist = float('inf')
            for crim_emb in crim_data["embeddings"]:
                dist = self._cosine_distance(embedding, crim_emb)
                if dist < best_dist:
                    best_dist = dist

            all_matches.append({
                "criminal_id": crim_id,
                "name": crim_data["name"],
                "crime": crim_data["crime"],
                "distance": best_dist,
                "confidence": round(max(0.0, min(1.0, 1.0 - best_dist)) * 100, 1)
            })

        all_matches.sort(key=lambda x: x["distance"])
        return all_matches[:TOP_K_MATCHES]

    def _classify_single_frame(self, top_matches: List[Dict]) -> Dict:
        """
        Binary classification: CRIMINAL or SAFE.
        No suspicious state.
        """
        if not top_matches:
            return {
                "match_id": None, "distance": 1.0, "confidence": 0.0,
                "threat": ThreatLevel.SAFE, "name": "Passenger",
                "top_matches": [], "reason": "No database entries"
            }

        best = top_matches[0]

        # No match above threshold → SAFE
        if best["distance"] > CRIMINAL_THRESHOLD:
            return {
                "match_id": None, "distance": best["distance"],
                "confidence": best["confidence"],
                "threat": ThreatLevel.SAFE, "name": "Passenger",
                "top_matches": top_matches,
                "reason": f"No match: dist={best['distance']:.3f} > {CRIMINAL_THRESHOLD}"
            }

        # Ambiguity check: if top-2 is very close to top-1, treat as SAFE
        if len(top_matches) >= 2:
            margin = top_matches[1]["distance"] - best["distance"]
            if margin < TOP_K_MARGIN:
                return {
                    "match_id": None, "distance": best["distance"],
                    "confidence": best["confidence"],
                    "threat": ThreatLevel.SAFE, "name": "Passenger",
                    "top_matches": top_matches,
                    "reason": f"Ambiguous: margin={margin:.3f} < {TOP_K_MARGIN}"
                }

        # Strong single-frame match — still needs multi-frame verification
        return {
            "match_id": best["criminal_id"],
            "distance": best["distance"],
            "confidence": best["confidence"],
            "threat": ThreatLevel.CRIMINAL,
            "name": best["name"],
            "top_matches": top_matches,
            "reason": f"Potential match: dist={best['distance']:.3f}"
        }

    def capture_evidence_snapshot(self, frame: np.ndarray,
                                   facial_area: Dict,
                                   criminal_id: str) -> Optional[str]:
        """
        Capture evidence snapshot if under MAX_EVIDENCE_SNAPSHOTS limit.
        Returns base64-encoded JPEG string, or None if limit reached.
        """
        if self.evidence_counts[criminal_id] >= MAX_EVIDENCE_SNAPSHOTS:
            return None

        try:
            x = facial_area.get("x", 0)
            y = facial_area.get("y", 0)
            w = facial_area.get("w", 100)
            h = facial_area.get("h", 100)

            # Expand crop area slightly for context
            pad = 30
            x1 = max(0, x - pad)
            y1 = max(0, y - pad)
            x2 = min(frame.shape[1], x + w + pad)
            y2 = min(frame.shape[0], y + h + pad)

            face_crop = frame[y1:y2, x1:x2]
            if face_crop.size == 0:
                face_crop = frame

            # Save to evidence directory
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{criminal_id}_{ts}_{self.evidence_counts[criminal_id]}.jpg"
            save_path = EVIDENCE_DIR / filename
            cv2.imwrite(str(save_path), face_crop)

            # Encode to base64
            _, buf = cv2.imencode('.jpg', face_crop, [cv2.IMWRITE_JPEG_QUALITY, 85])
            b64 = base64.b64encode(buf.tobytes()).decode('utf-8')

            self.evidence_counts[criminal_id] += 1
            return b64
        except Exception as e:
            print(f"Evidence capture error: {e}")
            return None

    def detect_and_identify(self, frame: np.ndarray, camera_id: str = "CAM-001",
                            camera_location: str = "Unknown") -> List[Detection]:
        """
        Detect faces and classify as CRIMINAL or SAFE.
        Multi-frame verification prevents false positives.
        """
        from deepface import DeepFace
        start = time.time()
        detections = []
        self._debug_info = []

        if frame is None or frame.size == 0:
            return detections

        try:
            face_results = DeepFace.represent(
                img_path=frame,
                model_name=self.model_name,
                detector_backend=self.detector_backend,
                enforce_detection=False
            )

            for face_data in face_results:
                embedding = np.array(face_data["embedding"])
                facial_area = face_data.get("facial_area", {})

                # Filter out full-frame fallbacks and tiny faces
                if facial_area:
                    fw = facial_area.get("w", 0)
                    fh = facial_area.get("h", 0)
                    if fw > frame.shape[1] * 0.9 and fh > frame.shape[0] * 0.9:
                        continue
                    if fw < FACE_MIN_SIZE or fh < FACE_MIN_SIZE:
                        continue

                # Step 1: Top-K match
                top_matches = self._get_top_k_matches(embedding)

                # Step 2: Single-frame classification
                frame_result = self._classify_single_frame(top_matches)

                # Step 3: Feed into multi-frame verifier
                cx = facial_area.get("x", 0) + facial_area.get("w", 0) // 2
                cy = facial_area.get("y", 0) + facial_area.get("h", 0) // 2
                track_id = self.verifier.get_track_id(cx, cy)

                self.verifier.add_result(
                    track_id,
                    match_id=frame_result["match_id"],
                    distance=frame_result["distance"],
                    confidence=frame_result["confidence"]
                )

                # Step 4: Get verified result
                verified = self.verifier.get_verified_result(track_id)

                final_threat = verified["threat_level"]
                final_confidence = verified.get("confidence", 0.0)
                criminal_id = verified.get("criminal_id", None)

                if final_threat == ThreatLevel.CRIMINAL and criminal_id:
                    crim_data = self.criminal_embeddings.get(criminal_id, {})
                    final_name = f"CONFIRMED: {crim_data.get('name', 'Unknown')}"
                else:
                    final_name = "Passenger"
                    criminal_id = None

                detection = Detection(
                    id=generate_id(),
                    person_name=final_name,
                    threat_level=final_threat,
                    confidence=final_confidence,
                    distance=round(frame_result["distance"], 4),
                    camera_id=camera_id,
                    camera_location=camera_location,
                    timestamp=datetime.now().isoformat(),
                    facial_area=facial_area,
                    criminal_id=criminal_id
                )
                detections.append(detection)

                self._debug_info.append({
                    "track_id": track_id,
                    "single_frame": frame_result["reason"],
                    "verification": verified["reason"],
                    "top_matches": [
                        f"{m['name']}(d={m['distance']:.3f},c={m['confidence']}%)"
                        for m in top_matches
                    ],
                    "final_threat": final_threat.value,
                    "match_frames": f"{verified.get('match_count', 0)}/{verified.get('total_frames', 0)}"
                })

        except Exception as e:
            if "Face could not be detected" not in str(e):
                print(f"DEBUG: DeepFace Exception: {e}")

        elapsed = time.time() - start
        if elapsed > 0:
            self._fps = 1.0 / elapsed
        self._process_time = elapsed
        return detections

    def annotate_frame(self, frame: np.ndarray, detections: List[Detection]) -> np.ndarray:
        """
        Annotate the live video frame:
        - SAFE faces: blurred (privacy protection for normal passengers)
        - CRIMINAL faces: clear, bright red bounding box with name
        """
        annotated = frame.copy()

        for det in detections:
            fa = det.facial_area
            if not fa:
                continue
            x, y = fa.get("x", 0), fa.get("y", 0)
            w, h = fa.get("w", 0), fa.get("h", 0)
            if w == 0 or h == 0:
                continue

            # Clamp to frame bounds
            x = max(0, x)
            y = max(0, y)
            x2 = min(annotated.shape[1], x + w)
            y2 = min(annotated.shape[0], y + h)

            if det.threat_level == ThreatLevel.CRIMINAL:
                # ── CRIMINAL: show clear face with aggressive red box ──────
                color = (0, 0, 255)  # Red (BGR)

                # Pulsing-style thick border
                cv2.rectangle(annotated, (x-2, y-2), (x2+2, y2+2), (0, 0, 180), 1)
                cv2.rectangle(annotated, (x, y), (x2, y2), color, 3)

                # Corner accent lines
                cl = min(25, w // 4, h // 4)
                corners = [
                    (x, y, cl, 0), (x, y, 0, cl),
                    (x2, y, -cl, 0), (x2, y, 0, cl),
                    (x, y2, cl, 0), (x, y2, 0, -cl),
                    (x2, y2, -cl, 0), (x2, y2, 0, -cl)
                ]
                for cx_, cy_, dx, dy in corners:
                    cv2.line(annotated, (cx_, cy_), (cx_+dx, cy_+dy), (255, 50, 50), 4)

                # Label background + text
                label = f"!! CRIMINAL !! {det.person_name.replace('CONFIRMED: ', '')}"
                font = cv2.FONT_HERSHEY_SIMPLEX
                (tw, th_t), _ = cv2.getTextSize(label, font, 0.55, 2)
                cv2.rectangle(annotated, (x, y - th_t - 14), (x + tw + 10, y), (180, 0, 0), -1)
                cv2.rectangle(annotated, (x, y - th_t - 14), (x + tw + 10, y), color, 1)
                cv2.putText(annotated, label, (x + 5, y - 5),
                            font, 0.55, (255, 255, 255), 2, cv2.LINE_AA)

                # Confidence below box
                conf_label = f"Confidence: {det.confidence}%"
                cv2.putText(annotated, conf_label, (x, y2 + 20),
                            font, 0.45, (255, 100, 100), 1, cv2.LINE_AA)

            else:
                # ── SAFE: blur the face for privacy ──────────────────────
                face_roi = annotated[y:y2, x:x2]
                if face_roi.size > 0:
                    # Strong blur — bigger kernel = more blurred
                    blur_ksize = max(15, (w // 5) * 2 + 1)
                    blurred_roi = cv2.GaussianBlur(face_roi, (blur_ksize, blur_ksize), 30)
                    annotated[y:y2, x:x2] = blurred_roi

                # Thin green box to show detection (unobtrusive)
                cv2.rectangle(annotated, (x, y), (x2, y2), (0, 200, 80), 1)

        # System overlay (top bar)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        overlay_h = 32
        cv2.rectangle(annotated, (0, 0), (annotated.shape[1], overlay_h), (10, 10, 30), -1)
        cv2.putText(annotated, f"AIRPORT SECURITY  |  {ts}",
                    (10, 22), cv2.FONT_HERSHEY_SIMPLEX, 0.55, (0, 200, 255), 1, cv2.LINE_AA)
        cv2.putText(annotated, f"FPS: {self._fps:.1f}",
                    (annotated.shape[1] - 110, 22),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 255, 0), 1, cv2.LINE_AA)

        # Bottom status bar
        has_criminal = any(d.threat_level == ThreatLevel.CRIMINAL for d in detections)
        bar_color = (0, 0, 200) if has_criminal else (0, 120, 40)
        bar_text = "!! CRIMINAL DETECTED — ALERT DISPATCHED !!" if has_criminal else "All Clear — No Criminal Detected"
        bar_y = annotated.shape[0] - 30
        cv2.rectangle(annotated, (0, bar_y), (annotated.shape[1], annotated.shape[0]), bar_color, -1)
        cv2.putText(annotated, bar_text, (10, annotated.shape[0] - 10),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.6, (255, 255, 255), 1, cv2.LINE_AA)

        return annotated

    @property
    def debug_info(self) -> List[Dict]:
        return self._debug_info

    @staticmethod
    def _cosine_distance(a: np.ndarray, b: np.ndarray) -> float:
        dot = np.dot(a, b)
        na, nb = np.linalg.norm(a), np.linalg.norm(b)
        if na == 0 or nb == 0:
            return 1.0
        return 1.0 - (dot / (na * nb))

    @property
    def fps(self):
        return self._fps

    @property
    def process_time(self):
        return self._process_time
