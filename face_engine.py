"""
Face detection and recognition engine with STRICT anti-false-positive measures.

Key anti-false-positive features:
1. Multi-frame verification — requires consistent matches across 7/10 frames
2. Top-3 matching with margin check — ambiguous matches → Suspicious only
3. 90% confidence threshold for criminal alerts
4. Unknown persons are NEVER classified as criminal
5. Minimum face size filtering
6. Debug output with distance scores and top matched identities
"""
import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

import numpy as np
import cv2
import time
from typing import List, Dict, Tuple, Optional
from collections import defaultdict, deque
from datetime import datetime
from .config import (
    FACE_DETECTION_BACKEND, FACE_RECOGNITION_MODEL,
    CRIMINAL_THRESHOLD, SUSPICIOUS_THRESHOLD,
    IMAGES_DIR, EMBEDDINGS_DIR,
    VERIFICATION_FRAME_COUNT, VERIFICATION_MIN_MATCHES,
    CONFIDENCE_ALERT_THRESHOLD, TOP_K_MATCHES, TOP_K_MARGIN,
    FACE_MIN_SIZE
)
from .models import Detection, ThreatLevel, generate_id


class MultiFrameVerifier:
    """
    Tracks face match results across multiple frames to prevent
    single-frame false positives. A person is only confirmed as
    criminal if matched consistently across VERIFICATION_MIN_MATCHES
    out of VERIFICATION_FRAME_COUNT consecutive frames.
    """

    def __init__(self):
        # Key: face_track_id → deque of per-frame results
        self.tracks: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=VERIFICATION_FRAME_COUNT)
        )
        self.track_positions: Dict[str, Tuple[int, int]] = {}
        self.track_last_seen: Dict[str, float] = {}

    def get_track_id(self, cx: int, cy: int) -> str:
        """Find existing track near this centroid, or create new one."""
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
            if dist < 120 and dist < best_dist:  # within 120px
                best_dist = dist
                best_id = tid

        if best_id is None:
            best_id = f"face_{generate_id()}"

        self.track_positions[best_id] = (cx, cy)
        self.track_last_seen[best_id] = now
        return best_id

    def add_result(self, track_id: str, match_id: Optional[str],
                   distance: float, confidence: float):
        """Record a single-frame match result for a tracked face."""
        self.tracks[track_id].append({
            "match_id": match_id,
            "distance": distance,
            "confidence": confidence,
            "time": time.time()
        })

    def get_verified_result(self, track_id: str) -> Dict:
        """
        Analyze the frame history for this track and return the
        verified classification. Only confirms CRIMINAL if:
        - Same person matched in >= VERIFICATION_MIN_MATCHES frames
        - Average confidence > CONFIDENCE_ALERT_THRESHOLD
        """
        history = self.tracks.get(track_id, deque())

        if len(history) < 3:
            # Not enough frames yet — always Unknown
            return {
                "verified": False,
                "threat_level": ThreatLevel.SAFE,
                "person_name": "Scanning...",
                "confidence": 0.0,
                "match_count": 0,
                "total_frames": len(history),
                "reason": "Insufficient frames for verification"
            }

        # Count matches per criminal ID
        match_counts: Dict[str, List[Dict]] = defaultdict(list)
        no_match_count = 0

        for entry in history:
            mid = entry["match_id"]
            if mid is None:
                no_match_count += 1
            else:
                match_counts[mid].append(entry)

        total_frames = len(history)

        if not match_counts:
            return {
                "verified": True,
                "threat_level": ThreatLevel.SAFE,
                "person_name": "Unknown Passenger",
                "confidence": 0.0,
                "match_count": 0,
                "total_frames": total_frames,
                "reason": "No database matches found"
            }

        # Find the most frequent match
        best_crim_id = max(match_counts, key=lambda k: len(match_counts[k]))
        best_entries = match_counts[best_crim_id]
        match_count = len(best_entries)
        avg_confidence = sum(e["confidence"] for e in best_entries) / len(best_entries)
        avg_distance = sum(e["distance"] for e in best_entries) / len(best_entries)

        # STRICT verification checks
        has_enough_frames = total_frames >= min(5, VERIFICATION_FRAME_COUNT)
        has_enough_matches = match_count >= VERIFICATION_MIN_MATCHES
        high_confidence = avg_confidence >= CONFIDENCE_ALERT_THRESHOLD
        low_distance = avg_distance < CRIMINAL_THRESHOLD

        if has_enough_frames and has_enough_matches and high_confidence and low_distance:
            return {
                "verified": True,
                "threat_level": ThreatLevel.CRIMINAL,
                "criminal_id": best_crim_id,
                "confidence": round(avg_confidence, 1),
                "avg_distance": round(avg_distance, 4),
                "match_count": match_count,
                "total_frames": total_frames,
                "reason": f"Verified: {match_count}/{total_frames} frames, "
                          f"conf={avg_confidence:.1f}%, dist={avg_distance:.3f}"
            }
        elif has_enough_frames and match_count >= 3 and avg_distance < SUSPICIOUS_THRESHOLD:
            return {
                "verified": True,
                "threat_level": ThreatLevel.SUSPICIOUS,
                "criminal_id": best_crim_id,
                "confidence": round(avg_confidence, 1),
                "avg_distance": round(avg_distance, 4),
                "match_count": match_count,
                "total_frames": total_frames,
                "reason": f"Suspicious: {match_count}/{total_frames} frames, "
                          f"conf={avg_confidence:.1f}% (needs {CONFIDENCE_ALERT_THRESHOLD}%)"
            }
        else:
            return {
                "verified": True,
                "threat_level": ThreatLevel.SAFE,
                "person_name": "Unknown Passenger",
                "confidence": round(avg_confidence, 1) if best_entries else 0.0,
                "match_count": match_count,
                "total_frames": total_frames,
                "reason": f"Not verified: {match_count}/{total_frames} frames "
                          f"(need {VERIFICATION_MIN_MATCHES})"
            }


class FaceEngine:
    """
    Face detection and recognition engine with strict false-positive prevention.
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
        for f in EMBEDDINGS_DIR.glob("*.npy"):
            try:
                f.unlink()
            except Exception:
                pass
        self.precompute_embeddings(criminals)

    def _get_top_k_matches(self, embedding: np.ndarray) -> List[Dict]:
        """
        Compare embedding against ALL criminal embeddings and return
        the top K closest matches with distances. This prevents
        false positives from single-best-match ambiguity.
        """
        all_matches = []

        for crim_id, crim_data in self.criminal_embeddings.items():
            # Get best distance for this criminal (across all their images)
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

        # Sort by distance (closest first)
        all_matches.sort(key=lambda x: x["distance"])
        return all_matches[:TOP_K_MATCHES]

    def _classify_single_frame(self, top_matches: List[Dict]) -> Dict:
        """
        Classify a single frame using top-K matches with anti-false-positive logic:
        1. If no matches or best distance > SUSPICIOUS_THRESHOLD → Safe/Unknown
        2. If top-1 and top-2 are within TOP_K_MARGIN → ambiguous → Suspicious at most
        3. If distance < CRIMINAL_THRESHOLD and clear margin → potential Criminal
        """
        if not top_matches:
            return {
                "match_id": None, "distance": 1.0, "confidence": 0.0,
                "threat": ThreatLevel.SAFE, "name": "Unknown Passenger",
                "top_matches": [], "reason": "No database entries"
            }

        best = top_matches[0]

        # Rule 1: No strong match → ALWAYS Unknown/Safe
        if best["distance"] > SUSPICIOUS_THRESHOLD:
            return {
                "match_id": None, "distance": best["distance"],
                "confidence": best["confidence"],
                "threat": ThreatLevel.SAFE, "name": "Unknown Passenger",
                "top_matches": top_matches,
                "reason": f"Best distance {best['distance']:.3f} > {SUSPICIOUS_THRESHOLD}"
            }

        # Rule 2: Check ambiguity — if top-2 match is close to top-1, it's ambiguous
        if len(top_matches) >= 2:
            margin = top_matches[1]["distance"] - best["distance"]
            if margin < TOP_K_MARGIN and best["distance"] < SUSPICIOUS_THRESHOLD:
                return {
                    "match_id": best["criminal_id"],
                    "distance": best["distance"],
                    "confidence": best["confidence"],
                    "threat": ThreatLevel.SUSPICIOUS,
                    "name": f"Ambiguous: {best['name']}?",
                    "top_matches": top_matches,
                    "reason": f"Ambiguous: top-1/top-2 margin={margin:.3f} < {TOP_K_MARGIN}"
                }

        # Rule 3: Strong match below criminal threshold (single-frame only — needs verification)
        if best["distance"] < CRIMINAL_THRESHOLD:
            return {
                "match_id": best["criminal_id"],
                "distance": best["distance"],
                "confidence": best["confidence"],
                "threat": ThreatLevel.CRIMINAL,  # Single-frame: will be verified
                "name": best["name"],
                "top_matches": top_matches,
                "reason": f"Strong match: dist={best['distance']:.3f} < {CRIMINAL_THRESHOLD}"
            }

        # Rule 4: Between thresholds → Suspicious
        return {
            "match_id": best["criminal_id"],
            "distance": best["distance"],
            "confidence": best["confidence"],
            "threat": ThreatLevel.SUSPICIOUS,
            "name": f"Possible: {best['name']}",
            "top_matches": top_matches,
            "reason": f"Moderate match: {CRIMINAL_THRESHOLD} <= dist={best['distance']:.3f} < {SUSPICIOUS_THRESHOLD}"
        }

    def detect_and_identify(self, frame: np.ndarray, camera_id: str = "CAM-001",
                            camera_location: str = "Unknown") -> List[Detection]:
        """
        Detect faces and classify with MULTI-FRAME VERIFICATION.
        A single frame match is NEVER enough to confirm criminal.
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

                # Filter: skip full-frame "faces" (no real face detected)
                if facial_area:
                    fw = facial_area.get("w", 0)
                    fh = facial_area.get("h", 0)
                    if fw > frame.shape[1] * 0.9 and fh > frame.shape[0] * 0.9:
                        continue
                    if fw < FACE_MIN_SIZE or fh < FACE_MIN_SIZE:
                        continue

                # Step 1: Get top-K matches for this face
                top_matches = self._get_top_k_matches(embedding)

                # Step 2: Single-frame classification (preliminary)
                frame_result = self._classify_single_frame(top_matches)

                # Step 3: Track this face and feed into multi-frame verifier
                cx = facial_area.get("x", 0) + facial_area.get("w", 0) // 2
                cy = facial_area.get("y", 0) + facial_area.get("h", 0) // 2
                track_id = self.verifier.get_track_id(cx, cy)

                self.verifier.add_result(
                    track_id,
                    match_id=frame_result["match_id"],
                    distance=frame_result["distance"],
                    confidence=frame_result["confidence"]
                )

                # Step 4: Get VERIFIED result from multi-frame history
                verified = self.verifier.get_verified_result(track_id)

                # Step 5: Build final detection using verified result
                final_threat = verified["threat_level"]
                final_confidence = verified.get("confidence", 0.0)
                criminal_id = verified.get("criminal_id", None)

                if final_threat == ThreatLevel.CRIMINAL and criminal_id:
                    crim_data = self.criminal_embeddings.get(criminal_id, {})
                    final_name = f"CONFIRMED: {crim_data.get('name', 'Unknown')}"
                elif final_threat == ThreatLevel.SUSPICIOUS and criminal_id:
                    crim_data = self.criminal_embeddings.get(criminal_id, {})
                    final_name = f"UNVERIFIED: {crim_data.get('name', '?')}"
                else:
                    final_name = verified.get("person_name", "Unknown Passenger")
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

                # Debug info for logging
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
                pass

        elapsed = time.time() - start
        if elapsed > 0:
            self._fps = 1.0 / elapsed
        self._process_time = elapsed
        return detections

    def annotate_frame(self, frame: np.ndarray, detections: List[Detection]) -> np.ndarray:
        """Annotate frame with bounding boxes, labels, and debug info."""
        annotated = frame.copy()

        for i, det in enumerate(detections):
            fa = det.facial_area
            if not fa:
                continue
            x, y = fa.get("x", 0), fa.get("y", 0)
            w, h = fa.get("w", 0), fa.get("h", 0)
            if w == 0 or h == 0:
                continue

            if det.threat_level == ThreatLevel.CRIMINAL:
                color = (0, 0, 255)
                icon = "CRIMINAL"
            elif det.threat_level == ThreatLevel.SUSPICIOUS:
                color = (0, 165, 255)
                icon = "SUSPICIOUS"
            else:
                color = (0, 255, 100)
                icon = "SAFE"

            thick = 2 if det.threat_level == ThreatLevel.SAFE else 3
            cv2.rectangle(annotated, (x, y), (x + w, y + h), color, thick)

            # Corner accents
            cl = min(20, w // 4, h // 4)
            for cx, cy, dx, dy in [
                (x, y, cl, 0), (x, y, 0, cl),
                (x+w, y, -cl, 0), (x+w, y, 0, cl),
                (x, y+h, cl, 0), (x, y+h, 0, -cl),
                (x+w, y+h, -cl, 0), (x+w, y+h, 0, -cl)
            ]:
                cv2.line(annotated, (cx, cy), (cx+dx, cy+dy), color, thick+1)

            # Main label
            label = f"{icon} | {det.person_name}"
            font = cv2.FONT_HERSHEY_SIMPLEX
            (tw, th_t), _ = cv2.getTextSize(label, font, 0.5, 1)
            cv2.rectangle(annotated, (x, y-th_t-10), (x+tw+10, y), color, -1)
            cv2.putText(annotated, label, (x+5, y-5), font, 0.5,
                        (255, 255, 255), 1, cv2.LINE_AA)

            # Debug info below bounding box
            debug_lines = [
                f"Dist: {det.distance:.3f} | Conf: {det.confidence}%",
            ]
            if i < len(self._debug_info):
                dbg = self._debug_info[i]
                debug_lines.append(f"Frames: {dbg.get('match_frames', '?')}")
                if dbg.get("top_matches"):
                    debug_lines.append(f"Top: {dbg['top_matches'][0]}")

            for j, line in enumerate(debug_lines):
                cv2.putText(annotated, line, (x, y + h + 15 + j * 16),
                            font, 0.38, color, 1, cv2.LINE_AA)

        # System overlay
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cv2.putText(annotated, f"AIRPORT SECURITY | {ts}", (10, 25),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 200, 255), 1, cv2.LINE_AA)
        cv2.putText(annotated, f"FPS: {self._fps:.1f}", (frame.shape[1]-120, 25),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 255, 0), 1, cv2.LINE_AA)

        # "No Criminal Detected" overlay when no threats
        has_threat = any(d.threat_level != ThreatLevel.SAFE for d in detections)
        if not has_threat:
            cv2.putText(annotated, "No Criminal Detected", (10, frame.shape[0] - 15),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 100), 1, cv2.LINE_AA)

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
