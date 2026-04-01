"""
Configuration settings for the Smart Airport Security System.
"""
import os
from pathlib import Path

# ─── Paths ───────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_DIR = BASE_DIR / "database"
CRIMINALS_JSON = DATABASE_DIR / "criminals.json"
IMAGES_DIR = DATABASE_DIR / "images"
EMBEDDINGS_DIR = DATABASE_DIR / "embeddings"
LOG_DIR = BASE_DIR / "logs"
DETECTION_LOG = LOG_DIR / "detections.jsonl"
ALERT_LOG = LOG_DIR / "alerts.jsonl"
SECURITY_DIR = BASE_DIR / "security"
ENCRYPTION_KEY_FILE = SECURITY_DIR / "encryption.key"
FRONTEND_DIR = BASE_DIR / "frontend"

# ─── Face Recognition ───────────────────────────────────
FACE_DETECTION_BACKEND = "opencv"
FACE_RECOGNITION_MODEL = "ArcFace"
DISTANCE_METRIC = "cosine"

# ─── Classification Thresholds (STRICT) ─────────────────
CRIMINAL_THRESHOLD = 0.40       # distance < 0.40 → Confirmed criminal
SUSPICIOUS_THRESHOLD = 0.60     # 0.40–0.60 → Suspicious / needs verification
# distance > 0.60 → Unknown / Safe — NEVER classify as criminal

# ─── Multi-Frame Verification (Anti-False-Positive) ─────
VERIFICATION_FRAME_COUNT = 10   # Track across this many frames
VERIFICATION_MIN_MATCHES = 7    # Must match in at least 7 of 10 frames
CONFIDENCE_ALERT_THRESHOLD = 90.0  # Only alert if confidence > 90%
TOP_K_MATCHES = 3               # Compare top 3 matches, not just best
TOP_K_MARGIN = 0.05             # If top-1 and top-2 are within this margin → Suspicious only
FACE_MIN_SIZE = 40              # Minimum face width/height in pixels to process

# ─── Camera Settings ────────────────────────────────────
DEFAULT_CAMERAS = [
    {"camera_id": "CAM-001", "location": "Main Entrance", "source": 0},
]
FRAME_WIDTH = 1280
FRAME_HEIGHT = 720
PROCESS_EVERY_N_FRAMES = 3

# ─── Behavior Analysis ──────────────────────────────────
LOITER_TIME_SECONDS = 120
LOITER_RADIUS_PIXELS = 80
RUNNING_SPEED_THRESHOLD = 250
RESTRICTED_AREAS = []

# ─── Server Settings ────────────────────────────────────
HOST = "127.0.0.1"
PORT = 8000

# ─── Create Required Directories ────────────────────────
for d in [DATABASE_DIR, IMAGES_DIR, EMBEDDINGS_DIR, LOG_DIR, SECURITY_DIR]:
    d.mkdir(parents=True, exist_ok=True)
