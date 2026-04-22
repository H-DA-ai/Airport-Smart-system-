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
EVIDENCE_DIR = DATABASE_DIR / "evidence"
LOG_DIR = BASE_DIR / "logs"
DETECTION_LOG = LOG_DIR / "detections.jsonl"
ALERT_LOG = LOG_DIR / "alerts.jsonl"
POLICE_LOG = LOG_DIR / "police_dispatch.jsonl"
SECURITY_DIR = BASE_DIR / "security"
ENCRYPTION_KEY_FILE = SECURITY_DIR / "encryption.key"
FRONTEND_DIR = BASE_DIR / "frontend"

# ─── Face Recognition ───────────────────────────────────
FACE_DETECTION_BACKEND = "mtcnn"                # MTCNN provides facial alignment (crucial for ArcFace accuracy!)
FACE_RECOGNITION_MODEL = "ArcFace"
DISTANCE_METRIC = "cosine"

# ─── Classification Thresholds ──────────────────────────
# Only two states: CRIMINAL or SAFE (no suspicious)
# ArcFace cosine distance: 0.0 = identical, 1.0 = completely different
CRIMINAL_THRESHOLD = 0.60       # Lowered from 0.85 to 0.60 to stop non-criminals from being detected!
FACE_MIN_SIZE = 30              # Minimum face size in pixels

# ─── Multi-Frame Verification ────────────────────────────
VERIFICATION_FRAME_COUNT = 3    # Track across 3 frames
VERIFICATION_MIN_MATCHES = 2    # Must match 2 times to prevent false positives
CONFIDENCE_ALERT_THRESHOLD = 0.0   # Nuclear override: ignore confidence limits
TOP_K_MATCHES = 3               # Compare top 3 matches
TOP_K_MARGIN = 0.08             # Margin for ambiguity check

# ─── Evidence & Police Alert Settings ───────────────────
MAX_EVIDENCE_SNAPSHOTS = 2      # Max 2 photos captured per criminal detection
POLICE_ALERT_COOLDOWN = 120     # Wait 2 minutes before sending another Telegram message!
ALERT_DEDUP_SECONDS = 60        # Wait 60 seconds before showing another red alert for the same person!

# ─── Telegram Integration ───────────────────────────────
TELEGRAM_BOT_TOKEN = "8628350259:AAE7te8zkpmVAATgJSxoZ3_byem8Ph26rS4"
TELEGRAM_CHAT_ID = ""           # Leave empty to auto-detect from recent bot messages

# ─── Camera Settings ────────────────────────────────────
DEFAULT_CAMERAS = [
    {"camera_id": "CAM-001", "location": "Main Entrance", "source": 0},
]
FRAME_WIDTH = 1280
FRAME_HEIGHT = 720
PROCESS_EVERY_N_FRAMES = 5      # Process every 5th frame so the camera feed remains incredibly fast and smooth!

# ─── Behavior Analysis (kept for loitering, but no suspicious threat) ──
LOITER_TIME_SECONDS = 120
LOITER_RADIUS_PIXELS = 80
RUNNING_SPEED_THRESHOLD = 250
RESTRICTED_AREAS = []

# ─── Server Settings ────────────────────────────────────
HOST = "127.0.0.1"
PORT = 8000

# ─── Create Required Directories ────────────────────────
for d in [DATABASE_DIR, IMAGES_DIR, EMBEDDINGS_DIR, EVIDENCE_DIR, LOG_DIR, SECURITY_DIR]:
    d.mkdir(parents=True, exist_ok=True)
