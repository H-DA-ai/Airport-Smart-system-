"""
FastAPI application - Main backend server for Smart Airport Security System.
Binary detection: CRIMINAL (alert + evidence + police dispatch) or SAFE (blurred face).
"""
import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

import json
import time
import asyncio
import threading
import base64
from pathlib import Path
from typing import List
from datetime import datetime

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, UploadFile, File, Form, Query
from fastapi.responses import StreamingResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import cv2
import numpy as np

from .config import (
    HOST, PORT, FRONTEND_DIR, IMAGES_DIR,
    DETECTION_LOG, PROCESS_EVERY_N_FRAMES
)
from .models import ThreatLevel, Alert, SystemStats, generate_id
from .database_manager import DatabaseManager
from .face_engine import FaceEngine
from .alert_system import AlertSystem
from .camera_manager import CameraManager
from .security import SecurityManager
from .config import ENCRYPTION_KEY_FILE

# ─── Initialize Components ──────────────────────────────
app = FastAPI(title="Smart Airport Security System", version="3.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"]
)

db_manager = DatabaseManager()
face_engine = FaceEngine()
alert_system = AlertSystem()
camera_manager = CameraManager()
security = SecurityManager(ENCRYPTION_KEY_FILE)

ws_clients: List[WebSocket] = []
ws_lock = threading.Lock()
start_time = time.time()
total_detections = 0
processing_active = False


# ─── Startup / Shutdown ─────────────────────────────────
@app.on_event("startup")
async def startup():
    global processing_active
    print("=" * 55)
    print("  SMART AIRPORT SECURITY SYSTEM v3.0")
    print("  Binary Mode: CRIMINAL | SAFE (No Suspicious)")
    print("  Privacy: Safe faces auto-blurred on video feed")
    print("=" * 55)
    face_engine.initialize()
    face_engine.precompute_embeddings(db_manager.get_all())
    camera_manager.initialize()
    processing_active = True
    threading.Thread(target=_processing_loop, daemon=True).start()
    print(f"Dashboard: http://{HOST}:{PORT}")
    print("=" * 55)


@app.on_event("shutdown")
async def shutdown():
    global processing_active
    processing_active = False
    camera_manager.stop_all()


# ─── Processing Loop ────────────────────────────────────
def _processing_loop():
    global total_detections
    frame_counter = 0
    last_detections = {}

    while processing_active:
        for cam_id, camera in camera_manager.cameras.items():
            if not camera.running:
                continue

            frame = camera.get_frame()
            if frame is None:
                continue

            frame_counter += 1
            detections = []

            if frame_counter % PROCESS_EVERY_N_FRAMES == 0:
                detections = face_engine.detect_and_identify(
                    frame, cam_id, camera.location
                )
                last_detections[cam_id] = detections

                # Count criminal detections only
                criminal_detections = [d for d in detections
                                       if d.threat_level == ThreatLevel.CRIMINAL]
                total_detections += len(criminal_detections)

                for det in detections:
                    if det.threat_level == ThreatLevel.CRIMINAL:
                        # Capture evidence snapshot (max 2 per criminal)
                        evidence_b64 = None
                        if det.criminal_id and det.facial_area:
                            evidence_b64 = face_engine.capture_evidence_snapshot(
                                frame, det.facial_area, det.criminal_id
                            )

                        evidence_list = [evidence_b64] if evidence_b64 else []

                        # Create alert
                        alert = alert_system.create_from_detection(
                            det, evidence_images=evidence_list
                        )

                        if alert:
                            # Send police alert
                            dispatch = alert_system.send_police_alert(alert)
                            _broadcast_alert(alert, dispatch)

                            # Log the detection
                            log_entry = {
                                "timestamp": det.timestamp,
                                "person": det.person_name,
                                "threat": det.threat_level.value,
                                "confidence": det.confidence,
                                "distance": det.distance,
                                "camera": cam_id,
                                "location": camera.location
                            }
                            security.secure_log(DETECTION_LOG, log_entry)

                    # Update last seen in DB for confirmed criminals
                    if det.criminal_id and det.threat_level == ThreatLevel.CRIMINAL:
                        db_manager.update_last_seen(det.criminal_id, camera.location)

            else:
                detections = last_detections.get(cam_id, [])

            # Annotate frame (safe faces blurred, criminal highlighted)
            annotated = face_engine.annotate_frame(frame, detections)
            camera.set_annotated(annotated)

        time.sleep(0.01)


def _broadcast_alert(alert: Alert, dispatch=None):
    """Broadcast alert to all connected WebSocket clients."""
    payload = {
        "type": "alert",
        "data": alert.model_dump()
    }
    # Remove heavy base64 images from WS broadcast (too large), keep flag only
    payload["data"]["has_evidence"] = len(alert.evidence_images) > 0
    payload["data"]["evidence_images"] = []  # Send separately via REST

    if dispatch:
        dispatch_payload = json.dumps({
            "type": "police_alert",
            "data": dispatch.model_dump()
        }, default=str)
    else:
        dispatch_payload = None

    alert_msg = json.dumps(payload, default=str)

    with ws_lock:
        dead_clients = []
        for client in ws_clients:
            try:
                asyncio.run(client.send_text(alert_msg))
                if dispatch_payload:
                    asyncio.run(client.send_text(dispatch_payload))
            except Exception:
                dead_clients.append(client)
        for c in dead_clients:
            ws_clients.remove(c)


# ─── Video Streaming ────────────────────────────────────
@app.get("/api/video/{camera_id}")
async def video_feed(camera_id: str):
    return StreamingResponse(
        camera_manager.generate_mjpeg(camera_id),
        media_type="multipart/x-mixed-replace; boundary=frame"
    )


@app.get("/api/snapshot/{camera_id}")
async def snapshot(camera_id: str):
    b64 = camera_manager.get_snapshot_base64(camera_id)
    if b64:
        return {"snapshot": b64}
    return JSONResponse({"error": "Camera not found"}, status_code=404)


# ─── Alerts API ─────────────────────────────────────────
@app.get("/api/alerts")
async def get_alerts(limit: int = Query(50)):
    alerts = alert_system.get_all(limit)
    result = []
    for a in alerts:
        d = a.model_dump()
        d["has_evidence"] = len(a.evidence_images) > 0
        # Inline first evidence image for thumbnail display in table
        d["evidence_thumb"] = a.evidence_images[0] if a.evidence_images else None
        d["evidence_images"] = []  # Don't send all base64 in list endpoint
        result.append(d)
    return result


@app.get("/api/alerts/{alert_id}/evidence")
async def get_alert_evidence(alert_id: str):
    """Get full evidence images for a specific alert."""
    for a in alert_system.alerts:
        if a.id == alert_id:
            return {"evidence_images": a.evidence_images}
    return JSONResponse({"error": "Alert not found"}, status_code=404)


@app.get("/api/alerts/unacknowledged")
async def get_unacknowledged():
    alerts = alert_system.get_unacknowledged()
    return [{"id": a.id, "threat_level": a.threat_level,
             "person_name": a.person_name, "camera_location": a.camera_location}
            for a in alerts]


@app.post("/api/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: str):
    if alert_system.acknowledge(alert_id):
        return {"status": "acknowledged"}
    return JSONResponse({"error": "Alert not found"}, status_code=404)


@app.delete("/api/alerts")
async def clear_alerts():
    alert_system.clear_all()
    return {"status": "cleared"}


@app.get("/api/alerts/police")
async def get_police_dispatches(limit: int = Query(50)):
    return alert_system.get_police_dispatches(limit)


# ─── Criminal Database API ──────────────────────────────
@app.get("/api/criminals")
async def get_criminals():
    return db_manager.get_all()


@app.get("/api/criminals/{criminal_id}")
async def get_criminal(criminal_id: str):
    record = db_manager.get_by_id(criminal_id)
    if record:
        return record
    return JSONResponse({"error": "Not found"}, status_code=404)


@app.get("/api/criminals/search/{query}")
async def search_criminals(query: str):
    return db_manager.search(query)


@app.post("/api/criminals")
async def add_criminal(
    name: str = Form(...),
    crime: str = Form(...),
    case_id: str = Form(...),
    status: str = Form("Wanted"),
    danger_level: str = Form("High"),
    description: str = Form(""),
    images: List[UploadFile] = File(default=[])
):
    saved_images = []
    for img_file in images:
        filename = f"{generate_id()}_{img_file.filename}"
        path = IMAGES_DIR / filename
        content = await img_file.read()
        with open(path, "wb") as f:
            f.write(content)
        saved_images.append(filename)

    record = db_manager.add(name, crime, case_id, status, danger_level,
                            description, saved_images)
    face_engine.reload_embeddings(db_manager.get_all())
    return record


@app.delete("/api/criminals/{criminal_id}")
async def remove_criminal(criminal_id: str):
    if db_manager.remove(criminal_id):
        face_engine.reload_embeddings(db_manager.get_all())
        return {"status": "removed"}
    return JSONResponse({"error": "Not found"}, status_code=404)


@app.post("/api/criminals/{criminal_id}/images")
async def upload_criminal_image(criminal_id: str, image: UploadFile = File(...)):
    filename = f"{criminal_id}_{generate_id()}_{image.filename}"
    path = IMAGES_DIR / filename
    content = await image.read()
    with open(path, "wb") as f:
        f.write(content)
    if db_manager.add_image(criminal_id, filename):
        face_engine.reload_embeddings(db_manager.get_all())
        return {"status": "uploaded", "filename": filename}
    return JSONResponse({"error": "Criminal not found"}, status_code=404)


# ─── Camera API ─────────────────────────────────────────
@app.get("/api/cameras")
async def get_cameras():
    return camera_manager.get_all_cameras()


@app.post("/api/cameras")
async def add_camera(camera_id: str = Form(...), source: str = Form(...),
                     location: str = Form(...)):
    src = int(source) if source.isdigit() else source
    camera_manager.add_camera(camera_id, src, location)
    return {"status": "added", "camera_id": camera_id}


@app.delete("/api/cameras/{camera_id}")
async def remove_camera(camera_id: str):
    camera_manager.remove_camera(camera_id)
    return {"status": "removed"}


# ─── System Stats ───────────────────────────────────────
@app.get("/api/stats")
async def get_stats():
    return SystemStats(
        total_cameras=len(camera_manager.cameras),
        active_cameras=camera_manager.active_count,
        total_detections=total_detections,
        total_alerts=len(alert_system.alerts),
        unacknowledged_alerts=len(alert_system.get_unacknowledged()),
        criminals_in_db=len(db_manager.get_all()),
        uptime_seconds=round(time.time() - start_time, 1),
        fps=round(face_engine.fps, 1)
    ).model_dump()


# ─── Detection Logs ─────────────────────────────────────
@app.get("/api/logs")
async def get_logs(limit: int = Query(100)):
    logs = []
    if DETECTION_LOG.exists():
        with open(DETECTION_LOG, "r") as f:
            lines = f.readlines()
        for line in lines[-limit:]:
            try:
                logs.append(json.loads(line.strip()))
            except Exception:
                pass
    return list(reversed(logs))


# ─── WebSocket ──────────────────────────────────────────
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    with ws_lock:
        ws_clients.append(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
            elif data == "stats":
                stats = SystemStats(
                    total_cameras=len(camera_manager.cameras),
                    active_cameras=camera_manager.active_count,
                    total_detections=total_detections,
                    total_alerts=len(alert_system.alerts),
                    unacknowledged_alerts=len(alert_system.get_unacknowledged()),
                    criminals_in_db=len(db_manager.get_all()),
                    uptime_seconds=round(time.time() - start_time, 1),
                    fps=round(face_engine.fps, 1)
                ).model_dump()
                await websocket.send_text(json.dumps({"type": "stats", "data": stats}))
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        with ws_lock:
            if websocket in ws_clients:
                ws_clients.remove(websocket)


# ─── Serve Frontend ─────────────────────────────────────
@app.get("/")
async def serve_frontend():
    index = FRONTEND_DIR / "index.html"
    if index.exists():
        return HTMLResponse(index.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>Smart Airport Security System</h1><p>Frontend not found.</p>")


# Mount static files
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")
