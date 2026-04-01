"""
Criminal database management: CRUD operations, search, and persistence.
"""
import json
from pathlib import Path
from typing import List, Optional, Dict
from datetime import datetime
from .config import CRIMINALS_JSON, IMAGES_DIR, EMBEDDINGS_DIR
from .models import generate_id


class DatabaseManager:
    def __init__(self):
        self.criminals: List[Dict] = []
        self._load()

    def _load(self):
        if CRIMINALS_JSON.exists():
            with open(CRIMINALS_JSON, "r", encoding="utf-8") as f:
                self.criminals = json.load(f)
                for c in self.criminals:
                    if "id" not in c:
                        c["id"] = generate_id()
        else:
            self.criminals = []

    def _save(self):
        CRIMINALS_JSON.parent.mkdir(parents=True, exist_ok=True)
        with open(CRIMINALS_JSON, "w", encoding="utf-8") as f:
            json.dump(self.criminals, f, indent=2, default=str)

    def get_all(self) -> List[Dict]:
        return self.criminals

    def get_by_id(self, criminal_id: str) -> Optional[Dict]:
        for c in self.criminals:
            if c["id"] == criminal_id:
                return c
        return None

    def search(self, query: str) -> List[Dict]:
        q = query.lower()
        return [
            c for c in self.criminals
            if q in c.get("name", "").lower()
            or q in c.get("crime", "").lower()
            or q in c.get("case_id", "").lower()
        ]

    def add(self, name: str, crime: str, case_id: str,
            status: str = "Wanted", danger_level: str = "High",
            description: str = "", images: List[str] = None) -> Dict:
        record = {
            "id": generate_id(),
            "name": name,
            "crime": crime,
            "case_id": case_id,
            "status": status,
            "danger_level": danger_level,
            "description": description,
            "images": images or [],
            "last_seen": None,
            "added_at": datetime.now().isoformat()
        }
        self.criminals.append(record)
        self._save()
        return record

    def update(self, criminal_id: str, **kwargs) -> Optional[Dict]:
        for c in self.criminals:
            if c["id"] == criminal_id:
                for key, value in kwargs.items():
                    if key in c:
                        c[key] = value
                self._save()
                return c
        return None

    def remove(self, criminal_id: str) -> bool:
        for i, c in enumerate(self.criminals):
            if c["id"] == criminal_id:
                for img in c.get("images", []):
                    img_path = IMAGES_DIR / img
                    if img_path.exists():
                        img_path.unlink()
                emb_path = EMBEDDINGS_DIR / f"{criminal_id}.npy"
                if emb_path.exists():
                    emb_path.unlink()
                self.criminals.pop(i)
                self._save()
                return True
        return False

    def add_image(self, criminal_id: str, filename: str) -> bool:
        for c in self.criminals:
            if c["id"] == criminal_id:
                if filename not in c["images"]:
                    c["images"].append(filename)
                    self._save()
                return True
        return False

    def update_last_seen(self, criminal_id: str, location: str = ""):
        for c in self.criminals:
            if c["id"] == criminal_id:
                c["last_seen"] = f"{datetime.now().isoformat()} - {location}"
                self._save()
                break

    def get_stats(self) -> Dict:
        by_status = {}
        by_danger = {}
        for c in self.criminals:
            s = c.get("status", "Unknown")
            d = c.get("danger_level", "Unknown")
            by_status[s] = by_status.get(s, 0) + 1
            by_danger[d] = by_danger.get(d, 0) + 1
        return {
            "total_records": len(self.criminals),
            "by_status": by_status,
            "by_danger_level": by_danger
        }
