"""
Security utilities: encryption, secure logging, hash verification.
"""
import json
import hashlib
import base64
from pathlib import Path
from datetime import datetime

try:
    from cryptography.fernet import Fernet
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


class SecurityManager:
    def __init__(self, key_file: Path):
        self.key_file = key_file
        self.cipher = None
        if HAS_CRYPTOGRAPHY:
            self._init_encryption()

    def _init_encryption(self):
        try:
            self.key_file.parent.mkdir(parents=True, exist_ok=True)
            if self.key_file.exists():
                key = self.key_file.read_bytes()
            else:
                key = Fernet.generate_key()
                self.key_file.write_bytes(key)
            self.cipher = Fernet(key)
        except Exception as e:
            print(f"Warning: Encryption init failed: {e}")

    def encrypt(self, data: str) -> str:
        if self.cipher:
            return self.cipher.encrypt(data.encode()).decode()
        return base64.b64encode(data.encode()).decode()

    def decrypt(self, data: str) -> str:
        if self.cipher:
            return self.cipher.decrypt(data.encode()).decode()
        return base64.b64decode(data.encode()).decode()

    def hash_data(self, data: str) -> str:
        return hashlib.sha256(data.encode()).hexdigest()

    def secure_log(self, log_file: Path, entry: dict):
        log_file.parent.mkdir(parents=True, exist_ok=True)
        entry_copy = entry.copy()
        entry_copy["timestamp"] = datetime.now().isoformat()
        entry_copy["hash"] = self.hash_data(
            json.dumps(entry_copy, sort_keys=True, default=str)
        )
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry_copy, default=str) + "\n")
