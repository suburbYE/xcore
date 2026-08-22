"""
API Key Manager: encrypted local storage for cloud provider credentials.

Machine-bound key (SID + hostname → PBKDF2), AES-256-GCM encryption.
"""

import hashlib
import json
import os

from .config import CLOUD_CONFIG


class APIKeyManager:
    @staticmethod
    def _derive_key() -> bytes:
        """Machine-bound key: SID + hostname → SHA-256."""
        import socket
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as k:
                sid = winreg.QueryValueEx(k, "ProductId")[0]
        except Exception:
            sid = os.environ.get("COMPUTERNAME", "unknown")
        hostname = socket.gethostname()
        salt = b"xcore-cloud-key-v1"
        return hashlib.pbkdf2_hmac("sha256", f"{sid}:{hostname}".encode(), salt, 100000, dklen=32)

    @staticmethod
    def _encrypt(plaintext: str, key: bytes) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        return nonce + aesgcm.encrypt(nonce, plaintext.encode(), None)

    @staticmethod
    def _decrypt(ciphertext: bytes, key: bytes) -> str:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(key)
        nonce = ciphertext[:12]
        ct = ciphertext[12:]
        return aesgcm.decrypt(nonce, ct, None).decode()

    @classmethod
    def load(cls) -> dict | None:
        try:
            if not CLOUD_CONFIG.exists():
                return None
            encrypted = CLOUD_CONFIG.read_bytes()
            key = cls._derive_key()
            plain = cls._decrypt(encrypted, key)
            return json.loads(plain)
        except Exception:
            return None

    @classmethod
    def save(cls, provider: str, api_key: str):
        key = cls._derive_key()
        data = json.dumps({"provider": provider, "key": api_key})
        encrypted = cls._encrypt(data, key)
        CLOUD_CONFIG.parent.mkdir(parents=True, exist_ok=True)
        CLOUD_CONFIG.write_bytes(encrypted)
        CLOUD_CONFIG.chmod(0o600)
