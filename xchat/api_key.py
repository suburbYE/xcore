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
        """Return {"providers": {name: key}, "primary": name}.

        Legacy single-provider format is transparently upgraded on read.
        """
        try:
            if not CLOUD_CONFIG.exists():
                return None
            encrypted = CLOUD_CONFIG.read_bytes()
            key = cls._derive_key()
            plain = cls._decrypt(encrypted, key)
            data = json.loads(plain)
            if "providers" in data:
                return data
            if "provider" in data and "key" in data:  # legacy format
                return {"providers": {data["provider"]: data["key"]}, "primary": data["provider"]}
            return None
        except Exception:
            return None

    @classmethod
    def _write(cls, data: dict):
        key = cls._derive_key()
        plain = json.dumps(data)
        encrypted = cls._encrypt(plain, key)
        CLOUD_CONFIG.parent.mkdir(parents=True, exist_ok=True)
        CLOUD_CONFIG.write_bytes(encrypted)
        CLOUD_CONFIG.chmod(0o600)

    @classmethod
    def save(cls, provider: str, api_key: str):
        """Legacy single-provider write: replaces config with one provider."""
        cls._write({"providers": {provider: api_key}, "primary": provider})

    @classmethod
    def add_provider(cls, provider: str, api_key: str, primary: bool = False):
        """Add or overwrite one provider, keeping the others."""
        cur = cls.load() or {"providers": {}, "primary": None}
        providers = dict(cur.get("providers", {}))
        providers[provider] = api_key
        cur_primary = cur.get("primary")
        if primary or not cur_primary or cur_primary not in providers:
            cur_primary = provider
        cls._write({"providers": providers, "primary": cur_primary})

    @classmethod
    def set_primary(cls, provider: str):
        """Switch the primary provider used by default."""
        cur = cls.load()
        if not cur or provider not in cur.get("providers", {}):
            raise ValueError(f"provider '{provider}' not configured")
        cur["primary"] = provider
        cls._write(cur)
