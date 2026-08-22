"""
Sanitizer: strips sensitive data before cloud upload.

Strips file paths → SHA-256 aliases, full hashes → truncated,
recursively cleans scan result dicts.
"""

import hashlib
import json


class Sanitizer:
    @staticmethod
    def file_path(path: str) -> str:
        return f"target_asset_{hashlib.sha256(path.encode()).hexdigest()[:8]}"

    @staticmethod
    def sha256(h: str) -> str:
        return h[:8] + "..."

    @staticmethod
    def scan_result(raw: dict) -> dict:
        """Strip sensitive fields from xcore scan result."""
        clean = {}
        for k, v in raw.items():
            if k in ("file_path", "path", "absolute_path"):
                clean[k] = Sanitizer.file_path(str(v))
            elif k in ("sha256", "hash", "digest"):
                clean[k] = Sanitizer.sha256(str(v))
            elif isinstance(v, dict):
                clean[k] = Sanitizer.scan_result(v)
            elif isinstance(v, list):
                clean[k] = [
                    Sanitizer.scan_result(item) if isinstance(item, dict) else item
                    for item in v
                ]
            else:
                clean[k] = v
        return clean

    @staticmethod
    def prompt(question: str, context: dict) -> str:
        """Build a sanitized prompt for cloud models."""
        clean_ctx = Sanitizer.scan_result(context) if context else {}
        ctx_str = json.dumps(clean_ctx, indent=2, ensure_ascii=False) if clean_ctx else ""
        return (
            "You are a reverse engineering assistant analyzing cryptographic algorithm matches.\n"
            f"Scan context:\n{ctx_str}\n\n"
            f"Question: {question}\n"
            "Answer concisely. If unsure, say 'cannot determine'."
        )
