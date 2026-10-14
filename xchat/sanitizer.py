"""
Sanitizer: strips sensitive data before cloud upload.

Strips file paths → SHA-256 aliases, full hashes → truncated,
recursively cleans scan result dicts, and scrubs free-form text.
"""

import hashlib
import json
import re


class Sanitizer:
    # 自由文本里的敏感串：Windows 盘符路径 / UNC 共享 / 常见 POSIX 用户目录
    _PATH_RES = (
        re.compile(r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\?)+"),
        re.compile(r"\\\\[^\s\"']+"),
        re.compile(r"/(?:home|Users|root|mnt|opt|var|tmp|srv)/[^\s\"':;,)]+"),
    )
    # 完整哈希（MD5/SHA-1/SHA-256 及以上）
    _HASH_RE = re.compile(r"\b[0-9a-fA-F]{32,}\b")

    @staticmethod
    def file_path(path: str) -> str:
        return f"target_asset_{hashlib.sha256(path.encode()).hexdigest()[:8]}"

    @staticmethod
    def sha256(h: str) -> str:
        return h[:8] + "..."

    @staticmethod
    def text(s: str) -> str:
        """Scrub absolute paths and full hashes out of free-form text.

        ``scan_result`` only cleans dict *keys* it recognises; prompts are plain
        strings assembled upstream and can carry paths verbatim, so they need
        their own pass.
        """
        if not s:
            return s
        out = s
        for rx in Sanitizer._PATH_RES:
            out = rx.sub(lambda m: Sanitizer.file_path(m.group(0)), out)
        out = Sanitizer._HASH_RE.sub(lambda m: Sanitizer.sha256(m.group(0)), out)
        return out

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
            elif isinstance(v, str):
                clean[k] = Sanitizer.text(v)
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
            f"Question: {Sanitizer.text(question)}\n"
            "Answer concisely. If unsure, say 'cannot determine'."
        )
