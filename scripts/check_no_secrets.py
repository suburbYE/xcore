"""Refuse to commit credentials.

A backup commit is the one operation that can turn a local secret into a
permanent one: once a key is in git history it survives every later deletion.
So the check runs before the commit, not after.

Scans exactly what `git add` would stage: API-key shapes, private-key headers,
and the token file by name. Exit non-zero if anything matches.

Run:  python scripts/check_no_secrets.py
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Shapes, not exact keys: the value is unknown, the format is not.
PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("OpenAI/DeepSeek-style key", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}")),
    ("Google API key", re.compile(r"\bAIza[A-Za-z0-9_\-]{30,}")),
    ("private key header", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("bearer token literal", re.compile(r"\bBearer\s+[A-Za-z0-9_\-\.]{30,}")),
)

# Files whose mere presence in the index is the problem, regardless of content.
FORBIDDEN_NAMES = ("server_token", ".env")

# These are source modules that talk about keys; they must never hold one.
SOURCES = (".py", ".ts", ".svelte", ".js", ".json", ".md", ".bat", ".cpp", ".h", ".hpp")


def staged_paths() -> list[str]:
    # encoding= is not optional here. Without it subprocess decodes with the
    # locale codec, which on this machine is GBK -- and git's output contains
    # Chinese filenames, so the decode raised UnicodeDecodeError and the check
    # died instead of reporting. Same trap as the C++ side, where a non-UTF-8
    # string made `--json` abort: the failure is in the decoding, not the data.
    out = subprocess.run(["git", "add", "-An", "."], cwd=ROOT,
                         capture_output=True, text=True,
                         encoding="utf-8", errors="replace").stdout or ""
    paths = []
    for line in out.splitlines():
        m = re.match(r"\s*add '(.+)'", line)
        if m:
            paths.append(m.group(1))
    return paths


def main() -> int:
    paths = staged_paths()
    if not paths:
        print("nothing staged; nothing to check")
        return 0
    print(f"checking {len(paths)} path(s) that git would stage")

    findings: list[str] = []

    for rel in paths:
        p = ROOT / rel
        if p.name in FORBIDDEN_NAMES:
            findings.append(f"{rel}: file name is a credential store")
            continue
        if not p.is_file() or p.suffix.lower() not in SOURCES:
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for label, rx in PATTERNS:
            for m in rx.finditer(text):
                line = text[: m.start()].count("\n") + 1
                findings.append(f"{rel}:{line}: {label}: {m.group(0)[:24]}...")

    if findings:
        print("\nREFUSING TO COMMIT -- credential-shaped content found:")
        for f in findings:
            print(f"  {f}")
        print("\nIf a match is a documentation example, make it obviously fake "
              "(sk-EXAMPLE...) or move it out of the staged set.")
        return 1

    print("clean: no credential-shaped content in the staged set")
    return 0


if __name__ == "__main__":
    sys.exit(main())
