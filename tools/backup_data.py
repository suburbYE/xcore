"""Data-safety utility: back up every core data asset with integrity proof.

The knowledge store, the case databases and the rule library are the parts of
this project that cannot be regenerated. Everything here is read-only w.r.t.
the originals.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BACKUP_ROOT = ROOT / "state" / "backups"

# Each backup contains a full copy of the knowledge store and the case DB, so
# the directory grows by a few MB per run. Keep the recent ones and prune the
# rest, newest first — an unbounded backup directory is its own kind of mess.
KEEP_BACKUPS = 5

# (path, label) — the assets that matter
ASSETS = [
    ("tools/cases.db", "case database"),
    ("tools/cases_clean.db", "case database (cleaned)"),
    ("state/usage.db", "usage ledger"),
    ("state/memory.db", "memory index (derived, rebuilt from L1/L2)"),
    ("rules/rules.json", "rule set"),
    ("knowledge", "knowledge store (memory L1)"),
    ("rules/fingerprints", "fingerprint library"),
    (".xchat_session.json", "session state"),
]


def prune(dest: Path, keep: int = KEEP_BACKUPS) -> list[str]:
    """Delete all but the newest `keep` backup directories."""
    if not BACKUP_ROOT.exists():
        return []
    dirs = sorted((d for d in BACKUP_ROOT.iterdir() if d.is_dir()),
                  key=lambda d: d.name, reverse=True)
    removed = []
    for d in dirs[keep:]:
        try:
            shutil.rmtree(d)
            removed.append(d.name)
        except Exception:
            pass
    return removed


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def tree_digest(d: Path) -> tuple[int, str]:
    """(file count, combined digest) for a directory, order-independent."""
    h = hashlib.sha256()
    files = sorted(p for p in d.rglob("*") if p.is_file())
    for p in files:
        h.update(p.relative_to(d).as_posix().encode())
        h.update(sha256_file(p).encode())
    return len(files), h.hexdigest()


def check_sqlite(p: Path) -> str:
    try:
        con = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
        r = con.execute("PRAGMA integrity_check").fetchone()[0]
        con.close()
        return r
    except Exception as e:
        return f"ERROR {e}"


def main() -> int:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    dest = BACKUP_ROOT / stamp
    dest.mkdir(parents=True, exist_ok=True)

    manifest = {"created": stamp, "root": str(ROOT), "assets": []}
    problems = []

    print(f"backing up -> {dest}")
    for rel, label in ASSETS:
        src = ROOT / rel
        if not src.exists():
            print(f"  {rel:<28} ABSENT (skipped)")
            continue

        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)

        if src.is_dir():
            shutil.copytree(src, target, dirs_exist_ok=True)
            count, digest = tree_digest(src)
            entry = {"path": rel, "label": label, "kind": "dir",
                     "files": count, "digest": digest}
            print(f"  {rel:<28} dir   {count:>4} files  {digest[:16]}")
        else:
            shutil.copy2(src, target)
            digest = sha256_file(src)
            entry = {"path": rel, "label": label, "kind": "file",
                     "bytes": src.stat().st_size, "digest": digest}
            extra = ""
            if src.suffix == ".db":
                ok = check_sqlite(src)
                entry["integrity"] = ok
                extra = f" integrity={ok}"
                if ok != "ok":
                    problems.append(f"{rel}: {ok}")
            print(f"  {rel:<28} file  {src.stat().st_size:>8} B  "
                  f"{digest[:16]}{extra}")

        manifest["assets"].append(entry)

    (dest / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    print()
    if problems:
        print("  !! INTEGRITY PROBLEMS:")
        for p in problems:
            print(f"     {p}")
    else:
        print("  all sqlite databases: integrity ok")

    pruned = prune(dest)
    if pruned:
        print(f"  pruned {len(pruned)} old backup(s), keeping {KEEP_BACKUPS}: "
              f"{', '.join(pruned)}")
    remaining = len([d for d in BACKUP_ROOT.iterdir() if d.is_dir()])
    print(f"  backups retained: {remaining}")

    print(f"\n  manifest: {dest / 'manifest.json'}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
