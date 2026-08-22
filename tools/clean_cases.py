#!/usr/bin/env python
"""Case DB noise cleaner - removes low-confidence / junk cases."""
import sqlite3
import json
import sys
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "tools" / "cases.db"
MIN_SCAN_SIZE = 1024
MIN_CONFIDENCE = 0.7

# llm_confidence is stored as text: "high"/"medium"/"low"
CONFIDENCE_SCORE = {"high": 1.0, "medium": 0.5, "low": 0.3}

def confidence_ok(val):
    if val is None:
        return False
    score = CONFIDENCE_SCORE.get(val.strip().lower(), 0.0)
    return score >= MIN_CONFIDENCE

def cleanup(db_path: str):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    # ── Before stats ──
    before_count = conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
    print(f"Cases before cleanup: {before_count}")

    deleted = 0

    # 1. Low confidence (text field: high / medium / low / NULL)
    rows = conn.execute("SELECT id, file_path, llm_confidence FROM cases").fetchall()
    for r in rows:
        if not confidence_ok(r['llm_confidence']):
            print(f"  [LOW-CONF] #{r['id']} conf={r['llm_confidence']}  {r['file_path']}")
    conn.execute(
        "DELETE FROM cases WHERE llm_confidence IS NULL OR TRIM(LOWER(llm_confidence)) NOT IN ('high')"
    )

    # 2. Tiny files (empty / < 1KB)  
    rows = conn.execute(
        "SELECT id, file_path, file_size FROM cases WHERE file_size < ?",
        (MIN_SCAN_SIZE,)
    ).fetchall()
    for r in rows:
        print(f"  [TINY] #{r['id']} size={r['file_size']}  {r['file_path']}")
    conn.execute("DELETE FROM cases WHERE file_size < ?", (MIN_SCAN_SIZE,))

    # 3. Empty rules_hits
    rows = conn.execute(
        "SELECT id, file_path FROM cases WHERE rules_hits IS NULL OR rules_hits = '' OR rules_hits = '[]'"
    ).fetchall()
    for r in rows:
        print(f"  [EMPTY-HITS] #{r['id']}  {r['file_path']}")
    conn.execute("DELETE FROM cases WHERE rules_hits IS NULL OR rules_hits = '' OR rules_hits = '[]'")

    deleted_actual = before_count - conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
    conn.commit()

    # ── After stats ──
    after_count = conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
    print(f"\nDeleted: {deleted_actual}")
    print(f"Cases after cleanup: {after_count}")

    # Confidence distribution
    rows = conn.execute(
        "SELECT llm_confidence, COUNT(*) as cnt FROM cases GROUP BY llm_confidence ORDER BY llm_confidence"
    ).fetchall()
    print("\nConfidence distribution:")
    for r in rows:
        print(f"  {r['llm_confidence']}: {r['cnt']}")

    # Algorithm distribution
    rows = conn.execute("SELECT llm_algorithms FROM cases").fetchall()
    algo_count = {}
    for r in rows:
        try:
            algos = json.loads(r['llm_algorithms'])
            for a in algos:
                algo_count[a] = algo_count.get(a, 0) + 1
        except Exception:
            pass
    print("\nAlgorithm distribution:")
    for k, v in sorted(algo_count.items(), key=lambda x: -x[1]):
        print(f"  {k}: {v}")

    conn.close()

if __name__ == "__main__":
    cleanup(str(DB_PATH))
