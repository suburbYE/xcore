"""Measure the real knowledge-file <-> vector coverage.

The L1<->L3 check in test_memory_budget.py can only fail when some knowledge
file has no vector. If that set is empty by construction (e.g. the ref/naming
scheme never lines up), the check is decorative. This prints the actual counts
so "it passes" is distinguishable from "it compared nothing".

Run:  python scripts/check_l1_l3_coverage.py
"""
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from xchat.config import BASE_DIR  # noqa: E402

kdir = BASE_DIR / "knowledge"
prod = BASE_DIR / "state" / "memory.db"

names = {p.stem for p in kdir.glob("*.json")}
conn = sqlite3.connect(f"file:{prod}?mode=ro", uri=True)
try:
    rows = [r[0] for r in
            conn.execute("SELECT ref FROM vectors WHERE source='knowledge'")]
finally:
    conn.close()

refs16 = {r[:16] for r in rows}
print(f"knowledge/*.json files      : {len(names)}")
print(f"vector rows (source=knowledge): {len(rows)}")
print(f"distinct refs (16-char)     : {len(refs16)}")
print(f"files with no vector        : {len(names - refs16)} {sorted(names - refs16)[:5]}")
print(f"vectors with no file        : {len(refs16 - names)} {sorted(refs16 - names)[:5]}")
print(f"ref length sample           : {[len(r) for r in rows[:3]]}")
print()
if not (names - refs16):
    print("NOTE: every knowledge file already has a vector, so the 'unindexed'")
    print("      check is currently a guard for future edits, not a live signal.")
