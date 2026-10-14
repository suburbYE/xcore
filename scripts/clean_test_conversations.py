"""One-time cleanup: the empty test conversations the suites left behind.

`test_substrate.py` and `test_investigation.py` used to create conversations in
the real `state/agent.db` (now fixed at the source via tests/_isolate.py). The
rows they already wrote are indistinguishable in the UI from the user's own
work: same dropdown, same shape, except each opens a conversation with zero
turns and no explanation.

Deletes only rows that are provably residue -- titled "mutation" with zero
turns in the transcript -- and prints everything it removed, so the decision is
auditable rather than a silent DELETE.

Run:  python scripts/clean_test_conversations.py [--apply]
"""
from __future__ import annotations

import shutil
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from xchat.config import SESSIONS_DIR, STATE_DIR  # noqa: E402

AGENT_DB = STATE_DIR / "agent.db"
APPLY = "--apply" in sys.argv

# Title alone is not proof -- a user could name a conversation "mutation". The
# conjunction with "no transcript at all" is what makes it residue: a real
# conversation cannot have zero turns, because the first user message is
# written before the model is ever called.
RESIDUE_TITLE = "mutation"


def transcript_lines(conversation_id: str) -> int:
    path = SESSIONS_DIR / conversation_id / "transcript.jsonl"
    if not path.exists():
        return 0
    return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())


def main() -> int:
    if not AGENT_DB.exists():
        print(f"no {AGENT_DB}")
        return 0

    conn = sqlite3.connect(AGENT_DB)
    conn.row_factory = sqlite3.Row
    rows = [dict(r) for r in conn.execute(
        "SELECT id, title, turns, dir FROM conversations ORDER BY updated DESC")]

    print(f"conversations in {AGENT_DB}: {len(rows)}")
    targets: list[dict] = []
    for r in rows:
        lines = transcript_lines(r["id"])
        residue = (r["title"] or "") == RESIDUE_TITLE and lines == 0
        flag = "  <-- residue" if residue else ""
        print(f"  {r['id']}  title={r['title']!r:14} turns={r['turns']:>3} "
              f"transcript={lines}{flag}")
        if residue:
            targets.append(r)

    if not targets:
        print("\nnothing to remove")
        conn.close()
        return 0

    print(f"\n{len(targets)} residue conversation(s)")
    if not APPLY:
        print("dry run; re-run with --apply to delete")
        conn.close()
        return 0

    for r in targets:
        conn.execute("DELETE FROM conversations WHERE id = ?", (r["id"],))
        d = Path(r["dir"]) if r["dir"] else SESSIONS_DIR / r["id"]
        if d.exists():
            shutil.rmtree(d, ignore_errors=True)
            print(f"  removed row {r['id']} and {d}")
        else:
            print(f"  removed row {r['id']} (no dir at {d})")
    conn.commit()
    left = conn.execute("SELECT COUNT(*) FROM conversations").fetchone()[0]
    conn.close()
    print(f"\ndone; {left} conversation(s) remain")
    return 0


if __name__ == "__main__":
    sys.exit(main())
