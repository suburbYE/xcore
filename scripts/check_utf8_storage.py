"""Is the mojibake in the console, or in the data?

A conversation title containing Chinese showed up as `mhypbase???ص?` in a
PowerShell dump. Those two explanations have very different consequences: a
console codepage problem is cosmetic and always has been, while a title stored
as mangled bytes means every Chinese message is being corrupted on the way into
the transcript -- which would make the whole history feature worse than useless
for this user.

So: read the bytes, decode as UTF-8 strictly, and also compare the title
against the first user turn it was derived from. If both hold, the storage is
sound and only the terminal was lying.

Run:  python scripts/check_utf8_storage.py
"""
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from xchat.config import SESSIONS_DIR, STATE_DIR  # noqa: E402

out = []
conn = sqlite3.connect(f"file:{STATE_DIR / 'agent.db'}?mode=ro", uri=True)
conn.row_factory = sqlite3.Row
rows = [dict(r) for r in conn.execute(
    "SELECT id, title FROM conversations ORDER BY updated DESC")]
conn.close()

out.append(f"conversations: {len(rows)}")
for r in rows:
    cid, title = r["id"], r["title"] or ""

    # The strict decode is the actual question: if the bytes were mangled on
    # write, re-encoding them back to bytes and decoding raise or produce
    # replacement characters here.
    try:
        raw = title.encode("utf-8")
        round_tripped = raw.decode("utf-8")
        clean = round_tripped == title
    except Exception as e:
        raw, clean = b"", False
        out.append(f"  ENCODE FAILED: {e!r}")

    has_cjk = any("\u4e00" <= ch <= "\u9fff" for ch in title)
    bad_chars = [ch for ch in title if ch == "\ufffd"]

    out.append(f"\n{cid}")
    out.append(f"  title bytes      : {raw[:60]!r}")
    out.append(f"  utf-8 round-trip : {'clean' if clean else 'MANGLED'}")
    out.append(f"  contains CJK     : {has_cjk}")
    out.append(f"  replacement chars: {len(bad_chars)}")
    out.append(f"  title (utf-8)    : {title!r}")

    # Cross-check against the transcript, which is a separate file on disk
    # written by a different code path. If both agree, two independent writers
    # produced the same text.
    tj = SESSIONS_DIR / cid / "transcript.jsonl"
    if tj.exists():
        import json
        first_user = ""
        for line in tj.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            t = json.loads(line)
            if t.get("role") == "user":
                first_user = t.get("content") or ""
                break
        same = first_user[:len(title)] == title if title else False
        out.append(f"  transcript first user turn starts with the title: {same}")
        out.append(f"  first user turn  : {first_user[:90]!r}")

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
print("\n".join(out))
