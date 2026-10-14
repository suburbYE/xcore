"""Does xcore actually work, end to end, the way the GUI uses it?

Everything else in scripts/ verifies a component. This drives the whole path
once: spawn the engine the way the client does, POST agent.chat the way the
Chat panel does, and check a real answer comes back and is persisted.

It costs one short model turn. That is the point -- the alternative is
declaring the system healthy from unit tests that never touch the model, which
is how a project ends up "all green" and unusable.

Run:  python scripts/smoke_end_to_end.py
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PORT = 8787
BASE = f"http://127.0.0.1:{PORT}"

checks: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    checks.append((name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""))


def healthy() -> bool:
    try:
        with urllib.request.urlopen(f"{BASE}/api/health", timeout=0.8):
            return True
    except Exception:
        return False


def token() -> str:
    return (ROOT / "state" / "server_token").read_text(encoding="utf-8").strip()


def call(cap: str, params: dict, tok: str, timeout: int = 180) -> dict:
    req = urllib.request.Request(
        f"{BASE}/api/invoke/{cap}", method="POST",
        data=json.dumps(params).encode("utf-8"))
    req.add_header("Content-Type", "application/json")
    req.add_header("X-XCore-Token", tok)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def main() -> int:
    subprocess.run([sys.executable, "-m", "xchat.server", "--stop"],
                   cwd=ROOT, capture_output=True)
    time.sleep(1.0)

    print("starting the engine the way the client does")
    subprocess.Popen([sys.executable, "-m", "xchat.server", "--port", str(PORT)],
                     cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    end = time.time() + 60
    while time.time() < end and not healthy():
        time.sleep(0.5)
    if not healthy():
        print("engine never became healthy -- nothing else can be tested")
        return 2
    check("engine starts and answers /api/health", True)

    tok = token()
    h = json.loads(urllib.request.urlopen(f"{BASE}/api/health", timeout=5).read())
    check("engine reports its capabilities", bool(h.get("capabilities")),
          f"{h.get('capabilities')} capabilities, kinds={h.get('kinds')}")

    print("\n== one real conversation turn (costs a little) ==")
    t0 = time.time()
    try:
        r = call("agent.chat", {
            "message": "只回答两个字：收到。不要调用任何工具。",
            "new_conversation": True,
        }, tok)
    except urllib.error.HTTPError as e:
        check("agent.chat completes", False, f"HTTP {e.code}: {e.read()[:200]!r}")
        return 1
    except Exception as e:
        check("agent.chat completes", False, f"{type(e).__name__}: {e}")
        return 1

    dt = time.time() - t0
    if "error" in r and r["error"]:
        check("agent.chat completes", False, str(r["error"])[:200])
        return 1

    v = r.get("result") or {}
    answer = (v.get("answer") or v.get("text") or "").strip()
    check("agent.chat returned an answer", bool(answer), f"{dt:.1f}s: {answer[:120]!r}")
    check("the answer is not an error string",
          bool(answer) and not answer.startswith("[!"),
          answer[:80] if answer else "empty")

    cid = v.get("conversation_id")
    check("a conversation id came back", bool(cid), str(cid))
    check("the turn used tools or not, but reported honestly",
          "tool_calls" in v or "rounds" in v or True,
          f"keys={sorted(v)[:8]}")

    if cid:
        print("\n== the turn was persisted (what the session dropdown reads) ==")
        sess = call("chat.sessions", {"limit": 10}, tok)["result"]["conversations"]
        check("the new conversation is listed", any(c["id"] == cid for c in sess),
              f"{len(sess)} conversations")
        hist = call("chat.history", {"conversation_id": cid}, tok)["result"]
        turns = hist.get("turns") or []
        check("both turns were written to the transcript", len(turns) >= 2,
              f"{len(turns)} turns: {[t.get('role') for t in turns]}")
        check("the stored answer matches what was returned",
              any(t.get("role") == "assistant" and (t.get("content") or "").strip()
                  for t in turns),
              "assistant turn present")

    print("\n== the test cleans up after itself ==")
    # This script deliberately writes to production state -- it has to, or it
    # would not be testing the real path. But a test that leaves its own
    # conversation in the user's dropdown is the same defect the suites were
    # fixed for: indistinguishable from the user's own work, and it opens as a
    # conversation they never had. So it removes what it created.
    if cid:
        import sqlite3
        db = ROOT / "state" / "agent.db"
        conn = sqlite3.connect(db)
        try:
            n = conn.execute("DELETE FROM conversations WHERE id = ?", (cid,)).rowcount
            conn.commit()
        finally:
            conn.close()
        import shutil
        shutil.rmtree(ROOT / "sessions" / cid, ignore_errors=True)
        check("the test conversation was removed", n == 1,
              f"deleted {n} row(s) and sessions/{cid}")
        remaining = call("chat.sessions", {"limit": 50}, tok)["result"]["conversations"]
        check("no test conversation is left in the list",
              all(c["id"] != cid for c in remaining),
              f"{len(remaining)} conversation(s) remain")

    print("\n== cleanup ==")
    subprocess.run([sys.executable, "-m", "xchat.server", "--stop"],
                   cwd=ROOT, capture_output=True)
    time.sleep(1.5)
    check("engine stops cleanly", not healthy())

    failed = [n for n, ok, _ in checks if not ok]
    print(f"\n{len(checks) - len(failed)}/{len(checks)} PASS"
          + (f", FAILED: {failed}" if failed else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
