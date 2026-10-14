"""Confirm the HTTP envelope the Chat panel now reads actually has that shape.

The panel was calling `api(...)` (a leftover from the old module) and reading
`r.value`. `api` is an object, so the call threw, and the `catch` turned the
throw into `sessions = []` / `turns = []`. That reads as "you have no past
conversations" — wrong and unactionable.

Fixing it to `api.invoke(...)` only helps if the response really carries
`result.conversations` and `result.turns`. That is the server's business, not
the client's, so ask the server.

Run:  python scripts/verify_chat_api.py
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOKEN = (ROOT / "state" / "server_token")
PORT = 8787

checks: list[tuple[str, bool, str]] = []
skips: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    checks.append((name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""))


def skip(name: str, why: str) -> None:
    """Record a check that could not run. Never counted as a pass: an
    unrun check and a passing check look identical in a tally, and that
    is exactly the confusion this script exists to avoid."""
    skips.append(name)
    print(f"  [SKIP] {name} -- {why}")


def healthy() -> bool:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/api/health", timeout=0.6):
            return True
    except Exception:
        return False


def invoke(cap: str, params: dict, token: str) -> dict:
    req = urllib.request.Request(
        f"http://127.0.0.1:{PORT}/api/invoke/{cap}",
        method="POST", data=json.dumps(params).encode())
    req.add_header("Content-Type", "application/json")
    req.add_header("X-XCore-Token", token)
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read().decode("utf-8"))


def main() -> int:
    if not healthy():
        print("engine not running; start it first")
        return 2
    token = TOKEN.read_text(encoding="utf-8").strip()

    print("== chat.sessions (the session dropdown) ==")
    r = invoke("chat.sessions", {"limit": 40}, token)
    check("envelope has `result`", "result" in r, f"keys={sorted(r)}")
    convs = r.get("result", {}).get("conversations")
    check("result.conversations is a list", isinstance(convs, list),
          f"type={type(convs).__name__}")
    check("at least one conversation exists", bool(convs), f"n={len(convs or [])}")
    if convs:
        c = convs[0]
        check("row carries id", bool(c.get("id")), str(c.get("id")))
        check("row carries title+turns for the label",
              "title" in c and "turns" in c, f"title={c.get('title')!r} turns={c.get('turns')}")
        # The panel renders `s.workspace?.scripts` and shows `workspace.dir`.
        check("row carries workspace summary", isinstance(c.get("workspace"), dict),
              str(c.get("workspace"))[:90])

    print("\n== chat.history (loading a conversation back) ==")
    cid = (convs or [{}])[0].get("id")
    if not cid:
        # Not a pass and not a failure: with no conversations there is nothing
        # to read back. Saying so is the point -- a green check here would mean
        # "the empty case works", which is not what this claims to test.
        skip("chat.history round-trip",
             "no conversations yet; chat once in the GUI then re-run")
    else:
        h = invoke("chat.history", {"conversation_id": cid}, token)
        res = h.get("result", {})
        check("result.conversation_id echoes the request",
              res.get("conversation_id") == cid, f"{res.get('conversation_id')}")
        check("result.turns is a list", isinstance(res.get("turns"), list),
              f"n={len(res.get('turns') or [])}")
        turns = res.get("turns") or []
        check("turns are non-empty for a real conversation", bool(turns), f"n={len(turns)}")
        if turns:
            t = turns[0]
            check("turn has role + content", "role" in t and "content" in t,
                  f"role={t.get('role')} len={len(t.get('content') or '')}")
            # The panel assigns `text: t.content ?? ""`; a turn stored without
            # content would render as an empty bubble with no explanation.
            check("no turn has null content",
                  all(x.get("content") is not None for x in turns))

        print("\n== chat.history with no id falls back to the latest ==")
        h2 = invoke("chat.history", {}, token)
        r2 = h2.get("result", {})
        check("empty id resolves to a real conversation", bool(r2.get("conversation_id")),
              str(r2.get("conversation_id")))

    print("\n== agent.chat accepts the params the panel sends ==")
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}/api/capabilities/agent.chat")
    req.add_header("X-XCore-Token", token)
    with urllib.request.urlopen(req, timeout=30) as r:
        spec = json.loads(r.read().decode("utf-8"))
    props = set((spec.get("params") or {}).get("properties") or {})
    for name in ("message", "backend", "conversation_id", "new_conversation"):
        check(f"agent.chat accepts `{name}`", name in props, f"props={sorted(props)}")

    failed = [n for n, ok, _ in checks if not ok]
    summary = (f"\n{len(checks) - len(failed)}/{len(checks)} PASS"
               + (f", FAILED: {failed}" if failed else ""))
    if skips:
        summary += f", {len(skips)} SKIPPED: {skips}"
    print(summary)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
