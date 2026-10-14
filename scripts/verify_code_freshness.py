"""Can the engine tell that it is running stale code?

The failure this guards against is silent by construction. Editing a .py file
while the engine runs changes nothing in that process, and the observable
result is the *previous* behaviour — which looks exactly like a fix that did
not work. That is how a correct policy fix was reported as still failing: the
engine had loaded `policy.py` before the edit.

So the detector itself needs a negative control: it must say "fresh" when
nothing changed, and "stale" when something did. A detector that always answers
"stale" would get ignored, and one that always answers "fresh" is the bug.

Run:  python scripts/verify_code_freshness.py
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from xchat.kernel import freshness  # noqa: E402

checks: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    checks.append((name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""))


def health() -> dict | None:
    try:
        with urllib.request.urlopen("http://127.0.0.1:8787/api/health", timeout=1.5) as r:
            return json.loads(r.read())
    except Exception:
        return None


def main() -> int:
    print("== the detector, in isolation ==")
    # A process that started now, with no edit since, must read as fresh.
    now = time.time()
    s = freshness.staleness(now)
    check("a just-started process is fresh", s["stale"] is False, s["detail"])
    check("it names the newest watched source", bool(s["newest_source"]),
          s["newest_source"])

    # A process that started before the newest source must read as stale.
    old = now - 10_000
    s_old = freshness.staleness(old)
    check("a process older than the newest source is stale", s_old["stale"] is True,
          s_old["detail"][:80])

    # The two answers must differ, or the detector is constant and useless.
    check("the detector can answer both ways",
          s["stale"] != s_old["stale"],
          f"fresh={s['stale']} stale={s_old['stale']}")

    print("\n== the live engine reports it ==")
    subprocess.run([sys.executable, "-m", "xchat.server", "--stop"],
                   cwd=ROOT, capture_output=True)
    time.sleep(1.0)
    subprocess.Popen([sys.executable, "-m", "xchat.server", "--resident"],
                     cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    h = None
    for _ in range(80):
        h = health()
        if h:
            break
        time.sleep(0.5)
    if not h:
        check("engine came up", False, "never answered /api/health")
        return 1
    check("engine came up", True)
    check("/api/health carries a `code` block", "code" in h, str(sorted(h))[:80])

    code = h.get("code") or {}
    check("a freshly started engine reports fresh code", code.get("stale") is False,
          str(code.get("detail"))[:80])

    # The case the user actually hit: edit a source file under the running
    # engine and ask again. `rules/` is watched but is data, so touching a
    # rules file must not be ignored either.
    target = ROOT / "rules" / "policy.json"
    original = target.read_bytes() if target.exists() else None
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((original or b"{}"))
        time.sleep(0.4)
        h2 = health() or {}
        code2 = h2.get("code") or {}
        check("a source edit under a running engine is reported as stale",
              code2.get("stale") is True, str(code2.get("detail"))[:80])
        check("it names the edited file",
              "policy.json" in str(code2.get("newest_source", "")),
              str(code2.get("newest_source")))
    finally:
        if original is not None:
            target.write_bytes(original)

    subprocess.run([sys.executable, "-m", "xchat.server", "--stop"],
                   cwd=ROOT, capture_output=True)

    failed = [n for n, ok, _ in checks if not ok]
    print(f"\n{len(checks) - len(failed)}/{len(checks)} PASS"
          + (f", FAILED: {failed}" if failed else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
