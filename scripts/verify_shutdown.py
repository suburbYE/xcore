"""Check the primitive behind the "停止后台引擎" button.

The button does not call Python's `--stop`; for an engine it did not spawn it
POSTs /api/shutdown with the shell's token. That is a different path with a
different failure mode (auth), and the interesting case is the adopted engine:
if the token check is wrong, the one control that can shut down a resident
engine silently does nothing and the user is left with a daemon.

Both halves are asserted, because "it stops the engine" is only half a
contract — an unauthenticated endpoint that stops the engine is worse than one
that does not.

Run:  python scripts/verify_shutdown.py
"""
from __future__ import annotations

import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOKEN_FILE = ROOT / "state" / "server_token"
PORT = 8787
URL = f"http://127.0.0.1:{PORT}/api/shutdown"

checks: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    checks.append((name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""))


def healthy() -> bool:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/api/health", timeout=0.6) as r:
            return r.status == 200
    except Exception:
        return False


def wait_down(seconds: float = 20.0) -> bool:
    end = time.time() + seconds
    while time.time() < end:
        if not healthy():
            return True
        time.sleep(0.4)
    return False


def post(token: str | None) -> tuple[int | None, str]:
    req = urllib.request.Request(URL, method="POST", data=b"")
    if token is not None:
        req.add_header("X-XCore-Token", token)
    try:
        with urllib.request.urlopen(req, timeout=6) as r:
            return r.status, r.read(200).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(200).decode("utf-8", "replace")
    except Exception as e:  # connection died without a reply
        return None, repr(e)


def main() -> int:
    subprocess.run([sys.executable, "-m", "xchat.server", "--stop"],
                   cwd=ROOT, capture_output=True)
    subprocess.run(["taskkill", "/F", "/IM", "X-Core.exe"], capture_output=True)
    time.sleep(1.0)

    print("starting a resident engine the way the client does")
    subprocess.Popen([sys.executable, "-m", "xchat.server", "--resident"],
                     cwd=ROOT,
                     creationflags=0x00000008 | 0x00000200 | 0x08000000,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     stdin=subprocess.DEVNULL)
    deadline = time.time() + 40
    while time.time() < deadline and not healthy():
        time.sleep(0.4)
    if not healthy():
        print("engine never came up")
        return 2

    token = TOKEN_FILE.read_text(encoding="utf-8").strip()
    check("token file readable", len(token) > 0, f"{len(token)} chars")

    print("\n== unauthenticated shutdown must be refused ==")
    code, body = post(None)
    check("no token -> rejected", code in (401, 403), f"HTTP {code} {body[:80]}")
    check("engine still running after the refusal", healthy())

    print("\n== wrong token must be refused ==")
    code, body = post("0" * len(token))
    check("bad token -> rejected", code in (401, 403), f"HTTP {code} {body[:80]}")
    check("engine still running after the refusal", healthy())

    print("\n== the real token stops it ==")
    code, body = post(token)
    check("valid token -> accepted", code is not None and code < 300,
          f"HTTP {code} {body[:80]}")
    check("engine went down", wait_down(), "no longer answering /api/health")

    subprocess.run([sys.executable, "-m", "xchat.server", "--stop"],
                   cwd=ROOT, capture_output=True)
    failed = [n for n, ok, _ in checks if not ok]
    print(f"\n{len(checks) - len(failed)}/{len(checks)} PASS"
          + (f", FAILED: {failed}" if failed else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
