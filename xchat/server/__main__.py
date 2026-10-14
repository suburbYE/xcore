"""
Local API server — the GUI's only entry point into the kernel channel.

    python -m xchat.server            # 127.0.0.1:8787, foreground
    python -m xchat.server --stop     # stop a running one (resident or not)
    python -m xchat.server --status   # is one running, and where is its log

Loopback-only by design: this process holds the API keys.

**Resident mode.** Normally the GUI starts this as a child that dies with it.
With `--resident` (or when the client is configured that way) the process is
started detached and keeps running after the window closes — the point being
that a scan or an investigation does not stop because someone closed a window.
A pid file makes it findable again, and `/api/shutdown` makes it stoppable
without hunting for a process id.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from ..config import STATE_DIR

PID_FILE = STATE_DIR / "server.pid"


def _read_pid() -> int | None:
    try:
        return int(PID_FILE.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


def _alive(host: str, port: int) -> bool:
    try:
        with urllib.request.urlopen(f"http://{host}:{port}/api/health",
                                    timeout=2) as r:
            return json.loads(r.read()).get("ok") is True
    except Exception:
        return False


def _token() -> str:
    try:
        return (STATE_DIR / "server_token").read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def stop(host: str, port: int) -> int:
    """Ask a running server to shut down, then confirm it went.

    Graceful first: killing mid-write would leave the SQLite databases to
    recover on next open, and a truncated transcript line is exactly what the
    JSONL reader tolerates but nobody wants to produce on purpose.
    """
    if not _alive(host, port):
        print(f"  no server answering on {host}:{port}")
        PID_FILE.unlink(missing_ok=True)
        return 0
    pid = _read_pid()
    body = json.dumps({}).encode()
    req = urllib.request.Request(
        f"http://{host}:{port}/api/shutdown", data=body, method="POST",
        headers={"X-XCore-Token": _token(), "Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=10).read()
    except urllib.error.HTTPError as e:
        print(f"  shutdown refused: HTTP {e.code} "
              f"(token mismatch? state/server_token)")
        return 1
    except Exception as e:  # noqa: BLE001 - connection death is a valid outcome
        print(f"  shutdown request ended: {e}")
    for _ in range(40):
        time.sleep(0.25)
        if not _alive(host, port):
            PID_FILE.unlink(missing_ok=True)
            print(f"  stopped (pid {pid})")
            return 0
    print(f"  [!] still answering after 10s; pid {pid} may need killing by hand")
    return 1


def status(host: str, port: int) -> int:
    pid = _read_pid()
    up = _alive(host, port)
    print(f"  url       : http://{host}:{port}")
    print(f"  answering : {up}")
    print(f"  pid file  : {pid if pid else '(none)'}")
    log = STATE_DIR / "server.log"
    print(f"  log       : {log if log.exists() else '(none)'}")
    return 0 if up else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="xchat.server",
        description="X-Core local API server (capability channel over HTTP/WS)",
    )
    parser.add_argument("--host", default="127.0.0.1",
                        help="bind address (default loopback only)")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--reload", action="store_true", help="dev auto-reload")
    parser.add_argument("--print-routes", action="store_true",
                        help="list routes and exit")
    parser.add_argument("--resident", action="store_true",
                        help="log to state/server.log and write a pid file "
                             "(implied when started detached by the client)")
    parser.add_argument("--stop", action="store_true",
                        help="stop a running server and exit")
    parser.add_argument("--status", action="store_true",
                        help="report whether a server is running, and exit")
    args = parser.parse_args(argv)

    if args.print_routes:
        from .app import routes
        for r in routes:
            methods = ",".join(sorted(getattr(r, "methods", []) or [])) or "WS"
            print(f"  {methods:<10} {r.path}")
        return 0

    if args.stop:
        return stop(args.host, args.port)
    if args.status:
        return status(args.host, args.port)

    if _alive(args.host, args.port):
        # Two servers on one port is never what anyone meant; the second would
        # fail to bind anyway, and failing here says why.
        print(f"  a server is already answering on {args.host}:{args.port}")
        print(f"  stop it with: python -m xchat.server --stop")
        return 1

    try:
        import uvicorn
    except ImportError:
        print("uvicorn is required to run the server (pip install uvicorn)",
              file=sys.stderr)
        return 1

    from .app import app

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    PID_FILE.write_text(str(os.getpid()), encoding="utf-8")
    try:
        uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    finally:
        # Only remove the pid file if it is still ours: a restart may have
        # written a newer one before this process finished shutting down.
        if _read_pid() == os.getpid():
            PID_FILE.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
