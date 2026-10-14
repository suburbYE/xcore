"""End-to-end check of engine lifetime: resident vs. dies-with-window.

This cannot be proven by reading the code, because the two mechanisms that
decide it live outside the Python process entirely:

  * a Windows Job Object with KILL_ON_JOB_CLOSE, bound at spawn time, and
  * a Rust exit handler that must *not* run its stop path in resident mode.

Both are invisible to a unit test and both fail silently: a mis-bound job
object still looks like a working client until the next launch finds the
engine mysteriously gone. So this drives the real X-Core.exe and kills it the
way a user closes a window -- `taskkill` without /F posts WM_CLOSE, which is an
orderly exit and therefore exercises the Rust handler. A force-kill would skip
the handler and only test the job object.

Four claims are checked:

  1. resident=true  + window closed  -> engine survives
  2. relaunch                        -> adopts the same engine (pid unchanged)
  3. resident=false + window closed  -> engine dies
  4. explicit stop                   -> engine dies even in resident mode

Run:  python scripts/verify_resident.py
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
EXE = ROOT / "X-Core.exe"
STATE = ROOT / "state"
PREFS = STATE / "client.json"
PID_FILE = STATE / "server.pid"
PORT = 8787
HEALTH = f"http://127.0.0.1:{PORT}/api/health"

checks: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    checks.append((name, ok, detail))
    mark = "PASS" if ok else "FAIL"
    print(f"  [{mark}] {name}" + (f" -- {detail}" if detail else ""))


def healthy(timeout: float = 0.6) -> bool:
    try:
        with urllib.request.urlopen(HEALTH, timeout=timeout) as r:
            return r.status == 200
    except Exception:
        return False


def wait_healthy(seconds: float = 40.0) -> bool:
    end = time.time() + seconds
    while time.time() < end:
        if healthy():
            return True
        time.sleep(0.4)
    return False


def wait_down(seconds: float = 25.0) -> bool:
    end = time.time() + seconds
    while time.time() < end:
        if not healthy():
            return True
        time.sleep(0.4)
    return False


def engine_pid() -> int | None:
    """The engine's pid, taken from the file the engine itself writes."""
    if not PID_FILE.exists():
        return None
    try:
        return int(PID_FILE.read_text(encoding="utf-8").strip().split()[0])
    except Exception:
        return None


def alive(pid: int | None) -> bool:
    if pid is None:
        return False
    out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH"],
                         capture_output=True, text=True).stdout
    return str(pid) in out


def set_resident(on: bool) -> None:
    STATE.mkdir(exist_ok=True)
    data = {}
    if PREFS.exists():
        try:
            data = json.loads(PREFS.read_text(encoding="utf-8"))
        except Exception:
            data = {}
    data["resident"] = on
    PREFS.write_text(json.dumps(data, indent=2), encoding="utf-8")


def stop_engine() -> None:
    subprocess.run([sys.executable, "-m", "xchat.server", "--stop"],
                   cwd=ROOT, capture_output=True, text=True)


def launch() -> subprocess.Popen:
    p = subprocess.Popen([str(EXE)], cwd=ROOT)
    if not wait_healthy():
        raise RuntimeError("engine never became healthy after launching X-Core.exe")
    return p


def close_window(p: subprocess.Popen) -> None:
    """Graceful close: WM_CLOSE, i.e. the user clicking the X."""
    subprocess.run(["taskkill", "/PID", str(p.pid)], capture_output=True)
    try:
        p.wait(timeout=20)
    except subprocess.TimeoutExpired:
        subprocess.run(["taskkill", "/F", "/PID", str(p.pid)], capture_output=True)
        p.wait(timeout=10)


def main() -> int:
    if not EXE.exists():
        print(f"missing {EXE}; run build-client.bat first")
        return 2

    print("cleaning up any previous engine / client")
    stop_engine()
    subprocess.run(["taskkill", "/F", "/IM", "X-Core.exe"], capture_output=True)
    time.sleep(1.5)

    try:
        # ── 1 + 2: resident survives a window close, and is adopted back ──
        print("\n== resident=true ==")
        set_resident(True)
        c1 = launch()
        pid1 = engine_pid()
        check("resident engine started", pid1 is not None and alive(pid1),
              f"engine pid={pid1}")
        # Give the client long enough to actually bind (or skip) the job object
        # before the close, so a race cannot masquerade as a pass.
        time.sleep(2.0)

        close_window(c1)
        time.sleep(3.0)
        check("window closed", not alive(c1.pid), f"client pid={c1.pid}")
        check("engine survived window close (resident)", alive(pid1),
              f"engine pid={pid1} alive={alive(pid1)}")
        check("engine still answers HTTP", healthy())

        print("\n== relaunch adopts the running engine ==")
        c2 = launch()
        pid2 = engine_pid()
        check("same engine adopted, not restarted", pid1 == pid2,
              f"before={pid1} after={pid2}")
        time.sleep(1.5)
        close_window(c2)
        time.sleep(3.0)
        check("engine survived the second close", alive(pid1), f"pid={pid1}")

        # ── 4: explicit stop works on an engine this window did not spawn ──
        print("\n== explicit stop (engine is not owned by any window now) ==")
        c3 = launch()
        time.sleep(1.0)
        subprocess.run([sys.executable, "-m", "xchat.server", "--stop"],
                       cwd=ROOT, capture_output=True, text=True)
        check("explicit stop takes the engine down", wait_down(),
              "engine no longer answering")
        check("pid file cleared", engine_pid() is None or not alive(engine_pid()),
              f"pid file -> {engine_pid()}")
        try:
            c3.wait(timeout=8)
        except subprocess.TimeoutExpired:
            subprocess.run(["taskkill", "/F", "/PID", str(c3.pid)],
                           capture_output=True)
            c3.wait(timeout=10)

        # ── 3: non-resident dies with the window ──
        print("\n== resident=false ==")
        set_resident(False)
        c4 = launch()
        pid4 = engine_pid()
        check("non-resident engine started", pid4 is not None and alive(pid4),
              f"engine pid={pid4}")
        time.sleep(2.0)
        close_window(c4)
        check("engine died with the window", wait_down(seconds=20),
              f"engine pid={pid4} alive={alive(pid4)}")
        check("non-resident engine really gone", not alive(pid4),
              f"alive={alive(pid4)}")

    finally:
        print("\ncleanup: restoring resident=true and stopping the engine")
        stop_engine()
        subprocess.run(["taskkill", "/F", "/IM", "X-Core.exe"], capture_output=True)
        set_resident(True)

    failed = [n for n, ok, _ in checks if not ok]
    print(f"\n{len(checks) - len(failed)}/{len(checks)} PASS"
          + (f", FAILED: {failed}" if failed else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
