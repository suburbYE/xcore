"""Verify the tray behaviour: what the X button does, in each mode.

The tray *icon* cannot be clicked by a script -- it lives in the shell's
notification area, not in the app. But the decision the icon exists to serve is
fully testable, because it is made by the window's close handler:

    close_to_tray = true   ->  X hides the window, process and engine continue
    close_to_tray = false  ->  X destroys the window, process and engine stop

So this posts a real WM_CLOSE to the real window of the real X-Core.exe, which
is exactly what clicking X does, and then checks three things that must all
hold at once: the client survived, the *window* is actually hidden (not merely
alive behind a visible window), and the engine is still answering.

It also covers the migration from the old single-field prefs file. That file
meant "keep running after the window closes" and was persisted as
`resident: true`; carrying it across literally would detach the engine, and
then quitting from the tray would orphan a process holding port 8787. The last
section proves the legacy file is translated rather than copied, by force
killing the client: with no job object bound the engine survives, with one
bound it dies.

Run:  python scripts/verify_tray.py
"""
from __future__ import annotations

import ctypes
import json
import subprocess
import sys
import time
import urllib.request
from ctypes import wintypes
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXE = ROOT / "X-Core.exe"
STATE = ROOT / "state"
PREFS = STATE / "client.json"
CLIENT_LOG = STATE / "client.log"
PORT = 8787
HEALTH = f"http://127.0.0.1:{PORT}/api/health"

user32 = ctypes.WinDLL("user32", use_last_error=True)
user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
user32.PostMessageW.restype = wintypes.BOOL
user32.IsWindowVisible.argtypes = [wintypes.HWND]
user32.IsWindowVisible.restype = wintypes.BOOL
user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
user32.GetWindowTextLengthW.restype = ctypes.c_int
user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
user32.GetWindowTextW.restype = ctypes.c_int
user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
user32.GetWindowThreadProcessId.restype = wintypes.DWORD
user32.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
user32.GetClassNameW.restype = ctypes.c_int
# EnumWindows takes a C function pointer, not a Python callable: the callback
# has to be wrapped in the actual WinFunctionType or ctypes refuses the call.
WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
user32.EnumWindows.argtypes = [WNDENUMPROC, wintypes.LPARAM]
user32.EnumWindows.restype = wintypes.BOOL

WM_CLOSE = 0x0010

checks: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    checks.append((name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""))


def healthy(timeout: float = 0.6) -> bool:
    try:
        with urllib.request.urlopen(HEALTH, timeout=timeout) as r:
            return r.status == 200
    except Exception:
        return False


def wait_healthy(seconds: float = 45.0) -> bool:
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


def alive(pid: int | None) -> bool:
    if pid is None:
        return False
    out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH"],
                         capture_output=True, text=True).stdout
    return str(pid) in out


def engine_pid() -> int | None:
    f = STATE / "server.pid"
    if not f.exists():
        return None
    try:
        return int(f.read_text(encoding="utf-8").strip().split()[0])
    except Exception:
        return None


def write_prefs(**fields) -> None:
    STATE.mkdir(exist_ok=True)
    PREFS.write_text(json.dumps(fields, indent=2), encoding="utf-8")


def read_prefs() -> dict:
    try:
        return json.loads(PREFS.read_text(encoding="utf-8"))
    except Exception:
        return {}


def log_from() -> int:
    """Byte offset of the current end of client.log, so a run reads only
    its own lines. 'TRAY BUILD FAILED' from an earlier attempt must not be
    read as this attempt's failure -- same for a stale 'hidden to tray'."""
    if not CLIENT_LOG.exists():
        return 0
    return CLIENT_LOG.stat().st_size


def log_since(offset: int) -> str:
    if not CLIENT_LOG.exists():
        return ""
    with CLIENT_LOG.open("rb") as fh:
        fh.seek(offset)
        return fh.read().decode("utf-8", "replace")


def main_window(pid: int, *, visible_only: bool = True) -> int:
    """The process's real top-level window, or 0.

    Not simply "the first window owned by the pid": Tauri and WebView2 create
    several hidden helper windows, and ctypes enumeration order is not
    specified. Picking one of those would make `IsWindowVisible` report False
    before anything was closed, and every close assertion would pass for the
    wrong reason. So match on the title the app actually sets, and fall back to
    "first visible" only if the title changes.
    """
    found: list[tuple[int, bool, str]] = []

    def cb(hwnd, _):
        wpid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(wpid))
        if wpid.value != pid:
            return True
        n = user32.GetWindowTextLengthW(hwnd)
        buf = ctypes.create_unicode_buffer(n + 1)
        user32.GetWindowTextW(hwnd, buf, n + 1)
        found.append((hwnd, bool(user32.IsWindowVisible(hwnd)), buf.value))
        return True

    user32.EnumWindows(WNDENUMPROC(cb), 0)

    titled = [h for h, _, t in found if t == "X-Core"]
    if titled:
        return titled[0]
    visible = [h for h, v, _ in found if v]
    if visible:
        return visible[0]
    if visible_only:
        return 0
    return found[0][0] if found else 0


def has_tray_window(pid: int) -> bool:
    """Is a tray icon actually registered with the shell?

    Stronger than "the builder logged no error": the tray-icon crate registers
    through a hidden message window it owns, whose class is `tray_icon_app`. If
    that window exists, the icon exists; if the build had silently produced
    nothing, this is what would be missing.
    """
    seen = {"hit": False}

    def cb(hwnd, _):
        wpid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(wpid))
        if wpid.value == pid:
            buf = ctypes.create_unicode_buffer(256)
            user32.GetClassNameW(hwnd, buf, 256)
            if "tray" in buf.value.lower():
                seen["hit"] = True
        return True

    user32.EnumWindows(WNDENUMPROC(cb), 0)
    return seen["hit"]


def wait_window(pid: int, seconds: float = 30.0) -> int:
    end = time.time() + seconds
    while time.time() < end:
        h = main_window(pid)
        if h:
            return h
        time.sleep(0.3)
    return 0


def launch() -> subprocess.Popen:
    p = subprocess.Popen([str(EXE)], cwd=ROOT)
    if not wait_healthy():
        raise RuntimeError("engine never became healthy after launching X-Core.exe")
    return p


def cleanup() -> None:
    subprocess.run([sys.executable, "-m", "xchat.server", "--stop"],
                   cwd=ROOT, capture_output=True)
    subprocess.run(["taskkill", "/F", "/IM", "X-Core.exe"], capture_output=True)
    time.sleep(1.2)


def main() -> int:
    if not EXE.exists():
        print(f"missing {EXE}; run build-client.bat first")
        return 2

    print("cleaning up any previous client / engine")
    cleanup()

    try:
        # ── A: close_to_tray = true -> hide, keep running ──────────────────
        print("\n== close_to_tray = true ==")
        write_prefs(close_to_tray=True, resident=False)
        off = log_from()
        c = launch()
        hwnd = wait_window(c.pid)
        check("window exists", bool(hwnd), f"hwnd={hwnd:#x}" if hwnd else "none")
        check("window is visible before close", bool(user32.IsWindowVisible(hwnd)))
        check("tray icon registered with the shell", has_tray_window(c.pid),
              "found a tray_icon_app window")
        ep = engine_pid()

        user32.PostMessageW(hwnd, WM_CLOSE, 0, 0)   # exactly what clicking X does
        time.sleep(4.0)

        check("client did NOT exit on close", alive(c.pid), f"client pid={c.pid}")
        check("window is now hidden", not user32.IsWindowVisible(hwnd),
              f"IsWindowVisible={bool(user32.IsWindowVisible(hwnd))}")
        check("engine still running", alive(ep), f"engine pid={ep}")
        check("engine still answers HTTP", healthy())
        # The icon must outlive the window, or there is no way back in.
        check("tray icon still registered after hiding", has_tray_window(c.pid),
              "the only way to restore the window")

        log = log_since(off)
        check("tray built without error", "TRAY BUILD FAILED" not in log,
              "no TRAY BUILD FAILED in client.log")
        check("close was logged as hide-to-tray",
              "window hidden to tray" in log, "found log line")

        # ── B: close_to_tray = false -> real quit ──────────────────────────
        print("\n== close_to_tray = false ==")
        cleanup()
        write_prefs(close_to_tray=False, resident=False)
        off = log_from()
        c2 = launch()
        hwnd2 = wait_window(c2.pid)
        ep2 = engine_pid()
        check("window exists", bool(hwnd2), f"hwnd={hwnd2:#x}" if hwnd2 else "none")

        user32.PostMessageW(hwnd2, WM_CLOSE, 0, 0)
        time.sleep(4.5)

        check("client exited on close", not alive(c2.pid), f"client pid={c2.pid}")
        check("engine stopped with it", wait_down(seconds=20), "no longer answering")
        check("engine process gone", not alive(ep2), f"engine pid={ep2}")
        check("close was logged as a real close",
              "window closing for real" in log_since(off))

        # ── C: legacy prefs file is migrated, not copied ───────────────────
        #
        # The old shape was {"resident": true}. Read literally it would detach
        # the engine from the job object. Then killing the client would leave
        # the engine running with no window to reach it. The migration must
        # therefore turn that intent into close_to_tray and start the engine
        # *attached* -- which is observable: a forced client kill takes the
        # engine down only if a kill-on-close job was bound.
        print("\n== legacy {'resident': true} migrates to the tray, engine attached ==")
        cleanup()
        write_prefs(resident=True)          # the old file, verbatim
        c3 = launch()
        hwnd3 = wait_window(c3.pid)
        ep3 = engine_pid()
        user32.PostMessageW(hwnd3, WM_CLOSE, 0, 0)
        time.sleep(3.0)
        check("legacy file still hides to tray", alive(c3.pid) and not user32.IsWindowVisible(hwnd3),
              f"client alive={alive(c3.pid)} visible={bool(user32.IsWindowVisible(hwnd3))}")

        # Force kill: no destructors, no orderly exit. Only the job object can
        # reap the engine now, so this is what distinguishes attached from
        # detached.
        subprocess.run(["taskkill", "/F", "/PID", str(c3.pid)], capture_output=True)
        check("engine reaped when the client was force-killed (job object bound)",
              wait_down(seconds=20), "engine attached, not detached")

    finally:
        print("\ncleanup: restoring defaults")
        cleanup()
        write_prefs(close_to_tray=True, resident=False)

    failed = [n for n, ok, _ in checks if not ok]
    print(f"\n{len(checks) - len(failed)}/{len(checks)} PASS"
          + (f", FAILED: {failed}" if failed else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
