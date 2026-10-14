"""Probe: does a real tray icon exist, or did we only avoid an error?

`client.log` not containing "TRAY BUILD FAILED" is weak evidence -- it says the
builder returned Ok, not that Windows registered anything in the notification
area. The tray-icon crate does its work through a hidden message-only window
owned by our process, so enumerating that process's window classes can show the
tray object directly.

Run:  python scripts/probe_tray_window.py
"""
from __future__ import annotations

import ctypes
import subprocess
import sys
import time
import urllib.request
from ctypes import wintypes
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXE = ROOT / "X-Core.exe"

user32 = ctypes.WinDLL("user32", use_last_error=True)
WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
user32.EnumWindows.argtypes = [WNDENUMPROC, wintypes.LPARAM]
user32.EnumWindows.restype = wintypes.BOOL
user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
user32.GetWindowThreadProcessId.restype = wintypes.DWORD
user32.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
user32.GetClassNameW.restype = ctypes.c_int
user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
user32.GetWindowTextW.restype = ctypes.c_int
user32.IsWindowVisible.argtypes = [wintypes.HWND]
user32.IsWindowVisible.restype = wintypes.BOOL


def windows_of(pid: int) -> list[tuple[int, str, str, bool]]:
    out: list[tuple[int, str, str, bool]] = []

    def cb(hwnd, _):
        wpid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(wpid))
        if wpid.value == pid:
            cb_buf = ctypes.create_unicode_buffer(256)
            user32.GetClassNameW(hwnd, cb_buf, 256)
            t_buf = ctypes.create_unicode_buffer(256)
            user32.GetWindowTextW(hwnd, t_buf, 256)
            out.append((hwnd, cb_buf.value, t_buf.value,
                        bool(user32.IsWindowVisible(hwnd))))
        return True

    user32.EnumWindows(WNDENUMPROC(cb), 0)
    return out


def healthy() -> bool:
    try:
        with urllib.request.urlopen("http://127.0.0.1:8787/api/health", timeout=0.6):
            return True
    except Exception:
        return False


def main() -> int:
    subprocess.run([sys.executable, "-m", "xchat.server", "--stop"],
                   cwd=ROOT, capture_output=True)
    subprocess.run(["taskkill", "/F", "/IM", "X-Core.exe"], capture_output=True)
    time.sleep(1.2)

    p = subprocess.Popen([str(EXE)], cwd=ROOT)
    end = time.time() + 45
    while time.time() < end and not healthy():
        time.sleep(0.4)
    if not healthy():
        print("engine never came up")
        return 2
    time.sleep(2.5)   # let the tray finish registering

    ws = windows_of(p.pid)
    print(f"windows owned by X-Core.exe (pid {p.pid}): {len(ws)}")
    for hwnd, cls, title, vis in ws:
        print(f"  {hwnd:#010x}  class={cls!r:34} title={title!r:16} visible={vis}")

    trayish = [w for w in ws if "tray" in w[1].lower() or "notify" in w[1].lower()]
    print()
    if trayish:
        print(f"TRAY WINDOW FOUND: {trayish[0][1]!r} -- the icon is registered with the shell")
    else:
        print("no class containing 'tray'/'notify'. The tray may still work")
        print("(the crate may reuse a generic message window), but this probe")
        print("cannot confirm it -- do not read this as a pass or a failure.")

    subprocess.run(["taskkill", "/F", "/PID", str(p.pid)], capture_output=True)
    subprocess.run([sys.executable, "-m", "xchat.server", "--stop"],
                   cwd=ROOT, capture_output=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
