"""
Phase 5d: Frida process management via CLI subprocess.

Wraps the Frida CLI (frida / frida-ps) as Python-callable functions
with unified error handling, timeout management, and structured output.

All functions operate through subprocess — no frida Python module required.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any


# ─── Constants ────────────────────────────────────────────────────────────────

# Regex to extract PID from Frida "Attached to <PID>" messages
_RE_ATTACHED_PID = re.compile(r"Attached\s+to\s+(\d+)", re.IGNORECASE)

# Regex to parse frida-ps output lines like "1234  com.example.app"
_RE_PS_LINE = re.compile(r"^\s*(\d+)\s+(.+)$")


# ─── Utility ──────────────────────────────────────────────────────────────────


def check_frida_installed() -> bool:
    """Check whether the ``frida`` CLI is available on PATH.

    Returns:
        ``True`` if ``shutil.which("frida")`` returns a non-None value.
    """
    return shutil.which("frida") is not None


# ─── Process listing ──────────────────────────────────────────────────────────


def list_processes(device: str = "usb") -> list[dict[str, Any]]:
    """List running processes on a connected device via ``frida-ps``.

    Args:
        device: ``"usb"`` (``-U``), ``"remote"`` (``-R``), or ``"local"`` (no flag).

    Returns:
        List of dicts with keys ``pid`` (int) and ``name`` (str).

    Raises:
        RuntimeError: If ``frida`` is not installed or ``frida-ps`` fails.
    """
    if not check_frida_installed():
        raise RuntimeError(
            "Frida CLI not found. Install with: pip install frida-tools"
        )

    cmd = _build_frida_ps_cmd(device)
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15,
            encoding="utf-8",
            errors="ignore",
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("frida-ps timed out — device may be unresponsive")
    except FileNotFoundError:
        raise RuntimeError("frida-ps not found — ensure frida-tools is installed")

    if proc.returncode != 0:
        raise RuntimeError(
            f"frida-ps failed (exit {proc.returncode}):\n{proc.stderr[:500]}"
        )

    return _parse_ps_output(proc.stdout)


def _build_frida_ps_cmd(device: str) -> list[str]:
    """Build the ``frida-ps`` command line for a given device type."""
    if device == "usb":
        return ["frida-ps", "-U"]
    elif device == "remote":
        return ["frida-ps", "-R"]
    else:
        return ["frida-ps"]


def _parse_ps_output(stdout: str) -> list[dict[str, Any]]:
    """Parse ``frida-ps`` stdout into {pid, name} dicts."""
    processes: list[dict[str, Any]] = []
    for line in stdout.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("PID") or line.startswith("---"):
            continue
        m = _RE_PS_LINE.match(line)
        if m:
            processes.append({
                "pid": int(m.group(1)),
                "name": m.group(2).strip(),
            })
    return processes


# ─── Frida session execution ──────────────────────────────────────────────────


def run_frida_session(
    script_path: str,
    target: str,
    device: str = "usb",
    timeout: int = 30,
) -> dict[str, Any]:
    """Launch a Frida session, inject a probe script, and capture output.

    Executes ``frida <flags> -l <script_path> <target>`` via subprocess.

    Args:
        script_path: Absolute path to the Frida JS probe script.
        target: Target process — package name (e.g. ``"com.example.app"``)
            or PID (e.g. ``"1234"``).
        device: ``"usb"`` (``-U``), ``"remote"`` (``-R``), or ``"local"`` (no flag).
        timeout: Maximum seconds to wait for the session.

    Returns:
        dict with keys:
            - **success** (bool) — ``True`` if session completed without errors.
            - **stdout** (str) — Frida normal output (hook-trigger logs).
            - **stderr** (str) — Error output (TypeError / crash messages).
            - **exit_code** (int) — Process exit code.
            - **pid** (int | None) — Attached PID extracted from stderr.
            - **device** (str) — Device type used.
            - **duration_ms** (float) — Wall-clock duration in milliseconds.

    Raises:
        FileNotFoundError: If ``script_path`` does not exist.
        RuntimeError: If ``frida`` CLI is not installed.
    """
    if not check_frida_installed():
        raise RuntimeError(
            "Frida CLI not found. Install with: pip install frida-tools"
        )

    script_abs = Path(script_path).resolve()
    if not script_abs.is_file():
        raise FileNotFoundError(f"Probe script not found: {script_abs}")

    cmd = _build_frida_cmd(str(script_abs), target, device)

    t_start = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="ignore",
        )
    except subprocess.TimeoutExpired:
        duration_ms = (time.perf_counter() - t_start) * 1000
        return {
            "success": False,
            "stdout": "",
            "stderr": f"Frida session timed out after {timeout}s",
            "exit_code": -1,
            "pid": None,
            "device": device,
            "duration_ms": round(duration_ms, 2),
        }
    except FileNotFoundError:
        raise RuntimeError(
            "Frida CLI not found — ensure frida-tools is on PATH"
        )

    duration_ms = (time.perf_counter() - t_start) * 1000
    pid = _extract_pid(proc.stderr)

    return {
        "success": proc.returncode == 0 and not _has_fatal_stderr(proc.stderr),
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "exit_code": proc.returncode,
        "pid": pid,
        "device": device,
        "duration_ms": round(duration_ms, 2),
    }


def _build_frida_cmd(script_path: str, target: str, device: str) -> list[str]:
    """Build the ``frida`` command line for the given device type.

    ``-U`` = USB attach, ``-R`` = remote attach, no flag = local spawn.
    """
    cmd = ["frida"]
    if device == "usb":
        cmd.append("-U")
    elif device == "remote":
        cmd.append("-R")
    # "local" mode — no flag, relies on spawn
    cmd.extend(["-l", script_path, target])
    return cmd


def _extract_pid(stderr: str) -> int | None:
    """Extract attached PID from Frida stderr ("Attached to 12345")."""
    m = _RE_ATTACHED_PID.search(stderr)
    if m:
        return int(m.group(1))
    return None


def _has_fatal_stderr(stderr: str) -> bool:
    """Check whether stderr contains fatal-level failure markers.

    A non-zero exit code may be spurious (e.g. Frida warnings);
    we only treat known fatal patterns as definitive failure.
    """
    fatal_markers = [
        "Failed to attach",
        "process not found",
        "unable to find process",
        "Failed to spawn",
        "connection refused",
    ]
    stderr_lower = stderr.lower()
    return any(marker.lower() in stderr_lower for marker in fatal_markers)
