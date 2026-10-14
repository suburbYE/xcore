"""
Subprocess plumbing shared by every capability provider.

The engine, the Node modules and (later) llama.cpp are all external processes.
Rather than each provider reimplementing "spawn, read, parse, report", they all
go through here so that progress reporting and failure semantics are identical
everywhere.

Failure semantics worth knowing:

* A non-zero exit is NOT automatically an error. Several tools in this project
  exit non-zero while still printing a perfectly good JSON payload (the native
  shell classifier does this for heavy shells; xcore prints a noise-gate warning
  to stderr and still returns hits). So the caller decides, based on whether a
  payload could be recovered.
* ``_extract_json`` scans for the first *balanced* object, because xcore.exe
  merges stderr into stdout and emits human-readable lines around the JSON.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import AsyncIterator

from ..contract import Event, EventEmitter, InvokeContext

# ── Paths ───────────────────────────────────────────────────────────────────

# This module lives at xchat/kernel/providers/proc.py, so the project root is
# three levels up: providers/ -> kernel/ -> xchat/ -> xcore/
PROVIDERS_DIR = Path(__file__).resolve().parent       # xchat/kernel/providers/
KERNEL_DIR = PROVIDERS_DIR.parent                     # xchat/kernel/
XCHAT_DIR = KERNEL_DIR.parent                         # xchat/
PROJECT_ROOT = XCHAT_DIR.parent                       # xcore/

XCORE_BIN = PROJECT_ROOT / "xcore.exe"
RULES_PATH = PROJECT_ROOT / "rules" / "rules.json"


def find_node() -> str:
    """Absolute path to node, or bare 'node' if discovery fails."""
    found = shutil.which("node")
    return found or "node"


@dataclass
class ProcResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    duration_ms: int = 0

    @property
    def combined(self) -> str:
        return self.stdout + ("\n" + self.stderr if self.stderr else "")

    def json(self) -> dict | None:
        """First balanced JSON object in the combined output, or None."""
        return extract_json(self.combined)


def extract_json(text: str) -> dict | None:
    """Return the first balanced JSON object, tolerating surrounding noise.

    Deliberately brace-counting rather than regex: the payloads here embed
    nested objects and braced strings (Windows paths, JSON-in-JSON).
    """
    if not text:
        return None
    cleaned = text.replace("\r", "")
    start = cleaned.find("{")
    while start != -1:
        depth = 0
        in_str = False
        esc = False
        for i in range(start, len(cleaned)):
            ch = cleaned[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(cleaned[start:i + 1])
                    except json.JSONDecodeError:
                        break
        start = cleaned.find("{", start + 1)
    return None


async def run_process(
    argv: list[str],
    em: EventEmitter,
    ctx: InvokeContext,
    *,
    cwd: Path | None = None,
    timeout: float = 300.0,
    echo_lines: bool = True,
) -> tuple[ProcResult, list[Event]]:
    """Run a process to completion, returning (result, log events).

    Returns events rather than yielding them, because callers need the exit
    status *and* the output before deciding what the terminal event should be
    (see the module docstring on non-zero exits).
    """
    events: list[Event] = []
    started = asyncio.get_event_loop().time()

    if not Path(argv[0]).exists() and not shutil.which(argv[0]):
        return ProcResult(argv, -1, "", f"executable not found: {argv[0]}",
                          duration_ms=0), [
            em.log(f"executable not found: {argv[0]}", level="error")
        ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            cwd=str(cwd or PROJECT_ROOT),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except Exception as e:  # noqa: BLE001
        return ProcResult(argv, -1, "", f"{type(e).__name__}: {e}",
                          duration_ms=0), [
            em.log(f"failed to spawn: {e}", level="error")
        ]

    async def pump(stream, sink: list[str], level: str):
        if stream is None:
            return
        while True:
            raw = await stream.readline()
            if not raw:
                break
            line = raw.decode("utf-8", "replace").rstrip()
            sink.append(line)
            if echo_lines and line.strip():
                events.append(em.log(line, level=level))

    out_lines: list[str] = []
    err_lines: list[str] = []
    try:
        await asyncio.wait_for(
            asyncio.gather(
                pump(proc.stdout, out_lines, "stdout"),
                pump(proc.stderr, err_lines, "stderr"),
                proc.wait(),
            ),
            timeout=timeout,
        )
        timed_out = False
    except asyncio.TimeoutError:
        timed_out = True
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        await proc.wait()

    duration = int((asyncio.get_event_loop().time() - started) * 1000)
    return ProcResult(
        argv=argv,
        returncode=proc.returncode if proc.returncode is not None else -1,
        stdout="\n".join(out_lines),
        stderr="\n".join(err_lines),
        timed_out=timed_out,
        duration_ms=duration,
    ), events
