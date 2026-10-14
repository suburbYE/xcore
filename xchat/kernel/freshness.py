"""Is the running engine executing the code that is on disk?

Python loads a module once. The engine is a long-lived process, so a source edit
made while it runs has no effect on it — and the symptom is not an error, it is
the *old behaviour*, which is indistinguishable from "the fix did not work".
That costs an hour every time: the edit is correct, the tests pass in a fresh
process, and the thing the user is actually talking to still refuses the
command.

This module answers the question from the inside, where it can be answered
exactly: compare the newest source mtime against the process start time. If a
source file is newer than this process, this process is running stale code.

Used by `/api/health` so the client can say so, and by the client's startup to
restart the engine when it would otherwise adopt a stale one.
"""
from __future__ import annotations

import os
import time
from pathlib import Path

from ..config import BASE_DIR

# What the engine actually executes. `rules/` is data, but a rules edit changes
# behaviour just as much as a code edit and is loaded the same way (at startup).
WATCHED = ("xchat", "modules", "rules")
SUFFIXES = (".py", ".js", ".json")


def newest_source(root: Path | None = None) -> tuple[float, str]:
    """(mtime, path) of the most recently modified watched source.

    Returns (0.0, "") when nothing is found, which compares as "not stale"
    rather than raising: a detector that crashes the health endpoint is worse
    than one that occasionally stays quiet.
    """
    root = root or BASE_DIR
    newest_t, newest_p = 0.0, ""
    for sub in WATCHED:
        base = root / sub
        if not base.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            # Build output, caches and vendored trees are not "the code".
            dirnames[:] = [d for d in dirnames
                           if d not in ("__pycache__", "node_modules", "target",
                                        "dist", "gen", ".git")]
            for name in filenames:
                if not name.endswith(SUFFIXES):
                    continue
                p = Path(dirpath) / name
                try:
                    t = p.stat().st_mtime
                except OSError:
                    continue
                if t > newest_t:
                    newest_t, newest_p = t, str(p.relative_to(root))
    return newest_t, newest_p


def staleness(process_started_at: float) -> dict:
    """Describe whether *this* process is behind the files on disk.

    `margin_s` exists because the two clocks are not the same clock: mtime comes
    from the filesystem and start time from the process table, and a file
    written during startup can round to slightly before the start. Two seconds
    of slack keeps that from reporting a false "stale" on every launch, which
    would train the reader to ignore the flag.
    """
    mtime, path = newest_source()
    started = process_started_at
    margin = 2.0
    stale = bool(path) and mtime > started + margin
    return {
        "stale": stale,
        "newest_source": path,
        "newest_source_age_s": round(time.time() - mtime, 1) if path else None,
        "process_age_s": round(time.time() - started, 1),
        "detail": (
            f"{path} is newer than this process; restart the engine to load it"
            if stale else "running code matches the files on disk"
        ),
    }
