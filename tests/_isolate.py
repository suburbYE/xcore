"""Point xcore's mutable state at a scratch directory for one test run.

Import this **before** anything from `xchat`:

    import _isolate  # noqa: F401  — must precede the xchat imports

Why it has to be first: `xchat.config` resolves its paths at import time, so
`XCORE_STATE_ROOT` has no effect once that module is loaded.

The problem it solves is not tidiness. The suites create conversations, record
claims and write workbench scripts. Before this, those went into the real
`state/agent.db`, `state/memory.db` and `sessions/` — so every test run added
entries to the user's conversation list that look exactly like their own work,
and clicking one opens a blank conversation. Two such leftovers ("mutation",
0 turns) were sitting at the top of the list when this was written.

Each suite gets its own directory under `temp/test-state/`, wiped on import, so
a run is reproducible and a failure can still be inspected afterwards.
"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# sys.argv[0] is this suite's path when run as `python tests/test_x.py`.
SUITE = Path(sys.argv[0]).stem or "suite"
SCRATCH = ROOT / "temp" / "test-state" / SUITE


def _isolate() -> Path:
    if SCRATCH.exists():
        shutil.rmtree(SCRATCH, ignore_errors=True)
    for sub in ("state", "sessions", "workbench"):
        (SCRATCH / sub).mkdir(parents=True, exist_ok=True)

    os.environ["XCORE_STATE_ROOT"] = str(SCRATCH)

    # Importing `xchat` must not depend on the caller's cwd. Note this happens
    # *after* the env var, so the first xchat import already sees it.
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    return SCRATCH


SCRATCH = _isolate()

if os.environ.get("XCORE_TEST_QUIET") != "1":
    print(f"[isolated] mutable state -> {SCRATCH}")
