"""One command that answers "is this v1.0 build actually good?".

Ten suites exist; remembering which to run, in which order, and which need a
built binary or a live engine is friction that ends in nobody running them.
This runs everything, locally, with zero model calls, and reports one verdict.

It also watches production state: the suites must not write to it. That check
is here rather than inside a suite because a suite cannot notice damage it
causes itself.

Run:  python scripts/verify_all.py [--quick]
      --quick skips the ones that launch the real GUI (slowest, and they open
      and close windows on the desktop)
"""
from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

# Subprocess output can contain U+FFFD (and any other non-GBK byte) once a suite
# fails. On a GBK console that raises UnicodeEncodeError at the print() below,
# which used to kill the framework at suite 4 of 13 -- the remaining 9 suites
# never ran, and the run still looked like it had finished. Reconfiguring with
# errors="replace" cannot fail, so the report always reaches the user.
# scripts/check_no_secrets.py already guarded against this same trap; the fix
# just never propagated to this summary entry point.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):
    pass  # non-reconfigurable stream (e.g. redirected); nothing to do

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable

# (label, command, needs_gui)
SUITES: list[tuple[str, list[str], bool]] = [
    ("version single-source", [PY, "scripts/sync_version.py", "--check"], False),
    ("code freshness", [PY, "scripts/verify_code_freshness.py"], False),
    ("CLI --json contract", [PY, "scripts/verify_cli_json.py"], False),
    ("MCP stdio surface", [PY, "scripts/verify_mcp.py"], False),
    ("policy / workbench", [PY, "tests/test_workbench.py"], False),
    ("goals / ledger / sessions", [PY, "tests/test_investigation.py"], False),
    ("jobs / code mode / mutation", [PY, "tests/test_substrate.py"], False),
    ("memory budgets", [PY, "tests/test_memory_budget.py"], False),
    ("native modules", [PY, "tests/smoke_test.py"], False),
    ("engine lifecycle", [PY, "scripts/verify_resident.py"], True),
    ("shutdown auth", [PY, "scripts/verify_shutdown.py"], True),
    ("tray behaviour", [PY, "scripts/verify_tray.py"], True),
    ("panel persistence", [PY, "scripts/verify_panel_persistence.py"], True),
]


def snapshot() -> dict[str, int]:
    def count(p: Path, kind: str) -> int:
        if not p.exists():
            return -1
        if kind == "dirs":
            return sum(1 for x in p.iterdir() if x.is_dir())
        return sum(1 for x in p.rglob("*") if x.is_file())

    def size(p: Path) -> int:
        return p.stat().st_size if p.exists() else -1

    return {
        "sessions/": count(ROOT / "sessions", "dirs"),
        "workbench/": count(ROOT / "workbench", "files"),
        "knowledge/": count(ROOT / "knowledge", "files"),
        "state/memory.db": size(ROOT / "state" / "memory.db"),
        "state/agent.db": size(ROOT / "state" / "agent.db"),
    }


def main() -> int:
    quick = "--quick" in sys.argv
    before = snapshot()

    results: list[tuple[str, bool, float, str]] = []
    print(f"X-Core verification ({'quick' if quick else 'full'} run)")
    print("=" * 66)

    for label, cmd, needs_gui in SUITES:
        if needs_gui and quick:
            print(f"  [skip] {label} (--quick)")
            results.append((label, True, 0.0, "skipped (--quick)"))
            continue
        t0 = time.time()
        p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                           encoding="utf-8", errors="replace")
        dt = time.time() - t0

        # Pick the line that actually states a result. "Last non-empty line" is
        # not good enough: smoke_test ends with a rule of '=' characters, so
        # the summary column showed a row of equals signs and told nobody
        # whether the suite had passed.
        import re
        tally = re.compile(r"\d+\s*/\s*\d+\s*(PASS|PASSED)|ALL .* PASS|"
                           r"^\s*\[PASS\]|all targets agree", re.I)
        lines = [ln.strip() for ln in (p.stdout or "").splitlines() if ln.strip()]
        summary = next((ln for ln in reversed(lines) if tally.search(ln)), "")
        if not summary:
            summary = (lines[-1] if lines else "") or \
                (p.stderr or "").strip().splitlines()[-1:][0:1] or ""
            if isinstance(summary, list):
                summary = summary[0] if summary else ""
        ok = p.returncode == 0
        results.append((label, ok, dt, summary))
        print(f"  [{'PASS' if ok else 'FAIL'}] {label:<30} {dt:6.1f}s  {summary[:60]}")

    after = snapshot()

    print("=" * 66)
    leaked = {k: (before[k], after[k]) for k in before if before[k] != after[k]}
    if leaked:
        print("PRODUCTION STATE CHANGED (suites must not write there):")
        for k, (b, a) in leaked.items():
            print(f"  {k}: {b} -> {a}")
        if "sessions/" in leaked and after["sessions/"] == before["sessions/"] + 1:
            print("  (a new session usually means you chatted in the GUI meanwhile)")
    else:
        print("production state unchanged: "
              + ", ".join(f"{k}={v}" for k, v in after.items()))

    failed = [r for r in results if not r[1]]
    print()
    if failed:
        print(f"FAILED ({len(failed)}): " + ", ".join(r[0] for r in failed))
        return 1
    print(f"ALL {len(results)} SUITES PASS")
    return 1 if leaked else 0


if __name__ == "__main__":
    sys.exit(main())
