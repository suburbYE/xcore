"""Why was that `dir` command refused?

The user hit a refusal on:

    dir /s /b "C:\\Users\\<user>\\Desktop\\workspace_x\\workbench\\tieba_pipeline" 2>nul & dir /s /b workbench 2>nul | findstr /i "tieba"

`dir` is on the allow list and `nul` is a device sink, so the refusal is a
misclassification somewhere. Guessing which part would be guessing; this runs
the real classifier over the real string plus a series of reductions, so the
component that flips the verdict is visible.

Run:  python scripts/diagnose_sh_classify.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from xchat.kernel import policy as P  # noqa: E402

CASES: list[tuple[str, str]] = [
    ("the command as sent",
     'dir /s /b "C:\\Users\\<user>\\Desktop\\workspace_x\\workbench\\tieba_pipeline" 2>nul & dir /s /b workbench 2>nul | findstr /i "tieba"'),
    ("just the first half (redirect, no &)",
     'dir /s /b "C:\\Users\\<user>\\Desktop\\workspace_x\\workbench\\tieba_pipeline" 2>nul'),
    ("first half, no redirect",
     'dir /s /b "C:\\Users\\<user>\\Desktop\\workspace_x\\workbench\\tieba_pipeline"'),
    ("redirect only",
     "dir 2>nul"),
    ("redirect with a space",
     "dir 2> nul"),
    ("second half (pipe)",
     'dir /s /b workbench 2>nul | findstr /i "tieba"'),
    ("pipe without redirect",
     'dir /s /b workbench | findstr /i "tieba"'),
    ("ampersand only",
     "dir & dir"),
    ("the outside-root path alone",
     'dir "C:\\Users\\<user>\\Desktop\\workspace_x\\workbench\\tieba_pipeline"'),
    ("relative path",
     "dir /s /b workbench"),
    ("findstr alone",
     'findstr /i "tieba"'),
    ("plain dir",
     "dir"),
]


def main() -> int:
    pol = P.default_policy()
    print("rule verdicts per command\n")
    for label, cmd in CASES:
        try:
            v = pol.classify_command(cmd)
        except Exception as e:
            print(f"  {label}\n    RAISED {type(e).__name__}: {e}")
            continue
        decision = v.get("decision")
        mark = "ok   " if decision == "allow" else "BLOCK"
        print(f"  [{mark}] {label}")
        print(f"           -> decision={decision} reason={v.get('reason')!r}")
        detail = {k: val for k, val in v.items()
                  if k not in ("decision", "reason") and val}
        if detail:
            print(f"           detail={detail}")

    print("\n-- how the compound command is split --")
    for label, cmd in CASES[:1] + [("pipe case", CASES[5][1])]:
        parts = P._split_commands(cmd) if hasattr(P, "_split_commands") else None
        print(f"  {label}: {parts}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
