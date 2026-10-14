"""Is `--json` machine-readable, or just JSON-shaped?

The CLI is the AI's interface, so the contract that matters is: with `--json`,
stdout is *the document* and nothing else. That was not true -- `scan --json`
emitted a summary line, then the JSON, then case matching and LLM progress, all
on stdout. A caller needed line numbers to find the document, which is the same
as not having one, and the failure is invisible in a terminal because the output
still reads fine to a human.

This asserts the contract the way a caller would: parse stdout, and treat any
non-JSON line as a failure. Progress is allowed on stderr -- that is the point
of the split.

Run:  python scripts/verify_cli_json.py
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
XCORE = ROOT / "xcore.exe"
RULES = ROOT / "rules" / "rules.json"
SAMPLES = ROOT / "test_samples"

checks: list[tuple[str, bool, str]] = []
skips: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    checks.append((name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""))


def skip(name: str, why: str) -> None:
    skips.append(name)
    print(f"  [SKIP] {name} -- {why}")


def run(args: list[str], timeout: int = 180):
    return subprocess.run([str(XCORE), *args], cwd=ROOT, capture_output=True,
                          text=True, encoding="utf-8", errors="replace",
                          timeout=timeout)


def first_sample(*suffixes: str) -> Path | None:
    if not SAMPLES.exists():
        return None
    for p in sorted(SAMPLES.iterdir()):
        if p.suffix.lower() in suffixes:
            return p
    return None


def main() -> int:
    if not XCORE.exists():
        print(f"missing {XCORE}; run build.bat first")
        return 2

    print("== version is consistent in every machine-readable place ==")
    p = run(["--version"])
    banner = (p.stdout + p.stderr).strip().splitlines()
    check("--version prints a version", bool(banner), banner[0] if banner else "")

    r = run(["scan", str(RULES), "--json"])   # cheap: the rules file itself

    print("\n== scan --json ==")
    sample = first_sample(".so", ".dll")
    if sample is None:
        skip("scan --json stdout is pure JSON", "no .so/.dll sample in test_samples/")
    else:
        p = run(["scan", str(sample), str(RULES), "--json"])
        out = p.stdout
        check("scan --json produced stdout", bool(out.strip()),
              f"{len(out)} chars, {len(out.splitlines())} lines")
        try:
            doc = json.loads(out)
            check("scan --json stdout parses as one JSON document", True,
                  f"top-level keys={sorted(doc)[:6]}")
            check("document carries the tool version",
                  doc.get("version", "").count(".") == 2,
                  f"version={doc.get('version')!r}")
        except json.JSONDecodeError as e:
            # Show the offending line, because "invalid JSON" alone gives no
            # hint about which of the thirty pipeline prints escaped.
            lines = out.splitlines()
            bad = lines[e.lineno - 1] if 0 < e.lineno <= len(lines) else ""
            check("scan --json stdout parses as one JSON document", False,
                  f"{e.msg} at line {e.lineno}: {bad[:90]!r}")
            check("document carries the tool version", False, "unparseable")

        # Progress is allowed -- on stderr. Say so explicitly so a later change
        # that silences it entirely is noticed rather than silently welcomed.
        check("progress went somewhere (stderr), not into stdout",
              bool(p.stderr.strip()) or not out.strip(),
              f"{len(p.stderr.splitlines())} stderr lines")

    print("\n== native --so --json ==")
    if sample is None:
        skip("native --so --json stdout is pure JSON", "no .so sample")
    else:
        p = run(["native", "--so", str(sample), "--json"])
        out = p.stdout
        if not out.strip():
            check("native --so --json produced stdout", False,
                  f"empty; stderr={p.stderr.strip()[:120]!r}")
        else:
            check("native --so --json produced stdout", True, f"{len(out)} chars")
            try:
                doc = json.loads(out)
                check("native --so --json stdout parses as one JSON document",
                      True, f"top-level keys={sorted(doc)[:6]}")
            except json.JSONDecodeError as e:
                lines = out.splitlines()
                bad = lines[e.lineno - 1] if 0 < e.lineno <= len(lines) else ""
                check("native --so --json stdout parses as one JSON document",
                      False, f"{e.msg} at line {e.lineno}: {bad[:90]!r}")

    print("\n== exit codes are meaningful ==")
    p = run(["scan", str(sample or RULES), str(RULES), "--json"]) if sample else None
    if p is None:
        skip("scan exit code", "no sample")
    else:
        check("clean run exits 0", p.returncode == 0, f"exit={p.returncode}")

    # --help is the CLI's self-description, and an AI decides what it may call
    # from reading it. `classify --json` worked for months while --help did not
    # mention it, so a caller would conclude the flag was unsupported.
    print("\n== --help advertises what the binary actually supports ==")
    h = run(["--help"])
    help_text = h.stdout + h.stderr
    check("--help runs", bool(help_text.strip()))

    import re
    for cmd in ("scan", "classify", "pipe", "verify"):
        row = next((ln for ln in help_text.splitlines()
                    if re.match(rf"\s*xcore\s+{cmd}\b", ln)), "")
        check(f"--help documents --json for `{cmd}`", "--json" in row,
              row.strip()[:88] if row else "no usage row found")

    check("--help explains the exit codes",
          "3=error" in help_text or "3 = error" in help_text,
          "exit-code legend present")

    print("\n== verify --json ==")
    if sample is None:
        skip("verify --json", "no sample")
    else:
        # Same file twice: byte-identical, so verified must be true. The point
        # is the shape of the document, not the comparison.
        p = run(["verify", str(sample), str(sample), "--json"])
        if not p.stdout.strip():
            check("verify --json produced stdout", False,
                  f"empty; stderr={p.stderr.strip()[:100]!r}")
        else:
            try:
                doc = json.loads(p.stdout)
                check("verify --json stdout parses as one JSON document", True,
                      f"keys={sorted(doc)[:6]}")
                check("verify reports a machine-readable verdict",
                      isinstance(doc.get("verified"), bool),
                      f"verified={doc.get('verified')!r}")
            except json.JSONDecodeError as e:
                lines = p.stdout.splitlines()
                bad = lines[e.lineno - 1] if 0 < e.lineno <= len(lines) else ""
                check("verify --json stdout parses as one JSON document", False,
                      f"{e.msg} at line {e.lineno}: {bad[:80]!r}")

    # The abort regression. `json::dump()` throws on non-UTF-8 strings, and an
    # uncaught throw is terminate -> abort: exit 0xC0000409, no stdout, no
    # stderr, nothing to diagnose. It is reachable whenever an error message
    # came from the OS or a CP936 source, i.e. routinely on a Chinese Windows.
    # Pointing at files that do not exist produces exactly such a message.
    print("\n== non-UTF-8 payloads must not abort the process ==")
    p = run(["verify", "no_such_a.js", "no_such_b.js", "--json"])
    aborted = p.returncode in (-1073740791, 0xC0000409 - 0x100000000)
    check("a non-UTF-8 error message does not abort", not aborted,
          f"exit={p.returncode}"
          + (" (0xC0000409 = abort)" if aborted else ""))
    if not aborted:
        try:
            doc = json.loads(p.stdout)
            check("the document is still valid JSON", True,
                  f"verified={doc.get('verified')!r}")
        except json.JSONDecodeError as e:
            check("the document is still valid JSON", False, f"{e.msg}")

    failed = [n for n, ok, _ in checks if not ok]
    summary = (f"\n{len(checks) - len(failed)}/{len(checks)} PASS"
               + (f", FAILED: {failed}" if failed else ""))
    if skips:
        summary += f", {len(skips)} SKIPPED: {skips}"
    print(summary)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
