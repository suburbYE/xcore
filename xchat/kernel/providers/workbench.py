"""
Capability provider: the agent substrate (workbench, shell, patch, search, gate).

This is the layer xcore was missing. It had 24 capabilities — all *domain nouns*
(scanners, databases, routers) — and **zero verbs**. An agent can only reach what
someone has already wrapped, so every new kind of work required a new capability.
Codex ships with exactly two primitives (a shell and a patcher) and no domain
tool at all; DSH ships ~20 and likewise none. The domain nouns are xcore's moat,
but they cannot be the *only* way in.

Four capabilities, and deliberately not more:

* ``sh.run``      — the universal verb
* ``fs.patch``    — apply-or-fail edits, grammar-checked in code
* ``fs.search``   — **summarised only**: counts and file names, never content
* ``verify.gate`` — the negative-control gate (see below)

``fs.search`` returning no content is not an oversight. SWE-agent's own ablation
(arXiv:2405.15793v3 Table 3, SWE-bench Lite %Resolved) scores a *human-friendly*
iterative search interface (Vim-style next/prev through matches) at **12.0 —
worse than having no search tool at all (15.7)** — because the agent walks every
match and burns its budget. Summarised search scores 18.0. The shape of a tool's
return value matters more than whether the tool exists.

``verify.gate`` is the acceptance contract, and it is the reason this layer ships
before the rest of the ledger. Self-assessment is measurably worse than useless:
without external feedback self-correction *reduces* accuracy on every model and
benchmark tested (arXiv:2310.01798; GPT-3.5 CommonSenseQA 75.8 -> 38.1,
Llama-2-70b GSM8K 62.0 -> 36.5), verifier false-negative rates reach 95.8-97.09%
(arXiv:2402.08115), and a model grading its own output is measurably biased
toward it (arXiv:2404.13076: self-recognition 73.5%, self-preference tracks it
linearly). The gate therefore refuses to certify anything until it has *proved
the check can fail* — SWT-Bench's criterion (arXiv:2406.12952): success requires
the check to FAIL on the bad input and PASS on the good one.

Safety posture: every path is classified by ``kernel.policy``, which is
deterministic code with inline self-tests, not a prompt. The default policy makes
``workbench/`` the only writable root. An honest limitation: this is enforced in
the xcore process, not by the OS, so it is defence in depth rather than a sandbox
boundary. OS-level enforcement is the follow-up.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
import time
from pathlib import Path

from ..contract import (
    COST_FREE,
    COST_LOCAL,
    SENS_INTERNAL,
    CapabilityError,
    CapabilitySpec,
    EventEmitter,
    InvokeContext,
    boolean,
    integer,
    schema,
    string,
)
from .. import output as shaping
from .. import policy as policy_mod
from .. import agentstate
from ...config import WORKBENCH_DIR

# The measured reason long work must be picked up again later: a call blocks at
# most this long, and anything still alive past it has to become a job handle.
# Codex uses the same ceiling (MAX_YIELD_TIME_MS = 30_000).
MAX_YIELD_MS = 30_000
DEFAULT_TIMEOUT_MS = 20_000


# ── helpers ─────────────────────────────────────────────────────────────────

def _run_blocking(fn, *args, **kw):
    loop = asyncio.get_running_loop()
    return loop.run_in_executor(None, lambda: fn(*args, **kw))


def _ensure_workbench() -> Path:
    WORKBENCH_DIR.mkdir(parents=True, exist_ok=True)
    return WORKBENCH_DIR


def _workspace(ctx: InvokeContext | None) -> Path:
    """The directory this call works in: the conversation's *harness* folder.

    `ctx.options["workspace"]` is the session folder, put there by the agent
    loop. The harness — the scripts an investigation is measured by — lives in
    its `scripts/` subdirectory, and that subdirectory is what the staleness
    digest covers. So the working directory is `scripts/`, not the session root:
    a script dumped in the root would be part of the investigation but not part
    of the instrument, and editing the instrument has to be what invalidates
    claims.

    A caller with no workspace falls back to the global workbench, so direct and
    CLI use behaves exactly as before.
    """
    if ctx is not None:
        ws = (ctx.options or {}).get("workspace")
        if ws:
            path = Path(ws) / "scripts"
            path.mkdir(parents=True, exist_ok=True)
            return path
    return _ensure_workbench()


def _scope(ctx: InvokeContext | None) -> str:
    """Which investigation a claim belongs to — the session folder's name.

    Derived from the workspace rather than passed separately, so it cannot
    drift out of sync with where the scripts actually are.
    """
    if ctx is not None:
        ws = (ctx.options or {}).get("workspace")
        if ws:
            return Path(ws).name
    return ""


def _get_policy(params: dict, ctx: InvokeContext | None = None) -> policy_mod.Policy:
    """Build the policy for this call, rooted at the caller's workspace.

    ``unrestricted`` is the documented escape hatch for a task that genuinely
    needs the machine. It is a *parameter*, so widening access is a decision
    recorded in the call, not a code change.
    """
    root = _workspace(ctx)
    if params.get("policy") == "unrestricted":
        return policy_mod.default_policy(unrestricted=True,
                                         base_root=root)
    extra = [Path(p) for p in (params.get("writable_roots") or [])]
    return policy_mod.default_policy(extra_writable=extra, base_root=root)


def _verdict_error(verdict: dict, *, what: str) -> CapabilityError:
    decision = verdict["decision"]
    reason = verdict.get("reason") or ""
    if decision == policy_mod.DENY:
        return CapabilityError(
            f"{what} refused by policy: {reason}", code="policy_denied",
            detail=json.dumps(verdict, ensure_ascii=False))
    # A `prompt` decision means a human should decide, and there is no approval
    # channel in the kernel yet — so it currently behaves as a refusal. Say that
    # plainly and name the exact edit that lifts it: an agent that only learns
    # "needs approval" will retry the same command forever, and a human who only
    # learns "it failed" has no idea the policy is an editable file.
    exe = ""
    cmd = verdict.get("command") or ""
    if cmd:
        exe = cmd.strip().split()[0].strip('"\'') if cmd.strip() else ""
    how = (f'add "{exe}" to the "allow" list in rules/policy.json'
           if exe else 'add it to the "allow" list in rules/policy.json')
    return CapabilityError(
        f"{what} needs human approval ({reason}), and there is no approval "
        f"channel yet, so it is refused. To permit it: {how} — or use a "
        f"different command that is already allowed.",
        code="approval_required",
        detail=json.dumps(verdict, ensure_ascii=False))


def _decode(raw: bytes) -> str:
    """Decode subprocess output without ever raising.

    xcore's own tree is UTF-8 but Windows tools emit CP936; a decode error must
    not lose the output, so replacement is correct here.
    """
    for enc in ("utf-8", "gbk", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


# The oracle is cmd.exe, but a shell-trained model reaches for POSIX by reflex:
# `ls`, `cat`, `find`, `2>/dev/null`, `~`. Telling it once in the prompt helps
# and is not enough — so when the shell itself says the command does not exist,
# the result carries the translation. The environment reports state; the model
# does not have to remember.
_UNIXISM_HINTS = (
    "is not recognized as an internal or external command",
    "The system cannot find the path specified",
    "command not found",
    "No such file or directory",
)
_WINDOWS_HINTS = """
[hint] this shell is cmd.exe on Windows, not a POSIX shell. Common translations:
  ls / dir -la          ->  dir /a
  cat f                 ->  type f
  find / -name x        ->  where /r C:\\ x      (or: dir /s /b x)
  grep x f              ->  findstr x f
  2>/dev/null           ->  2>nul
  ~                     ->  %USERPROFILE%
  rm f                  ->  del f        (del is policy-denied here)
  which x               ->  where x
  $VAR                  ->  %VAR%
  chmod/export/ln -s    ->  (not available; use PowerShell if needed)
Drive paths use C:\\style; forward slashes also work for most tools."""


def _windows_hint(stdout: str, stderr: str) -> str:
    """Append a translation hint when the failure looks like a Unix idiom."""
    blob = f"{stdout}\n{stderr}"
    if any(marker in blob for marker in _UNIXISM_HINTS):
        return _WINDOWS_HINTS
    return ""


# ── sh.run ──────────────────────────────────────────────────────────────────

def _execute(command: str, cwd: Path, timeout_s: float) -> dict:
    started = time.time()
    env = dict(os.environ)
    # Keep child analysis scripts writing into the workbench by default, so the
    # writable root and the working directory agree.
    env["XCORE_WORKBENCH"] = str(WORKBENCH_DIR)
    try:
        proc = subprocess.run(
            command, shell=True, cwd=str(cwd), env=env,
            capture_output=True, timeout=timeout_s,
        )
        return {
            "exit_code": proc.returncode,
            "stdout": _decode(proc.stdout),
            "stderr": _decode(proc.stderr),
            "timed_out": False,
            "duration_s": round(time.time() - started, 3),
        }
    except subprocess.TimeoutExpired as e:
        return {
            "exit_code": None,
            "stdout": _decode(e.stdout or b""),
            "stderr": _decode(e.stderr or b""),
            "timed_out": True,
            "duration_s": round(time.time() - started, 3),
        }


async def sh_run(params: dict, ctx: InvokeContext):
    em = EventEmitter("sh.run")
    command = (params.get("command") or "").strip()
    if not command:
        raise CapabilityError("'command' is required", code="invalid_params")

    pol = _get_policy(params, ctx)
    verdict = pol.classify_command(command)
    if verdict["decision"] != policy_mod.ALLOW:
        raise _verdict_error(verdict, what="command")

    timeout_ms = min(int(params.get("timeout_ms") or DEFAULT_TIMEOUT_MS), MAX_YIELD_MS)
    cwd = _workspace(ctx)
    if params.get("cwd"):
        cwd = pol.resolve(params["cwd"], base=cwd)
        sub, why = pol.check_path(cwd, access=policy_mod.WRITE)
        if sub != policy_mod.ALLOW:
            raise CapabilityError(f"cwd refused: {why}", code="policy_denied")

    yield em.log(f"$ {command}")
    ctx.check_cancelled()
    result = await _run_blocking(_execute, command, cwd, timeout_ms / 1000.0)

    # Shape once, at the boundary where output enters the transcript. Producers
    # never truncate; this is the single place that decides what the model sees.
    max_chars = int(params.get("max_chars") or shaping.DEFAULT_MAX_CHARS)
    out = shaping.shape(result["stdout"], max_chars=max_chars)
    err = shaping.shape(result["stderr"], max_chars=max(max_chars // 2, 512))

    ok = result["exit_code"] == 0
    detail = ("timed out" if result["timed_out"]
              else f"exit={result['exit_code']}")
    body = out.text
    if err.text.strip():
        body += "\n--- stderr ---\n" + err.text
    hint = _windows_hint(out.text, err.text)
    if hint:
        body += "\n" + hint

    yield em.result({
        "exit_code": result["exit_code"],
        "timed_out": result["timed_out"],
        "duration_s": result["duration_s"],
        "stdout": out.text,
        "stderr": err.text,
        "stdout_shape": out.to_dict(),
        "stderr_shape": err.to_dict(),
        "unix_idiom_hint": bool(hint),
        # Every substrate result ends with a status line so a clipped or empty
        # result cannot be mistaken for a complete one.
        "text": shaping.with_status(
            body, ok=ok, detail=detail,
            extra={"duration_s": result["duration_s"]}),
    })


# ── fs.patch ────────────────────────────────────────────────────────────────

def _apply_patch(path: Path, edits: list[dict]) -> dict:
    """Validate every edit, then apply. Never a partial write.

    Apply-or-fail is the whole point: a patch that half-applies leaves the
    workbench in a state neither the agent nor a later verifier can reason
    about. Each `old` must appear exactly once — an ambiguous match is a
    refusal, not a first-wins.
    """
    original = path.read_text(encoding="utf-8")
    text = original
    applied = []
    for i, edit in enumerate(edits):
        if not isinstance(edit, dict) or "old" not in edit or "new" not in edit:
            raise CapabilityError(f"edit[{i}] must have 'old' and 'new'",
                                  code="invalid_params")
        old, new = edit["old"], edit["new"]
        if not old:
            raise CapabilityError(f"edit[{i}].old is empty", code="invalid_params")
        count = text.count(old)
        if count == 0:
            raise CapabilityError(
                f"edit[{i}]: the text to replace was not found. Read the file "
                f"again — do not guess at its contents.",
                code="patch_no_match", detail=old[:200])
        if count > 1:
            raise CapabilityError(
                f"edit[{i}]: matched {count} times; include more surrounding "
                f"context to make it unique.",
                code="patch_ambiguous", detail=old[:200])
        text = text.replace(old, new, 1)
        applied.append({"index": i, "removed": len(old), "added": len(new)})

    path.write_text(text, encoding="utf-8")
    return {"applied": applied, "chars_before": len(original),
            "chars_after": len(text)}


async def fs_patch(params: dict, ctx: InvokeContext):
    em = EventEmitter("fs.patch")
    raw_path = params.get("path")
    content = params.get("content")
    edits = params.get("edits")
    if not raw_path:
        raise CapabilityError("'path' is required", code="invalid_params")
    if content is None and not edits:
        raise CapabilityError(
            "'edits' is required to change an existing file; pass 'content' to "
            "create a new one", code="invalid_params")

    pol = _get_policy(params, ctx)
    path = pol.resolve(raw_path, base=_workspace(ctx))
    sub, why = pol.check_path(path, access=policy_mod.WRITE)
    if sub != policy_mod.ALLOW:
        raise _verdict_error({"decision": sub, "reason": why}, what=f"write {path}")

    # Creation path. Refusing to clobber an existing file is deliberate
    # (DSH's createIfAbsent): overwriting is how a working harness silently
    # becomes a different one, and every claim verified against the old file
    # quietly becomes unverifiable.
    if content is not None:
        existed = path.exists()
        if existed and not params.get("overwrite"):
            raise CapabilityError(
                f"{path} already exists. Use 'edits' to change it, or pass "
                f"overwrite=true to replace it outright.",
                code="already_exists")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        # `existed` is captured before the write: testing path.exists() after
        # write_text() reports "replaced" for every creation.
        verb = "replaced" if existed else "created"
        yield em.log(f"{verb} {path.name} ({len(content)} chars)")
        yield em.result({
            "path": str(path), "created": not existed,
            "chars_after": len(content),
            "text": shaping.with_status(
                f"{verb} {path.name} ({len(content)} chars)", ok=True,
                detail=f"{len(content)} chars"),
        })
        return

    if not path.exists():
        raise CapabilityError(f"{path} does not exist; pass 'content' to create it",
                              code="not_found")

    yield em.log(f"patching {path.name} ({len(edits)} edit(s))")
    try:
        # utf-8 only: an encoding guess would silently corrupt a target's
        # extracted text. Refuse instead.
        result = await _run_blocking(_apply_patch, path, edits)
    except UnicodeDecodeError as e:
        raise CapabilityError(f"{path} is not valid UTF-8: {e}",
                              code="not_text") from None

    for a in result["applied"]:
        yield em.log(f"  edit[{a['index']}] -{a['removed']} +{a['added']}")
    yield em.result({
        **result,
        "path": str(path),
        "text": shaping.with_status(
            f"patched {path.name}: {len(result['applied'])} edit(s) applied",
            ok=True, detail=f"{len(result['applied'])} edits",
            extra={"chars": f"{result['chars_before']}->{result['chars_after']}"}),
    })


# ── fs.search ───────────────────────────────────────────────────────────────

MAX_SEARCH_RESULTS = 50


def _search(root: Path, pattern: str, glob: str, limit: int) -> dict:
    """Count matches per file. Content is deliberately not returned."""
    rx = re.compile(pattern)
    files: list[dict] = []
    total = 0
    truncated = False
    for path in sorted(root.rglob(glob or "*")):
        if not path.is_file():
            continue
        try:
            # Cap the read: a summary does not justify loading a 400 MB binary.
            with path.open("r", encoding="utf-8", errors="ignore") as fh:
                text = fh.read(8 * 1024 * 1024)
        except OSError:
            continue
        hits = rx.findall(text)
        if not hits:
            continue
        total += len(hits)
        if len(files) < limit:
            files.append({"file": str(path.relative_to(root)), "hits": len(hits)})
        else:
            truncated = True
    return {"total_hits": total, "files": files, "truncated": truncated}


async def fs_search(params: dict, ctx: InvokeContext):
    em = EventEmitter("fs.search")
    pattern = params.get("pattern")
    if not pattern:
        raise CapabilityError("'pattern' is required", code="invalid_params")
    try:
        re.compile(pattern)
    except re.error as e:
        raise CapabilityError(f"bad regex: {e}", code="invalid_params") from None

    pol = _get_policy(params, ctx)
    root = pol.resolve(params.get("path") or ".", base=_workspace(ctx))
    sub, why = pol.check_path(root, access=policy_mod.READ)
    if sub != policy_mod.ALLOW:
        raise _verdict_error({"decision": sub, "reason": why}, what=f"search {root}")
    if not root.exists():
        raise CapabilityError(f"{root} does not exist", code="not_found")

    limit = min(int(params.get("max_results") or MAX_SEARCH_RESULTS),
                MAX_SEARCH_RESULTS)
    yield em.log(f"searching {root} for /{pattern}/")
    result = await _run_blocking(_search, root, pattern,
                                 params.get("glob") or "*", limit)

    # The summary IS the result. Returning the matching lines is what makes an
    # iterative search interface score worse than no search tool at all.
    lines = [f"{result['total_hits']} match(es) in "
             f"{len(result['files'])} file(s){' (list truncated)' if result['truncated'] else ''}"]
    for f in result["files"]:
        lines.append(f"  {f['hits']:>5}  {f['file']}")
    if not result["files"]:
        lines.append("  (no matches)")
    lines.append("content not returned by design — read the file to see matches")

    yield em.result({
        **result,
        "root": str(root),
        "text": shaping.with_status(
            "\n".join(lines), ok=True,
            detail=f"{result['total_hits']} hits in {len(result['files'])} files"),
    })


# ── verify.gate ─────────────────────────────────────────────────────────────

# A check may end its output with a machine-readable summary line. When it does
# the gate records the denominator and the identity of the failures, because a
# bare score is not evidence: 27.2-32.1% of agent sessions lose the denominator
# entirely and then overclaim coverage in 80.4% of those cases (arXiv:2609.20812).
SUMMARY_RE = re.compile(r"^\s*(\{.*\"cases_total\".*\})\s*$", re.M)


def _run_check(command: str, cwd: Path, timeout_s: float) -> dict:
    result = _execute(command, cwd, timeout_s)
    summary = None
    match = SUMMARY_RE.search(result["stdout"] or "")
    if match:
        try:
            summary = json.loads(match.group(1))
        except json.JSONDecodeError:
            summary = None
    result["summary"] = summary
    return result


async def verify_gate(params: dict, ctx: InvokeContext):
    """Accept a claim only if the check has proven it can fail.

    The order matters and is the point: the negative control runs FIRST. If it
    passes, the check has no discriminating power — it would report success on
    a known-bad input — so the claim is rejected before the real check is even
    run. "The test passed" is a ~25%-precision signal on its own (TestGen-LLM at
    Meta: of generated tests, 75% built and 57% passed reliably but only 25%
    increased coverage).
    """
    em = EventEmitter("verify.gate")
    claim = (params.get("claim") or "").strip()
    check = (params.get("check") or "").strip()
    control = (params.get("negative_control") or "").strip()
    if not claim:
        raise CapabilityError("'claim' is required", code="invalid_params")
    if not check:
        raise CapabilityError("'check' is required", code="invalid_params")
    if not control:
        # Missing, not empty: a claim without a negative control cannot be
        # accepted at all, so refuse rather than defaulting to a weaker gate.
        raise CapabilityError(
            "'negative_control' is required: give a command that MUST FAIL, so "
            "the gate can prove the check discriminates. Without it a passing "
            "check proves nothing.",
            code="negative_control_required")

    pol = _get_policy(params, ctx)
    for label, command in (("check", check), ("negative_control", control)):
        verdict = pol.classify_command(command)
        if verdict["decision"] != policy_mod.ALLOW:
            raise _verdict_error(verdict, what=f"{label} command")

    timeout_ms = min(int(params.get("timeout_ms") or MAX_YIELD_MS), MAX_YIELD_MS)
    cwd = _workspace(ctx)

    # Step 1 — the negative control must FAIL.
    yield em.log("gate 1/2: running negative control (must fail)")
    ctx.check_cancelled()
    bad = await _run_blocking(_run_check, control, cwd, timeout_ms / 1000.0)
    if bad["exit_code"] == 0:
        yield em.error(
            "the negative control PASSED, so this check cannot fail and a "
            "passing result would prove nothing. Fix the check so it rejects "
            "the known-bad input first.",
            code="no_discriminating_power",
            negative_control_output=bad["stdout"][:2000])
        return
    yield em.log(f"  negative control failed as required (exit={bad['exit_code']})")

    # Step 2 — the real check must PASS.
    yield em.log("gate 2/2: running check (must pass)")
    ctx.check_cancelled()
    good = await _run_blocking(_run_check, check, cwd, timeout_ms / 1000.0)
    verified = good["exit_code"] == 0
    summary = good.get("summary") or {}

    failures = summary.get("failures")
    cases_total = summary.get("cases_total")
    cases_passed = summary.get("cases_passed")
    lines = [
        f"claim    : {claim}",
        f"verified : {verified}",
        f"control  : failed as required (exit={bad['exit_code']})",
        f"check    : exit={good['exit_code']}",
    ]
    if cases_total is not None:
        lines.append(f"coverage : {cases_passed}/{cases_total}")
        if failures:
            lines.append(f"failures : {len(failures)} — {failures[:5]}"
                         + (" ..." if len(failures) > 5 else ""))
    else:
        lines.append("coverage : not reported — have the check print a "
                     '{"cases_total":N,"cases_passed":M,"failures":[...]} line')
    if not verified:
        lines.append("--- check output ---")
        lines.append(shaping.shape(good["stdout"], max_chars=2048).text)

    # The gate is the ledger's only writer. Letting the agent record its own
    # verified claims would turn the ledger into a transcript of assertions;
    # writing here means every entry carries a negative control that actually
    # ran, and the harness digest it was measured with.
    claim_id = None
    if params.get("record"):
        claim_id = agentstate.record_claim(
            claim,
            goal_id=params.get("goal_id") or "",
            status="verified" if verified else "refuted",
            cases_total=cases_total,
            cases_passed=cases_passed,
            failures=failures,
            negative_control=control,
            check_cmd=check,
            scope=_scope(ctx),
            evidence={"negative_control_exit": bad["exit_code"],
                      "check_exit": good["exit_code"],
                      "has_structured_summary": bool(summary)},
        )["id"]
        yield em.log(f"ledger <- {claim_id} ({'verified' if verified else 'refuted'})")
        lines.append(f"ledger   : recorded as {claim_id}")

    yield em.result({
        "claim": claim,
        "verified": verified,
        "negative_control_exit": bad["exit_code"],
        "check_exit": good["exit_code"],
        "cases_total": cases_total,
        "cases_passed": cases_passed,
        "failures": failures,
        "has_structured_summary": bool(summary),
        "recorded": claim_id,
        "text": shaping.with_status(
            "\n".join(lines), ok=verified,
            detail=("verified" if verified else "not verified")),
    })


# ── registration ────────────────────────────────────────────────────────────

async def verify_mutate(params: dict, ctx: InvokeContext):
    """Prove a check still *can* fail, by breaking the harness on purpose.

    `verify.gate` proves this once, at record time, with a negative control.
    That is necessary and not sufficient: a harness drifts. Someone loosens a
    threshold, a comparison becomes unconditional, a loop stops covering the
    interesting cases — and the check goes on passing, now proving nothing. The
    mhypbase episode is the worked example: the formula was right and the
    *ruler* was wrong, and 18 failures were the only thing that revealed it.

    So each named mutation is applied to the harness, the check is run, and it
    is expected to FAIL. A mutation the check does not notice is a **survivor**,
    and a survivor means the check is weaker than its own pass/fail suggests.

    What a mutation is here matters: a patch to the investigation's own scripts,
    not a synthetic AST rewrite. "Put the old `read_rva` back" is a mutation; so
    is "drop the segment-table fallback". Those are the mistakes that actually
    happened, so those are the ones worth confirming the check still catches.

    Every mutated file is snapshotted before the first edit and restored after
    the run, including when an edit fails part-way — a mutation run that leaves
    the harness modified would be worse than no mutation run at all.
    """
    em = EventEmitter("verify.mutate")
    check = (params.get("check") or "").strip()
    mutations = params.get("mutations") or []
    if not check:
        raise CapabilityError("'check' is required", code="invalid_params")
    if not isinstance(mutations, list) or not mutations:
        raise CapabilityError(
            "'mutations' must be a non-empty list of {name, edits}; each edit is "
            "{path, old, new}. Undo the mistake on purpose and confirm the check "
            "notices.", code="invalid_params")

    pol = _get_policy(params, ctx)
    verdict = pol.classify_command(check)
    if verdict["decision"] != policy_mod.ALLOW:
        raise _verdict_error(verdict, what="check command")

    root = _workspace(ctx)
    timeout_ms = min(int(params.get("timeout_ms") or MAX_YIELD_MS), MAX_YIELD_MS)
    results: list[dict] = []

    for mutation in mutations:
        if not isinstance(mutation, dict):
            continue
        name = str(mutation.get("name") or "unnamed")
        originals: list[tuple[Path, str]] = []
        apply_error = ""

        try:
            for edit in mutation.get("edits") or []:
                target = pol.resolve(edit["path"], base=root)
                decision, why = pol.check_path(target, access=policy_mod.WRITE)
                if decision != policy_mod.ALLOW:
                    raise CapabilityError(f"{target}: {why}", code="policy_denied")
                if not target.exists():
                    raise CapabilityError(f"{target} does not exist",
                                          code="not_found")
                before = target.read_text(encoding="utf-8")
                if edit["old"] not in before:
                    raise CapabilityError(f"{target.name}: mutation text not found",
                                          code="patch_no_match")
                originals.append((target, before))
                target.write_text(before.replace(edit["old"], edit["new"], 1),
                                  encoding="utf-8")
        except Exception as exc:  # noqa: BLE001 - an unusable mutation is a result
            apply_error = f"{type(exc).__name__}: {exc}"

        if apply_error:
            for path, before in originals:
                path.write_text(before, encoding="utf-8")
            results.append({"mutation": name, "applied": False,
                            "error": apply_error, "detected": None})
            yield em.log(f"  {name}: could not apply ({apply_error[:70]})",
                         level="warning")
            continue

        yield em.log(f"  {name}: applied, running check")
        ctx.check_cancelled()
        outcome = await _run_blocking(_run_check, check, root, timeout_ms / 1000.0)

        for path, before in originals:
            path.write_text(before, encoding="utf-8")

        detected = outcome["exit_code"] != 0
        results.append({
            "mutation": name, "applied": True, "detected": detected,
            "exit_code": outcome["exit_code"],
            "output": shaping.shape(outcome["stdout"], max_chars=600).text,
        })
        yield em.log(
            f"  {name}: " + ("detected — the check noticed"
                             if detected else
                             "SURVIVED — the check does not notice this"),
            level="info" if detected else "warning")

    applied = [r for r in results if r["applied"]]
    survivors = [r["mutation"] for r in applied if not r["detected"]]
    lines = [f"check    : {check}",
             f"mutations: {len(applied)} applied, "
             f"{len(applied) - len(survivors)} detected, {len(survivors)} survived"]
    for r in results:
        if not r["applied"]:
            lines.append(f"  [!] {r['mutation']}: not applied — {r['error'][:70]}")
        else:
            lines.append(f"  [{'ok' if r['detected'] else 'SURVIVED'}] "
                         f"{r['mutation']} (exit={r['exit_code']})")
    if survivors:
        lines.append("")
        lines.append("A surviving mutation means the check passes for reasons "
                     "other than the thing it claims to measure. Strengthen the "
                     "check, or narrow what the claim asserts.")
    if not applied:
        lines.append("no mutation could be applied — the harness may have moved on")

    yield em.result({
        "check": check,
        "results": results,
        "applied": len(applied),
        "detected": len(applied) - len(survivors),
        "survivors": survivors,
        "scope": _scope(ctx),
        "text": shaping.with_status(
            "\n".join(lines), ok=bool(applied) and not survivors,
            detail=f"{len(applied) - len(survivors)}/{len(applied)} detected"),
    })


SPECS = (
    CapabilitySpec(
        id="sh.run",
        kind="sh",
        name="执行命令",
        description="在工作台里执行一条命令。这是通用动词——分析脚本、跑引擎、"
                    "驱动 Unicorn/capstone 都走这里。输出保头保尾、中间省略并标注原始长度；"
                    "策略文件决定哪些命令需要批准。",
        params=schema(
            {
                "command": string("要执行的命令"),
                "cwd": string("工作目录（相对工作台，须可写）"),
                "timeout_ms": integer("超时毫秒（上限 30000）", default=DEFAULT_TIMEOUT_MS),
                "max_chars": integer("stdout 字符上限", default=shaping.DEFAULT_MAX_CHARS),
                "policy": string("unrestricted 可放开沙箱（默认受限）"),
                "writable_roots": {"type": "array", "items": {"type": "string"},
                                   "description": "额外可写根目录"},
            },
            required=["command"],
        ),
        returns=schema({"exit_code": {"type": "integer"},
                        "text": {"type": "string"},
                        "timed_out": {"type": "boolean"}}),
        streaming=True,
        cost=COST_FREE,
        sensitivity=SENS_INTERNAL,
        backend="providers.workbench",
        tags=("substrate", "shell", "verb"),
    ),
    CapabilitySpec(
        id="fs.patch",
        kind="fs",
        name="写文件 / 打补丁",
        description="两种用法：给 `content` 新建文件（已存在则拒绝，除非 overwrite=true）；"
                    "给 `edits` 改已存在的文件，每处 old 必须唯一匹配，全部校验通过才写入。"
                    "apply-or-fail——不允许半途而废的写入。只能写工作台里的文件。",
        params=schema(
            {
                "path": string("目标文件"),
                "content": string("新建/整文件替换的内容（新建时用这个）"),
                "overwrite": boolean("允许覆盖已存在的文件", default=False),
                "edits": {"type": "array", "items": {"type": "object"},
                          "description": "改已有文件时用：每项 {old, new}；old 必须唯一匹配"},
                "policy": string("unrestricted 可放开沙箱"),
            },
            required=["path"],
        ),
        returns=schema({"applied": {"type": "array"},
                        "created": {"type": "boolean"}}),
        streaming=True,
        cost=COST_FREE,
        sensitivity=SENS_INTERNAL,
        backend="providers.workbench",
        tags=("substrate", "edit", "verb"),
    ),
    CapabilitySpec(
        id="fs.search",
        kind="fs",
        name="检索",
        description="按正则统计命中：**只返回计数与文件名，不返回内容**。"
                    "这是刻意的——逐条返回命中会让 agent 把每条都翻一遍，实测比不给搜索工具更差。"
                    "要看内容请显式读取。",
        params=schema(
            {
                "pattern": string("正则"),
                "path": string("搜索根目录（默认工作台）"),
                "glob": string("文件名过滤", default="*"),
                "max_results": integer("最多返回多少个文件", default=MAX_SEARCH_RESULTS),
                "policy": string("unrestricted 可放开沙箱"),
            },
            required=["pattern"],
        ),
        returns=schema({"total_hits": {"type": "integer"},
                        "files": {"type": "array"}}),
        streaming=True,
        cost=COST_FREE,
        sensitivity=SENS_INTERNAL,
        backend="providers.workbench",
        tags=("substrate", "search", "verb"),
    ),
    CapabilitySpec(
        id="verify.gate",
        kind="verify",
        name="验证闸门",
        description="接受一条主张前，必须先证明这个检查**能失败**（负对照）。"
                    "先跑 negative_control：它**必须失败**，否则说明检查没有区分力，主张直接驳回；"
                    "再跑 check：它必须通过。检查若打印 {\"cases_total\":N,\"cases_passed\":M,"
                    "\"failures\":[...]} 一行，闸门会记下分母与失败清单。",
        params=schema(
            {
                "claim": string("被验证的主张（例如「handler 0x186CB87 公式覆盖 986/986」）"),
                "check": string("验证命令；退出码 0 = 通过"),
                "negative_control": string("**必须失败**的命令，用来证明检查有区分力"),
                "record": boolean("把结果写进主张账本（闸门是账本唯一写入方）",
                                  default=False),
                "goal_id": string("归属的调查目标"),
                "timeout_ms": integer("超时毫秒（上限 30000）", default=MAX_YIELD_MS),
                "policy": string("unrestricted 可放开沙箱"),
            },
            required=["claim", "check", "negative_control"],
        ),
        returns=schema({"verified": {"type": "boolean"},
                        "cases_total": {"type": "integer"},
                        "failures": {"type": "array"}}),
        streaming=True,
        cost=COST_FREE,
        sensitivity=SENS_INTERNAL,
        backend="providers.workbench",
        tags=("substrate", "verify", "negative-control"),
    ),
    CapabilitySpec(
        id="verify.mutate",
        kind="verify",
        name="变异检验",
        description="**故意把量具改错，看检查还抓不抓得住**。给若干变异（每个是"
                    "对 harness 脚本的一处 patch），逐个应用并跑检查：检查**必须失败**。"
                    "没抓住的变异叫 survivor —— 那说明这个检查的通过另有原因，"
                    "它比自己的 pass/fail 看起来更弱。典型变异就是「把旧版 read_rva 放回去」。"
                    "每个被改的文件在开始前快照、结束后还原，中途失败也会还原。",
        params=schema(
            {
                "check": string("验证命令；退出码 0 = 通过（变异后应为非 0）"),
                "mutations": {"type": "array", "items": {"type": "object"},
                              "description": "[{name, edits:[{path, old, new}]}]，"
                                             "path 相对 harness 目录"},
                "timeout_ms": integer("每次检查的超时毫秒", default=MAX_YIELD_MS),
                "policy": string("unrestricted 可放开沙箱"),
            },
            required=["check", "mutations"],
        ),
        returns=schema({"applied": {"type": "integer"},
                        "detected": {"type": "integer"},
                        "survivors": {"type": "array"}}),
        streaming=True, cost=COST_FREE, sensitivity=SENS_INTERNAL,
        backend="providers.workbench", tags=("substrate", "verify", "mutation"),
    ),
)

HANDLERS = {
    "sh.run": sh_run,
    "fs.patch": fs_patch,
    "fs.search": fs_search,
    "verify.gate": verify_gate,
    "verify.mutate": verify_mutate,
}


def register_all(registry) -> None:
    for spec in SPECS:
        registry.register(spec, HANDLERS[spec.id])
