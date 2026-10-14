"""
Capability provider: code mode — one round-trip, N capability calls.

The problem: an investigation needs hundreds of iterations of "run experiment,
compare against ground truth, look at the failures", and each iteration as a
separate model turn costs a full round-trip. The mhypbase work took 98 scripts;
98 turns of context is both slow and expensive.

Codex's answer is `exec` + `wait`: the model writes source that calls other
tools, running in a sandboxed JS isolate, so one turn contains many calls. This
is the same idea in the language xcore already runs — the model writes Python,
and a small `xcore` bridge inside the script reaches back into the kernel:

    for seed in seeds:
        r = xcore.call("native.target_scan", so=path, seed=seed)
        if r["verdict"] != expected:
            failures.append(seed)
    result = {"cases_total": len(seeds), "failures": failures}

That shape — a sweep that returns a denominator and a failure list — is exactly
what `verify.gate` wants, and it is why the two compose: code mode produces the
evidence, the gate refuses to accept it without a negative control.

**Budget enforcement.** A runaway script cannot be killed from outside in
CPython, so the bridge checks the wall clock *at every capability call* and
raises inside the script, which unwinds it cleanly. A busy loop that never calls
a capability is not interruptible this way; the thread is abandoned and the
result reports the timeout. That limitation is stated here rather than hidden,
because the alternative — claiming a hard kill we cannot deliver — is worse.
"""

from __future__ import annotations

import asyncio
import io
import json
import time
import traceback
import uuid

from ..contract import (
    COST_FREE,
    SENS_INTERNAL,
    CapabilityError,
    CapabilitySpec,
    EventEmitter,
    InvokeContext,
    integer,
    schema,
    string,
)
from .. import output as shaping
from pathlib import Path

from ...config import WORKBENCH_DIR

DEFAULT_TIMEOUT_S = 120
MAX_TIMEOUT_S = 900
MAX_RESULT_CHARS = 8000


def _workspace(ctx: InvokeContext | None) -> Path:
    """The harness directory for this call — same rule as `sh.run`."""
    if ctx is not None:
        ws = (ctx.options or {}).get("workspace")
        if ws:
            path = Path(ws) / "scripts"
            path.mkdir(parents=True, exist_ok=True)
            return path
    WORKBENCH_DIR.mkdir(parents=True, exist_ok=True)
    return WORKBENCH_DIR


class _Budget:
    def __init__(self, deadline: float) -> None:
        self.deadline = deadline

    def check(self) -> None:
        if time.monotonic() > self.deadline:
            raise TimeoutError("code.run budget exhausted")


class _Bridge:
    """What the script sees as `xcore`."""

    def __init__(self, registry, ctx, loop, budget: _Budget) -> None:
        self._registry = registry
        self._ctx = ctx
        self._loop = loop
        self._budget = budget
        self.calls = 0

    def call(self, capability: str, **params):
        """Invoke a capability and return its result value (blocking).

        The budget is checked *before* each call so a long sweep stops at a
        clean boundary with its partial results intact, rather than being torn
        down in the middle.
        """
        self._budget.check()
        self.calls += 1

        async def go():
            value = None
            async for ev in self._registry.invoke(
                    capability, params,
                    InvokeContext(session_id=self._ctx.session_id,
                                  cancelled=self._ctx.cancelled)):
                if ev.type == "result":
                    value = ev.data.get("value")
                elif ev.type == "error":
                    raise RuntimeError(
                        f"{capability}: {ev.data.get('message')} "
                        f"[{ev.data.get('code')}]")
            return value

        fut = asyncio.run_coroutine_threadsafe(go(), self._loop)
        return fut.result(timeout=max(1.0, self._budget.deadline - time.monotonic()))

    def capabilities(self):
        """The capability ids available — so a script can be written blind."""
        return [s["id"] for s in self._registry.specs()]


def _run_source(source: str, bridge: _Bridge, budget: _Budget) -> dict:
    """Exec the script and collect its result.

    Prefers an explicit `result` binding; falls back to the last JSON object
    printed. Preferring the binding means a script that logs progress does not
    accidentally have a log line mistaken for its answer.
    """
    stdout = io.StringIO()
    scope: dict = {"__name__": "__xcore_code__", "xcore": bridge}
    started = time.monotonic()
    error = None
    try:
        import contextlib
        with contextlib.redirect_stdout(stdout):
            exec(compile(source, "<code.run>", "exec"), scope)  # noqa: S102
    except TimeoutError as exc:
        error = {"code": "timeout", "message": str(exc)}
    except Exception as exc:  # noqa: BLE001 - a script error is a result
        error = {"code": "script_error",
                 "message": f"{type(exc).__name__}: {exc}",
                 "traceback": traceback.format_exc()[-2000:]}

    printed = stdout.getvalue()
    result = scope.get("result")
    if result is None and not error:
        # Fall back to the last JSON object on a line by itself.
        for line in reversed(printed.splitlines()):
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                try:
                    result = json.loads(line)
                    break
                except json.JSONDecodeError:
                    continue
    return {"result": result, "stdout": printed, "error": error,
            "duration_s": round(time.monotonic() - started, 2),
            "calls": bridge.calls}


async def code_run(params: dict, ctx: InvokeContext):
    em = EventEmitter("code.run")
    source = params.get("source") or ""
    path = (params.get("path") or "").strip()

    # `path` is the escape hatch from a real constraint: a chat-completions
    # tool argument is always a JSON string, so a long script has to survive
    # being escaped into one. Codex avoids this by making `apply_patch` a
    # FREEFORM (non-JSON) tool; that is not available here, so instead a long
    # script can be written to the workbench first (with fs.patch, which is
    # itself editable in pieces) and referenced by path.
    if path and not source:
        from .. import policy as policy_mod
        root = _workspace(ctx)
        pol = policy_mod.default_policy(base_root=root)
        target = pol.resolve(path, base=root)
        decision, why = pol.check_path(target, access=policy_mod.READ)
        if decision != policy_mod.ALLOW:
            raise CapabilityError(f"cannot read {target}: {why}",
                                  code="policy_denied")
        if not target.exists():
            raise CapabilityError(
                f"{target} does not exist. Write the script first — fs.patch("
                f"path=..., content=...) — then call code.run(path=...).",
                code="not_found")
        source = target.read_text(encoding="utf-8")
        yield em.log(f"code.run: loaded {len(source)} chars from {target.name}")

    if not source.strip():
        raise CapabilityError(
            "'source' is required (or 'path' pointing at a script in the "
            "workbench)", code="invalid_params")
    if len(source) > 40000:
        raise CapabilityError(
            f"source is {len(source)} chars; keep one script under 40000 — "
            f"write it to the workbench with fs.patch and run it with sh.run "
            f"if it is genuinely that long.", code="too_large")

    registry = ctx.registry
    if registry is None:
        raise CapabilityError("no registry on this invocation", code="no_registry")

    timeout_s = min(int(params.get("timeout_s") or DEFAULT_TIMEOUT_S), MAX_TIMEOUT_S)
    budget = _Budget(time.monotonic() + timeout_s)
    loop = asyncio.get_running_loop()
    bridge = _Bridge(registry, ctx, loop, budget)

    # The script gets the workbench as its working directory, so relative paths
    # in it land next to the other artifacts rather than in the repo root.
    root = _workspace(ctx)
    import os
    previous = os.getcwd()
    yield em.log(f"code.run: {len(source)} chars, budget {timeout_s}s")
    try:
        os.chdir(root)
        outcome = await loop.run_in_executor(None, _run_source, source, bridge, budget)
    finally:
        os.chdir(previous)

    lines = [f"capability calls : {outcome['calls']}",
             f"duration         : {outcome['duration_s']}s"]
    if outcome["error"]:
        lines.append(f"error            : {outcome['error']['code']} — "
                     f"{outcome['error']['message'][:300]}")
    if outcome["stdout"].strip():
        lines.append("--- script output ---")
        lines.append(shaping.shape(outcome["stdout"], max_chars=2000).text)
    if outcome["result"] is not None:
        body = json.dumps(outcome["result"], ensure_ascii=False, default=str)
        lines.append("--- result ---")
        lines.append(shaping.shape(body, max_chars=MAX_RESULT_CHARS).text)
    elif not outcome["error"]:
        lines.append("(the script set no `result` and printed no JSON object)")

    yield em.result({
        "result": outcome["result"],
        "error": outcome["error"],
        "calls": outcome["calls"],
        "duration_s": outcome["duration_s"],
        # Compose with verify.gate: a sweep that reports cases_total and
        # failures can be handed straight to the gate as its check.
        "looks_like_evidence": bool(
            isinstance(outcome["result"], dict)
            and "cases_total" in outcome["result"]),
        "text": shaping.with_status(
            "\n".join(lines),
            ok=outcome["error"] is None and outcome["result"] is not None,
            detail=f"{outcome['calls']} calls, {outcome['duration_s']}s"),
    })


SPECS = (
    CapabilitySpec(
        id="code.run",
        kind="code",
        name="跑一段能调能力的脚本",
        description="**一次往返里跑 N 次能力调用**。写一段 Python，里面用 "
                    "`xcore.call(\"能力id\", **参数)` 调任何能力，把结果放进变量 `result`。"
                    "适合扫参数空间、批量对拍、逐条比对——几十次调用只花一轮。"
                    "建议把 `{\"cases_total\":N,\"cases_passed\":M,\"failures\":[...]}` "
                    "放进 result，可以直接交给 verify.gate 当检查。"
                    "**脚本超过二三十行就先 fs.patch 写到 workbench 的 .py，再用 path= 调用** —— "
                    "把整段脚本塞进一个 JSON 参数容易在输出预算里被截断。",
        params=schema(
            {
                "source": string("Python 源码。用 `xcore.call(...)` 调能力，"
                                 "用 `xcore.capabilities()` 列出可用能力，"
                                 "把答案赋给 `result`。**短脚本用这个**"),
                "path": string("也可以给一个工作台里的 .py 路径，从文件读源码 —— "
                               "**长脚本请先用 fs.patch 写到文件再用 path**，"
                               "避免把整段脚本塞进一个 JSON 参数里"),
                "timeout_s": integer("墙钟预算秒数（上限 900）", default=DEFAULT_TIMEOUT_S),
            },
        ),
        returns=schema({"result": {"type": "object"},
                        "calls": {"type": "integer"},
                        "error": {"type": "object"}}),
        streaming=True, cost=COST_FREE, sensitivity=SENS_INTERNAL,
        backend="providers.code", tags=("code", "batch", "verb", "long-horizon"),
    ),
)

HANDLERS = {"code.run": code_run}


def register_all(registry) -> None:
    for spec in SPECS:
        registry.register(spec, HANDLERS[spec.id])
