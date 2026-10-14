"""
Capability provider: the C++ engine (xcore.exe).

This is the provider `xcore_bridge.py` claimed to be but wasn't — that module's
docstring says "wraps xcore CLI" while in fact every one of its functions shells
out to a Node script, and `run_web_pipeline` is an unimplemented stub. This one
actually drives xcore.exe.

Only read-only / analysis subcommands are exposed. `pipe` (stdin streaming) and
`classify` (which needs an LLM key and blocks on input) are deliberately left
out until they can be modelled as proper streaming capabilities.
"""

from __future__ import annotations

from pathlib import Path

from ..contract import (
    COST_LOCAL,
    SENS_INTERNAL,
    CapabilityError,
    CapabilitySpec,
    Event,
    EventEmitter,
    InvokeContext,
    boolean,
    integer,
    schema,
    string,
)
from .proc import PROJECT_ROOT, RULES_PATH, XCORE_BIN, run_process


async def _ensure_binary() -> None:
    if not XCORE_BIN.exists():
        raise CapabilityError(
            f"xcore.exe not found at {XCORE_BIN}. Build it with build.bat.",
            code="engine_missing",
        )


async def _run_xcore(params: dict, ctx: InvokeContext, argv: list[str],
                     em: EventEmitter, *, timeout: float = 300.0):
    """Shared driver: run xcore, echo output as log events, return (proc, events)."""
    await _ensure_binary()
    ctx.check_cancelled()
    proc, events = await run_process(argv, em, ctx, timeout=timeout)
    return proc, events


# ── engine.scan ─────────────────────────────────────────────────────────────

async def scan(params: dict, ctx: InvokeContext):
    em = EventEmitter("engine.scan")
    target = params["file"]
    if not Path(target).exists():
        raise CapabilityError(f"target not found: {target}", code="not_found")

    argv = [str(XCORE_BIN), "scan", target, str(params.get("rules") or RULES_PATH)]
    if params.get("fingerprints_dir"):
        argv += ["--fingerprints-dir", params["fingerprints_dir"]]
    if params.get("brief"):
        argv.append("--brief")
    argv.append("--json")

    proc, events = await _run_xcore(params, ctx, argv, em,
                                    timeout=float(params.get("timeout", 300)))
    for ev in events:
        yield ev

    if proc.timed_out:
        yield em.error(f"scan timed out after {proc.duration_ms}ms", code="timeout")
        return

    payload = proc.json()
    if payload is None:
        # xcore prints human-readable hit lines when --json yields nothing
        # (e.g. a clean file); surface the raw output rather than a bare error.
        yield em.result({"hits": [], "raw_output": proc.combined[-4000:]},
                        returncode=proc.returncode, duration_ms=proc.duration_ms,
                        note="no JSON payload; returned raw output")
        return

    yield em.result(payload, returncode=proc.returncode,
                    duration_ms=proc.duration_ms)


# ── engine.native_scan ──────────────────────────────────────────────────────

async def native_scan(params: dict, ctx: InvokeContext):
    em = EventEmitter("engine.native_scan")
    target = params["so"]
    if not Path(target).exists():
        raise CapabilityError(f"target not found: {target}", code="not_found")

    argv = [str(XCORE_BIN), "native", "--so", target, "--json"]
    if params.get("fingerprints_dir"):
        argv += ["--fingerprints-dir", params["fingerprints_dir"]]
    if params.get("max_scan_size") is not None:
        argv += ["--max-scan-size", str(params["max_scan_size"])]

    proc, events = await _run_xcore(params, ctx, argv, em,
                                    timeout=float(params.get("timeout", 600)))
    for ev in events:
        yield ev

    if proc.timed_out:
        yield em.error(f"native scan timed out after {proc.duration_ms}ms",
                       code="timeout")
        return

    payload = proc.json()
    if payload is None:
        yield em.error("native scan produced no JSON payload", code="no_payload",
                       returncode=proc.returncode,
                       output=proc.combined[-2000:])
        return

    # Surface a degraded analysis as a first-class signal: a scan whose layers
    # crashed must not be read as "clean" (see target_scanner's failed_layers).
    if payload.get("degraded"):
        yield em.log(
            "analysis degraded: " + ", ".join(payload.get("failed_layers", [])),
            level="warning",
        )
    yield em.result(payload, returncode=proc.returncode,
                    duration_ms=proc.duration_ms)


# ── engine.db_stats ─────────────────────────────────────────────────────────

async def db_stats(params: dict, ctx: InvokeContext):
    em = EventEmitter("engine.db_stats")
    argv = [str(XCORE_BIN), "db", "stats"]
    if params.get("db"):
        argv += ["--db", params["db"]]

    proc, events = await _run_xcore(params, ctx, argv, em, timeout=60.0)
    for ev in events:
        yield ev

    payload = proc.json()
    if payload is None:
        yield em.error("db stats produced no JSON payload", code="no_payload",
                       output=proc.combined[-1000:])
        return
    yield em.result(payload)


# ── engine.deobfuscate ──────────────────────────────────────────────────────

async def deobfuscate(params: dict, ctx: InvokeContext):
    em = EventEmitter("engine.deobfuscate")
    target = params["file"]
    if not Path(target).exists():
        raise CapabilityError(f"target not found: {target}", code="not_found")

    argv = [str(XCORE_BIN), "deobfuscate", target]
    if params.get("output"):
        argv += ["--output", params["output"]]
    if params.get("entry"):
        argv += ["--entry", params["entry"]]
    if params.get("verify"):
        argv.append("--verify")

    proc, events = await _run_xcore(params, ctx, argv, em,
                                    timeout=float(params.get("timeout", 900)))
    for ev in events:
        yield ev

    if proc.timed_out:
        yield em.error(f"deobfuscate timed out after {proc.duration_ms}ms",
                       code="timeout")
        return

    # This pipeline legitimately fails when the target has no instrumentable
    # state machine; report exit status honestly instead of dressing it up.
    if proc.returncode != 0:
        yield em.error(
            "deobfuscate pipeline did not complete (see logs above)",
            code="pipeline_failed", returncode=proc.returncode,
            duration_ms=proc.duration_ms,
        )
        return

    yield em.result({"returncode": proc.returncode},
                    duration_ms=proc.duration_ms,
                    output=proc.combined[-2000:])


# ── engine.verify ───────────────────────────────────────────────────────────

async def verify(params: dict, ctx: InvokeContext):
    em = EventEmitter("engine.verify")
    for key in ("original", "flattened"):
        if not Path(params[key]).exists():
            raise CapabilityError(f"{key} not found: {params[key]}", code="not_found")

    argv = [str(XCORE_BIN), "verify", params["original"], params["flattened"]]
    proc, events = await _run_xcore(params, ctx, argv, em,
                                    timeout=float(params.get("timeout", 600)))
    for ev in events:
        yield ev

    yield em.result(
        {"matched": proc.returncode == 0 and "PASS" in proc.combined,
         "returncode": proc.returncode},
        duration_ms=proc.duration_ms,
        output=proc.combined[-2000:],
    )


# ── registration ────────────────────────────────────────────────────────────

SPECS = (
    CapabilitySpec(
        id="engine.scan",
        kind="engine",
        name="规则扫描",
        description="对文件做 hex/string/entropy 分层规则匹配 + 判例库相似度",
        params=schema(
            {
                "file": string("待扫描文件路径"),
                "rules": string("规则文件，默认 rules/rules.json"),
                "fingerprints_dir": string("指纹目录（可选）"),
                "brief": boolean("仅输出命中摘要", default=False),
                "timeout": integer("超时秒数", default=300),
            },
            required=["file"],
        ),
        returns=schema({"hits": {"type": "array"}}, ),
        streaming=True,
        cost=COST_LOCAL,
        sensitivity=SENS_INTERNAL,
        backend="providers.engine",
        tags=("scan", "rules"),
    ),
    CapabilitySpec(
        id="engine.native_scan",
        kind="engine",
        name="Native 靶心扫描",
        description="L1-L5 多维扫描（字符串/常量/符号/指纹/CFG），输出 verdict 与算法归因",
        params=schema(
            {
                "so": string("目标 .so / .dll 路径"),
                "fingerprints_dir": string("指纹目录（可选）"),
                "max_scan_size": integer("最大扫描字节数，0=全量（可选）"),
                "timeout": integer("超时秒数", default=600),
            },
            required=["so"],
        ),
        returns=schema({
            "verdict": {"type": "string"},
            "final_score": {"type": "number"},
            "layers": {"type": "object"},
        }),
        streaming=True,
        cost=COST_LOCAL,
        sensitivity=SENS_INTERNAL,
        backend="providers.engine",
        tags=("native", "scan"),
    ),
    CapabilitySpec(
        id="engine.db_stats",
        kind="engine",
        name="判例库统计",
        description="SQLite 判例库的算法分布与置信度统计",
        params=schema({"db": string("判例库路径（可选）")}),
        returns=schema({"total_cases": {"type": "integer"}}),
        cost=COST_LOCAL,
        sensitivity=SENS_INTERNAL,
        backend="providers.engine",
        tags=("db",),
    ),
    CapabilitySpec(
        id="engine.deobfuscate",
        kind="engine",
        name="控制流去混淆",
        description="AST 插桩 → 沙盒 trace → 原生 flatten → 死分支剔除 → 等价性验证",
        params=schema(
            {
                "file": string("目标 JS 文件"),
                "entry": string("入口表达式，如 window.MySign.sign"),
                "output": string("输出目录（可选）"),
                "verify": boolean("跑等价性验证", default=False),
                "timeout": integer("超时秒数", default=900),
            },
            required=["file"],
        ),
        returns=schema({"returncode": {"type": "integer"}}),
        streaming=True,
        cost=COST_LOCAL,
        sensitivity=SENS_INTERNAL,
        backend="providers.engine",
        tags=("deobfuscate",),
    ),
    CapabilitySpec(
        id="engine.verify",
        kind="engine",
        name="等价性验证",
        description="对比原始与扁平化 JS 的行为是否字节一致",
        params=schema(
            {"original": string("原始 JS"), "flattened": string("扁平化后 JS")},
            required=["original", "flattened"],
        ),
        returns=schema({"matched": {"type": "boolean"}}),
        streaming=True,
        cost=COST_LOCAL,
        sensitivity=SENS_INTERNAL,
        backend="providers.engine",
        tags=("verify",),
    ),
)

HANDLERS = {
    "engine.scan": scan,
    "engine.native_scan": native_scan,
    "engine.db_stats": db_stats,
    "engine.deobfuscate": deobfuscate,
    "engine.verify": verify,
}


def register_all(registry) -> None:
    for spec in SPECS:
        registry.register(spec, HANDLERS[spec.id])
