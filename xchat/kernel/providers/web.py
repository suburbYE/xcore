"""
Capability provider: web-layer Node modules (modules/web/).

Exposes the v0.21 web pipeline (fetch/probe/wasm/jsvm) that previously had no
route into the Python side at all — `xcore_bridge.run_web_pipeline` was an
unimplemented stub.
"""

from __future__ import annotations

from pathlib import Path

from ..contract import (
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
from .proc import PROJECT_ROOT, find_node, run_process


def _node_argv(script: str, args: list[str]) -> list[str]:
    return [find_node(), str(PROJECT_ROOT / "modules" / "web" / script), *args]


async def _run_node(script: str, args: list[str], em: EventEmitter,
                    ctx: InvokeContext, timeout: float):
    argv = _node_argv(script, args)
    script_path = Path(argv[1])
    if not script_path.exists():
        raise CapabilityError(f"module not found: {script_path}", code="module_missing")
    ctx.check_cancelled()
    return await run_process(argv, em, ctx, timeout=timeout)


# ── web.pipeline ────────────────────────────────────────────────────────────

async def pipeline(params: dict, ctx: InvokeContext):
    em = EventEmitter("web.pipeline")
    if not params.get("url") and not params.get("html"):
        raise CapabilityError("either 'url' or 'html' is required",
                              code="invalid_params")
    if params.get("html") and not Path(params["html"]).exists():
        raise CapabilityError(f"html not found: {params['html']}", code="not_found")

    args = []
    if params.get("url"):
        args += ["--url", params["url"]]
    else:
        args += ["--html", str(Path(params["html"]).resolve())]
    if params.get("out"):
        args += ["--out", params["out"]]
    if params.get("depth") is not None:
        args += ["--depth", str(params["depth"])]
    args.append("--json")

    proc, events = await _run_node("pipeline_web.js", args, em, ctx,
                                   float(params.get("timeout", 300)))
    for ev in events:
        yield ev

    if proc.timed_out:
        yield em.error("web pipeline timed out", code="timeout")
        return

    payload = proc.json()
    if payload is None:
        yield em.error("pipeline_web produced no JSON payload", code="no_payload",
                       output=proc.combined[-2000:])
        return

    for path in payload.get("artifacts", []) or []:
        yield em.artifact(path, kind="web_artifact")

    failed = (payload.get("stages", {}).get("fetch", {}) or {}).get("failedScripts")
    if failed:
        yield em.log(f"{len(failed)} script(s) could not be fetched", level="warning")

    yield em.result(payload, duration_ms=proc.duration_ms)


# ── web.wasm ────────────────────────────────────────────────────────────────

async def wasm(params: dict, ctx: InvokeContext):
    em = EventEmitter("web.wasm")
    target = params.get("file")
    if target and not Path(target).exists():
        raise CapabilityError(f"wasm not found: {target}", code="not_found")

    args = ["--file", str(Path(target).resolve())] if target else ["--dir", params["dir"]]
    if params.get("strings"):
        args.append("--strings")
    args.append("--json")

    proc, events = await _run_node("wasm_analyzer.js", args, em, ctx,
                                   float(params.get("timeout", 300)))
    for ev in events:
        yield ev

    payload = proc.json()
    if payload is None:
        yield em.error("wasm_analyzer produced no JSON payload", code="no_payload",
                       output=proc.combined[-2000:])
        return
    yield em.result(payload, duration_ms=proc.duration_ms)


# ── web.jsvm ────────────────────────────────────────────────────────────────

async def jsvm(params: dict, ctx: InvokeContext):
    em = EventEmitter("web.jsvm")
    target = params.get("file")
    if target and not Path(target).exists():
        raise CapabilityError(f"file not found: {target}", code="not_found")

    args = ["--file", str(Path(target).resolve())] if target else ["--dir", params["dir"]]
    if params.get("strings"):
        args.append("--strings")
    if params.get("key") is not None:
        args += ["--key", str(params["key"])]
    if params.get("out"):
        args += ["--out", params["out"]]
    args.append("--json")

    proc, events = await _run_node("jsvm_analyzer.js", args, em, ctx,
                                   float(params.get("timeout", 300)))
    for ev in events:
        yield ev

    payload = proc.json()
    if payload is None:
        yield em.error("jsvm_analyzer produced no JSON payload", code="no_payload",
                       output=proc.combined[-2000:])
        return
    yield em.result(payload, duration_ms=proc.duration_ms)


# ── registration ────────────────────────────────────────────────────────────

SPECS = (
    CapabilitySpec(
        id="web.pipeline",
        kind="web",
        name="Web 全链路分析",
        description="抓取/解析 HTML → 脚本外链与端点提取 → 签名参数探测 → WASM/JSVM 分析",
        params=schema(
            {
                "url": string("目标 URL（与 html 二选一）"),
                "html": string("本地 HTML 路径（与 url 二选一）"),
                "out": string("输出目录（可选，默认 temp/web_out）"),
                "depth": integer("递归深度", default=1),
                "timeout": integer("超时秒数", default=300),
            },
        ),
        returns=schema({"stages": {"type": "object"}}),
        streaming=True,
        cost=COST_LOCAL,
        sensitivity=SENS_INTERNAL,
        backend="providers.web",
        tags=("web", "pipeline"),
    ),
    CapabilitySpec(
        id="web.wasm",
        kind="web",
        name="WASM 结构分析",
        description="段/导入/导出/类型签名还原 + 控制流平坦化启发式 + 框架识别",
        params=schema(
            {
                "file": string("单个 .wasm 文件"),
                "dir": string("或目录（与 file 二选一）"),
                "strings": boolean("提取字符串表", default=False),
                "timeout": integer("超时秒数", default=300),
            },
        ),
        returns=schema({"sections": {"type": "array"}}),
        streaming=True,
        cost=COST_LOCAL,
        sensitivity=SENS_INTERNAL,
        backend="providers.web",
        tags=("web", "wasm"),
    ),
    CapabilitySpec(
        id="web.jsvm",
        kind="web",
        name="JSVM 字节码分析",
        description="定位 JS 内嵌 VM 解释器，提取操作码表与字符串表",
        params=schema(
            {
                "file": string("HTML 或 JS 文件"),
                "dir": string("或目录（与 file 二选一）"),
                "strings": boolean("提取字符串表", default=False),
                "key": integer("异或密钥（可选，自动爆破）"),
                "out": string("输出目录（可选）"),
                "timeout": integer("超时秒数", default=300),
            },
        ),
        returns=schema({"runtimes": {"type": "array"}}),
        streaming=True,
        cost=COST_LOCAL,
        sensitivity=SENS_INTERNAL,
        backend="providers.web",
        tags=("web", "jsvm"),
    ),
)

HANDLERS = {
    "web.pipeline": pipeline,
    "web.wasm": wasm,
    "web.jsvm": jsvm,
}


def register_all(registry) -> None:
    for spec in SPECS:
        registry.register(spec, HANDLERS[spec.id])
