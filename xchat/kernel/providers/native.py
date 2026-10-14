"""
Capability provider: native-layer Node modules (modules/native/).

Wraps the APK / .so analysis toolchain that until now was only reachable
through `xcore_bridge.py`'s four ad-hoc functions.
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
    return [find_node(), str(PROJECT_ROOT / "modules" / "native" / script), *args]


async def _run_node(script: str, args: list[str], em: EventEmitter,
                    ctx: InvokeContext, timeout: float):
    argv = _node_argv(script, args)
    script_path = Path(argv[1])
    if not script_path.exists():
        raise CapabilityError(f"module not found: {script_path}", code="module_missing")
    ctx.check_cancelled()
    return await run_process(argv, em, ctx, timeout=timeout)


# ── native.target_scan ──────────────────────────────────────────────────────

async def target_scan(params: dict, ctx: InvokeContext):
    em = EventEmitter("native.target_scan")
    target = params["so"]
    if not Path(target).exists():
        raise CapabilityError(f"target not found: {target}", code="not_found")

    args = ["--so", str(Path(target).resolve()), "--json"]
    if params.get("fingerprints_dir"):
        args += ["--fingerprints-dir", params["fingerprints_dir"]]
    if params.get("max_scan_size") is not None:
        args += ["--max-scan-size", str(params["max_scan_size"])]

    proc, events = await _run_node("target_scanner.js", args, em, ctx,
                                   float(params.get("timeout", 600)))
    for ev in events:
        yield ev

    if proc.timed_out:
        yield em.error("target scan timed out", code="timeout")
        return

    payload = proc.json()
    if payload is None:
        yield em.error("target_scanner produced no JSON payload", code="no_payload",
                       output=proc.combined[-2000:])
        return
    if payload.get("degraded"):
        yield em.log("analysis degraded: " + ", ".join(payload.get("failed_layers", [])),
                     level="warning")
    yield em.result(payload, duration_ms=proc.duration_ms)


# ── native.shell_classify ───────────────────────────────────────────────────

async def shell_classify(params: dict, ctx: InvokeContext):
    em = EventEmitter("native.shell_classify")
    apk = params["apk"]
    if not Path(apk).exists():
        raise CapabilityError(f"apk not found: {apk}", code="not_found")

    args = ["--apk", str(Path(apk).resolve()),
            "--mode", params.get("mode", "passive"), "--json"]
    if params.get("output"):
        args += ["--output", params["output"]]

    proc, events = await _run_node("shell_classifier.js", args, em, ctx,
                                   float(params.get("timeout", 300)))
    for ev in events:
        yield ev

    # shell_classifier exits non-zero for heavy shells while still printing a
    # valid JSON verdict, so the payload — not the exit code — decides.
    payload = proc.json()
    if payload is None:
        yield em.error("shell_classifier produced no JSON payload", code="no_payload",
                       returncode=proc.returncode, output=proc.combined[-2000:])
        return
    yield em.result(payload, returncode=proc.returncode, duration_ms=proc.duration_ms)


# ── native.apk_pipeline ─────────────────────────────────────────────────────

async def apk_pipeline(params: dict, ctx: InvokeContext):
    em = EventEmitter("native.apk_pipeline")
    apk = params["apk"]
    if not Path(apk).exists():
        raise CapabilityError(f"apk not found: {apk}", code="not_found")

    args = ["--apk", str(Path(apk).resolve())]
    if params.get("output_dir"):
        args += ["--output-dir", params["output_dir"]]
    if params.get("spawn"):
        args.append("--spawn")

    proc, events = await _run_node("pipeline_native.js", args, em, ctx,
                                   float(params.get("timeout", 1800)))
    for ev in events:
        yield ev

    if proc.timed_out:
        yield em.error("apk pipeline timed out", code="timeout")
        return

    status = proc.json() or {}
    summary_file = status.get("summary_file")
    if summary_file and Path(summary_file).is_file():
        import json
        payload = json.loads(Path(summary_file).read_text(encoding="utf-8"))
        yield em.artifact(summary_file, kind="summary")
        yield em.result(payload, duration_ms=proc.duration_ms)
        return

    if status:
        yield em.result(status, duration_ms=proc.duration_ms,
                        note="pipeline status only; no summary.json located")
        return
    yield em.error("apk pipeline produced no parsable output", code="no_payload",
                   output=proc.combined[-2000:])


# ── native.probe_generate ───────────────────────────────────────────────────

async def probe_generate(params: dict, ctx: InvokeContext):
    em = EventEmitter("native.probe_generate")
    scan = params["scan_result"]
    if not Path(scan).exists():
        raise CapabilityError(f"scan result not found: {scan}", code="not_found")

    out_script = params.get("out") or str(
        Path(scan).resolve().parent / "frida_probe.js")
    args = ["--scan-result", str(Path(scan).resolve()), "--out", out_script]
    if params.get("spawn"):
        args.append("--spawn")
    if params.get("target_lib"):
        args += ["--target-lib", params["target_lib"]]

    proc, events = await _run_node("probe_generator.js", args, em, ctx,
                                   float(params.get("timeout", 300)))
    for ev in events:
        yield ev

    if not Path(out_script).is_file():
        yield em.error("probe_generator did not produce the script",
                       code="no_artifact", output=proc.combined[-1500:])
        return
    yield em.artifact(out_script, kind="frida_probe")
    yield em.result({"script": out_script}, duration_ms=proc.duration_ms)


# ── registration ────────────────────────────────────────────────────────────

SPECS = (
    CapabilitySpec(
        id="native.target_scan",
        kind="native",
        name="Native 靶心扫描 (Node)",
        description="modules/native/target_scanner.js — L1-L5 分层扫描与算法归因",
        params=schema(
            {
                "so": string("目标 .so / .dll"),
                "fingerprints_dir": string("指纹目录（可选）"),
                "max_scan_size": integer("最大扫描字节，0=全量（可选）"),
                "timeout": integer("超时秒数", default=600),
            },
            required=["so"],
        ),
        returns=schema({"verdict": {"type": "string"}}),
        streaming=True,
        cost=COST_LOCAL,
        sensitivity=SENS_INTERNAL,
        backend="providers.native",
        tags=("native", "scan"),
    ),
    CapabilitySpec(
        id="native.shell_classify",
        kind="native",
        name="APK 壳分类",
        description="识别 360/梆梆/爱加密/VMP/乐固/聚安全等商业壳",
        params=schema(
            {
                "apk": string("目标 APK"),
                "mode": string("passive | active", default="passive"),
                "output": string("输出目录（可选）"),
                "timeout": integer("超时秒数", default=300),
            },
            required=["apk"],
        ),
        returns=schema({"shell": {"type": "object"}}),
        streaming=True,
        cost=COST_LOCAL,
        sensitivity=SENS_INTERNAL,
        backend="providers.native",
        tags=("apk", "shell"),
    ),
    CapabilitySpec(
        id="native.apk_pipeline",
        kind="native",
        name="APK 全链路",
        description="壳分类 → .so 提取 → 靶心扫描 → Frida 探针生成",
        params=schema(
            {
                "apk": string("目标 APK"),
                "output_dir": string("输出目录（可选）"),
                "spawn": boolean("生成 spawn 模式探针", default=False),
                "timeout": integer("超时秒数", default=1800),
            },
            required=["apk"],
        ),
        returns=schema({"pipeline": {"type": "string"}}),
        streaming=True,
        cost=COST_LOCAL,
        sensitivity=SENS_INTERNAL,
        backend="providers.native",
        tags=("apk", "pipeline"),
    ),
    CapabilitySpec(
        id="native.probe_generate",
        kind="native",
        name="Frida 探针生成",
        description="从靶心扫描结果生成 JNI/RegisterNatives 截获脚本",
        params=schema(
            {
                "scan_result": string("target_scanner 输出的 JSON"),
                "out": string("输出脚本路径（可选）"),
                "spawn": boolean("spawn 模式", default=False),
                "target_lib": string("目标 so 名（可选）"),
                "timeout": integer("超时秒数", default=300),
            },
            required=["scan_result"],
        ),
        returns=schema({"script": {"type": "string"}}),
        streaming=True,
        cost=COST_LOCAL,
        sensitivity=SENS_INTERNAL,
        backend="providers.native",
        tags=("frida", "probe"),
    ),
)

HANDLERS = {
    "native.target_scan": target_scan,
    "native.shell_classify": shell_classify,
    "native.apk_pipeline": apk_pipeline,
    "native.probe_generate": probe_generate,
}


def register_all(registry) -> None:
    for spec in SPECS:
        registry.register(spec, HANDLERS[spec.id])
