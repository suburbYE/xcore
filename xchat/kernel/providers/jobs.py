"""
Capability provider: background jobs (submit / output / list / kill).

Any capability can be run in the background. The three controls match DSH's job
surface, which is deliberately tiny: one way to start, one to read, one to stop.

Why this exists at all: `engine.deobfuscate` and `native.apk_pipeline` take
minutes, so they had been banned from the agent's tool list and the agent could
therefore not perform either task it exists to perform. A minutes-long runtime
is a scheduling constraint, not a reason to remove a capability.
"""

from __future__ import annotations

import asyncio

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
from .. import jobs as jobmod
from .. import output as shaping


async def job_submit(params: dict, ctx: InvokeContext):
    em = EventEmitter("job.submit")
    capability = (params.get("capability") or "").strip()
    if not capability:
        raise CapabilityError("'capability' is required", code="invalid_params")

    registry = ctx.registry
    if registry is None:
        raise CapabilityError("no registry on this invocation", code="no_registry")
    if not registry.has(capability):
        raise CapabilityError(f"unknown capability {capability!r}",
                              code="unknown_capability")

    inner = dict(params.get("params") or {})
    # A job started from a job is a loop waiting to happen; the manager itself
    # is the only thing that may nest.
    if capability.startswith("job."):
        raise CapabilityError("cannot run a job control capability in the "
                              "background", code="invalid_params")

    job = jobmod.MANAGER.submit(capability, inner, registry, ctx,
                                label=str(params.get("label") or capability))
    yield em.log(f"job {job.id} started: {capability}")
    yield em.result({
        **job.to_dict(),
        "text": shaping.with_status(
            f"job {job.id} started ({capability}). It keeps running while you "
            f"do something else; read it with job.output, stop it with "
            f"job.kill. Do not busy-poll.",
            ok=True, detail=f"{job.id} running"),
    })


async def job_output(params: dict, ctx: InvokeContext):
    em = EventEmitter("job.output")
    job_id = (params.get("job_id") or "").strip()
    if not job_id:
        raise CapabilityError("'job_id' is required", code="invalid_params")

    if params.get("wait"):
        # Bounded wait. A timed-out wait leaves the job alive and says so,
        # rather than killing work the caller merely grew impatient with.
        deadline = float(params.get("timeout_s") or 30.0)
        step = 0.25
        waited = 0.0
        while waited < deadline:
            job = jobmod.MANAGER.get(job_id)
            if job is None or job.status in jobmod._TERMINAL:
                break
            await asyncio.sleep(step)
            waited += step

    read = jobmod.MANAGER.read(job_id)
    if read.get("error"):
        raise CapabilityError(f"no job {job_id}", code="not_found")

    job = read["job"]
    body = read["text"] or "(no new output)"
    yield em.result({
        **read,
        "text": shaping.with_status(
            body, ok=job["status"] == jobmod.COMPLETED,
            detail=f"{job['status']}, {job['duration_s']}s",
            extra={"new_lines": read["new_lines"]}),
    })


async def job_list(params: dict, ctx: InvokeContext):
    em = EventEmitter("job.list")
    rows = [j.to_dict() for j in jobmod.MANAGER.list()]
    lines = [f"  {j['id']}  {j['status']:<9} {j['duration_s']:>6}s  "
             f"{j['capability']}" for j in rows] or ["  (no jobs)"]
    yield em.result({
        "jobs": rows, "counts": jobmod.MANAGER.counts(),
        "text": shaping.with_status("\n".join(lines), ok=True,
                                    detail=f"{len(rows)} job(s)"),
    })


async def job_kill(params: dict, ctx: InvokeContext):
    em = EventEmitter("job.kill")
    job_id = (params.get("job_id") or "").strip()
    if not job_id:
        raise CapabilityError("'job_id' is required", code="invalid_params")
    outcome = jobmod.MANAGER.kill(job_id, str(params.get("reason") or ""))
    if outcome == "not_found":
        raise CapabilityError(f"no job {job_id}", code="not_found")
    yield em.result({
        "outcome": outcome, "job_id": job_id,
        "text": shaping.with_status(
            f"job {job_id}: {outcome}", ok=True, detail=outcome),
    })


SPECS = (
    CapabilitySpec(
        id="job.submit",
        kind="job",
        name="后台跑一个能力",
        description="把一个耗时能力丢到后台跑，立刻拿到 job_id。适合 engine.deobfuscate、"
                    "native.apk_pipeline 这类要跑几分钟的活 —— **不要傻等，也别重复提交**，"
                    "用 job.output 读进度、job.kill 停掉。",
        params=schema(
            {
                "capability": string("要跑的能力 id，例如 engine.deobfuscate"),
                "params": {"type": "object", "description": "该能力的参数"},
                "label": string("给这个作业起个名字，方便回头看"),
            },
            required=["capability"],
        ),
        returns=schema({"id": {"type": "string"}, "status": {"type": "string"}}),
        streaming=True, cost=COST_FREE, sensitivity=SENS_INTERNAL,
        backend="providers.jobs", tags=("job", "background", "long-running"),
    ),
    CapabilitySpec(
        id="job.output",
        kind="job",
        name="读取作业输出",
        description="读作业**自上次读取以来**的新输出，末尾带状态行。可用 wait=true 有界等待。",
        params=schema(
            {
                "job_id": string("作业 id"),
                "wait": {"type": "boolean", "description": "阻塞到结束或有界超时",
                         "default": False},
                "timeout_s": integer("wait 的最长秒数", default=30),
            },
            required=["job_id"],
        ),
        returns=schema({"job": {"type": "object"}, "text": {"type": "string"}}),
        streaming=True, cost=COST_FREE, sensitivity=SENS_INTERNAL,
        backend="providers.jobs", tags=("job", "background"),
    ),
    CapabilitySpec(
        id="job.list",
        kind="job",
        name="作业列表",
        description="列出所有作业及其状态。",
        params=schema({}),
        returns=schema({"jobs": {"type": "array"}}),
        streaming=True, cost=COST_FREE, sensitivity=SENS_INTERNAL,
        backend="providers.jobs", tags=("job", "background"),
    ),
    CapabilitySpec(
        id="job.kill",
        kind="job",
        name="终止作业",
        description="请求取消一个还在跑的作业。",
        params=schema(
            {
                "job_id": string("作业 id"),
                "reason": string("简短原因，会记进日志"),
            },
            required=["job_id"],
        ),
        returns=schema({"outcome": {"type": "string"}}),
        streaming=True, cost=COST_FREE, sensitivity=SENS_INTERNAL,
        backend="providers.jobs", tags=("job", "background"),
    ),
)

HANDLERS = {
    "job.submit": job_submit,
    "job.output": job_output,
    "job.list": job_list,
    "job.kill": job_kill,
}


def register_all(registry) -> None:
    for spec in SPECS:
        registry.register(spec, HANDLERS[spec.id])
