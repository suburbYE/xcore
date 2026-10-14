"""
Background jobs: the thing that lets a long capability run without blocking.

The problem this solves is specific. `engine.deobfuscate` and
`native.apk_pipeline` take minutes, so they were excluded from the agent's tool
list (`AGENT_DENY`) — with the result that the agent could not do either of the
two headline tasks. But "takes minutes" is a *scheduling* problem, not a reason
to exclude a capability.

Codex reaches the same conclusion from the other direction: there is no
`background` argument at all, because backgrounding is implicit. A call blocks
at most 30 s and, if still alive, comes back with a `session_id` the model can
poll. DSH adds the other half — completion is *pushed* to the owner rather than
polled.

xcore's loop is turn-based and synchronous, so a true push is not available
mid-turn. The equivalent is: finished jobs are collected at each round boundary
and injected into the transcript as a notice. That is a pull at a natural
boundary, and for a loop that only observes the world between rounds it is
indistinguishable from a push.

Incremental reads matter for cost too: `read()` returns only output produced
since the previous read, so watching a long job does not re-bill its whole
output every time.
"""

from __future__ import annotations

import asyncio
import threading
import time
import uuid
from dataclasses import dataclass, field

RUNNING = "running"
COMPLETED = "completed"
FAILED = "failed"
KILLED = "killed"

_TERMINAL = (COMPLETED, FAILED, KILLED)

# Per-read cap. A long job can emit megabytes; the model sees a bounded window
# and the full log stays on disk via the capability's own artifact events.
MAX_READ_CHARS = 6000


@dataclass
class Job:
    id: str
    capability: str
    params: dict
    label: str = ""
    status: str = RUNNING
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0
    result: dict | None = None
    error: dict | None = None
    # Append-only output. `cursor` is per-job and shared, because "since the
    # last read" is a property of the reader's position, not of the job.
    output: list[str] = field(default_factory=list)
    cursor: int = 0
    reported: bool = False      # completion notice already surfaced to the agent
    task: object | None = None
    cancelled: bool = False

    def to_dict(self) -> dict:
        return {
            "id": self.id, "capability": self.capability, "label": self.label,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at or None,
            "duration_s": round((self.finished_at or time.time()) - self.started_at, 1),
            "error": (self.error or {}).get("message") if self.error else None,
        }


class JobManager:
    """Owns running jobs. One per process; the registry injects it via ctx."""

    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._lock = threading.RLock()

    def submit(self, capability: str, params: dict, registry,
               ctx, label: str = "") -> Job:
        job = Job(id=uuid.uuid4().hex[:12], capability=capability,
                  params=dict(params), label=label or capability)
        with self._lock:
            self._jobs[job.id] = job

        async def run() -> None:
            try:
                from .contract import InvokeContext
                from . import EVENT_RESULT, EVENT_ERROR, EVENT_LOG, EVENT_ARTIFACT
                sub = InvokeContext(session_id=ctx.session_id,
                                    cancelled=lambda: job.cancelled)
                async for ev in registry.invoke(capability, params, sub):
                    if job.cancelled:
                        break
                    if ev.type == EVENT_RESULT:
                        job.result = ev.data.get("value")
                    elif ev.type == EVENT_ERROR:
                        job.error = ev.data
                    elif ev.type == EVENT_LOG:
                        job.output.append(str(ev.data.get("message", "")))
                    elif ev.type == EVENT_ARTIFACT:
                        job.output.append(f"[artifact] {ev.data.get('path')}")
                job.status = (KILLED if job.cancelled
                              else FAILED if job.error else COMPLETED)
            except Exception as exc:  # noqa: BLE001 - a job must always settle
                job.error = {"message": f"{type(exc).__name__}: {exc}",
                             "code": "job_failed"}
                job.status = FAILED
            finally:
                job.finished_at = time.time()

        job.task = asyncio.ensure_future(run())
        return job

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def list(self) -> list[Job]:
        with self._lock:
            return sorted(self._jobs.values(), key=lambda j: j.started_at,
                          reverse=True)

    def read(self, job_id: str) -> dict:
        """Output since the previous read, plus the status line.

        Every read ends with the status so a model cannot mistake a partial
        stream for a finished result — the same reason DSH appends
        `[status: ...]` to every job read.
        """
        job = self.get(job_id)
        if job is None:
            return {"error": "no such job", "job_id": job_id}
        with self._lock:
            fresh = job.output[job.cursor:]
            job.cursor = len(job.output)
        text = "\n".join(fresh)
        truncated = len(text) > MAX_READ_CHARS
        if truncated:
            text = text[:MAX_READ_CHARS] + f"\n…[{len(text)} chars, truncated]"
        return {"job": job.to_dict(), "text": text,
                "new_lines": len(fresh), "truncated": truncated}

    def kill(self, job_id: str, reason: str = "") -> str:
        job = self.get(job_id)
        if job is None:
            return "not_found"
        if job.status in _TERMINAL:
            return "already-finished"
        job.cancelled = True
        if job.task is not None:
            job.task.cancel()
        job.status = KILLED
        job.finished_at = time.time()
        if reason:
            job.output.append(f"[killed] {reason}")
        return "cancellation-requested"

    def settled_unreported(self) -> list[Job]:
        """Finished jobs whose completion has not yet been surfaced.

        This is what replaces a push notification in a turn-based loop: the
        agent loop asks at each round boundary instead of being interrupted.
        """
        out = []
        with self._lock:
            for job in self._jobs.values():
                if job.status in _TERMINAL and not job.reported:
                    job.reported = True
                    out.append(job)
        return out

    def counts(self) -> dict:
        with self._lock:
            jobs = list(self._jobs.values())
        return {
            "total": len(jobs),
            "running": sum(1 for j in jobs if j.status == RUNNING),
            "completed": sum(1 for j in jobs if j.status == COMPLETED),
            "failed": sum(1 for j in jobs if j.status == FAILED),
            "killed": sum(1 for j in jobs if j.status == KILLED),
        }


# One manager per process. Kept module-level rather than threaded through the
# registry because jobs outlive the invocation that created them — that is the
# entire point — so their owner cannot be the InvokeContext.
MANAGER = JobManager()
