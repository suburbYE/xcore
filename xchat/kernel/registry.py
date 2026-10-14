"""
Kernel Channel — capability registry.

Holds the mapping from capability id to handler, enforces the contract, and
normalises failures into events. Consumers never see a raw traceback unless the
handler genuinely crashed.
"""

from __future__ import annotations

import traceback
from typing import AsyncIterator

from . import containment
from .contract import (
    EVENT_ERROR,
    EVENT_RESULT,
    EVENT_STARTED,
    CapabilityError,
    CapabilitySpec,
    Event,
    EventEmitter,
    InvokeContext,
    Registration,
    SENSITIVITY_ORDER,
)


class Registry:
    def __init__(self) -> None:
        self._caps: dict[str, Registration] = {}

    # ── registration ────────────────────────────────────────────────────
    def register(self, spec: CapabilitySpec, handler) -> None:
        if spec.id in self._caps:
            raise ValueError(f"capability '{spec.id}' already registered")
        if spec.sensitivity not in SENSITIVITY_ORDER:
            raise ValueError(
                f"capability '{spec.id}' has invalid sensitivity '{spec.sensitivity}'"
            )
        self._caps[spec.id] = Registration(spec=spec, handler=handler)

    def unregister(self, cap_id: str) -> bool:
        return self._caps.pop(cap_id, None) is not None

    def clear(self) -> None:
        self._caps.clear()

    # ── lookup ──────────────────────────────────────────────────────────
    def get(self, cap_id: str) -> Registration | None:
        return self._caps.get(cap_id)

    def has(self, cap_id: str) -> bool:
        return cap_id in self._caps

    def ids(self) -> list[str]:
        return sorted(self._caps)

    def specs(self, kind: str | None = None) -> list[dict]:
        """Serialisable specs — this is what the GUI renders forms from."""
        out = []
        for cap_id in sorted(self._caps):
            spec = self._caps[cap_id].spec
            if kind and spec.kind != kind:
                continue
            out.append(spec.to_dict())
        return out

    def kinds(self) -> list[str]:
        return sorted({r.spec.kind for r in self._caps.values()})

    def __len__(self) -> int:
        return len(self._caps)

    def __contains__(self, cap_id: object) -> bool:
        return cap_id in self._caps

    # ── invocation ──────────────────────────────────────────────────────
    async def invoke(self, cap_id: str, params: dict | None = None,
                     ctx: InvokeContext | None = None) -> AsyncIterator[Event]:
        """Run a capability, always yielding a well-formed event stream.

        Guarantees: at most one ``started`` event, always first when present;
        exactly one terminal event (``result`` or ``error``), always last.

        ``started`` is omitted for pre-flight rejections — an unknown capability
        id or a missing required parameter never begins executing, so announcing
        a start would be a lie. Consumers must therefore treat ``started`` as
        optional and key off the terminal event.

        ``CapabilityError`` becomes a clean error event; an unexpected exception
        is reported with a traceback in ``data.traceback`` so bugs stay
        debuggable instead of being flattened into a generic message.
        """
        params = params or {}
        ctx = ctx or InvokeContext()
        # Let orchestration capabilities (the agent) reach the channel they were
        # invoked through, without importing a module-level global.
        if ctx.registry is None:
            ctx.registry = self
        reg = self._caps.get(cap_id)
        em = EventEmitter(cap_id)

        if reg is None:
            yield em.error(f"unknown capability '{cap_id}'", code="unknown_capability",
                           known=self.ids())
            return

        # Validate required params before touching the handler so the caller
        # gets a precise message rather than a KeyError deep inside a provider.
        required = reg.spec.params.get("required", []) if reg.spec.params else []
        missing = [k for k in required if k not in params]
        if missing:
            yield em.error(
                f"missing required parameter(s): {', '.join(missing)}",
                code="invalid_params", missing=missing,
            )
            return

        yield em.started(params=params, request_id=ctx.request_id)

        # `seq` must be stream-scoped, not per-emitter. The dispatch emitter and
        # the handler's own emitter each start counting at 1, so a stream that
        # passes through both would carry duplicate sequence numbers — which
        # breaks any consumer that uses seq as a render key.
        seq = 1
        terminal = False
        try:
            async for ev in reg.handler(params, ctx):
                seq += 1
                ev.seq = seq
                if ev.type in (EVENT_RESULT, EVENT_ERROR):
                    terminal = True
                yield ev
        except CapabilityError as e:
            seq += 1
            err = em.error(str(e), code=e.code, detail=e.detail)
            err.seq = seq
            yield err
            terminal = True
        except Exception as e:  # noqa: BLE001 - contract boundary
            seq += 1
            err = em.error(
                f"{type(e).__name__}: {e}", code="internal_error",
                traceback=traceback.format_exc()[-2000:],
            )
            err.seq = seq
            yield err
            terminal = True

        if not terminal:
            # A handler that produced no terminal event is a contract violation;
            # say so rather than leaving consumers to hang waiting for one.
            seq += 1
            err = em.error(
                "capability finished without emitting a result or error",
                code="no_terminal_event",
            )
            err.seq = seq
            yield err


# Process-wide default registry. Providers register into this on import via
# `bootstrap()`; tests may build isolated Registries instead.
default = Registry()


def bootstrap(registry: Registry | None = None, *, reset: bool = False) -> Registry:
    """Register every built-in capability provider.

    Idempotent: calling it twice used to raise "already registered", which made
    any code path that defensively called it (the agent does) crash on the
    second call.
    """
    from .providers import agent as agent_provider
    from .providers import code as code_provider
    from .providers import engine as engine_provider
    from .providers import investigation as investigation_provider
    from .providers import jobs as jobs_provider
    from .providers import knowledge as knowledge_provider
    from .providers import llm as llm_provider
    from .providers import memory as memory_provider
    from .providers import native as native_provider
    from .providers import web as web_provider
    from .providers import workbench as workbench_provider

    reg = registry or default
    if reset:
        reg.clear()

    # Contain spawned processes before anything can spawn one. Until this ran,
    # a child started through `sh.run` outlived the process that started it —
    # measured, not assumed: kill the client mid-scan and the scan kept going.
    # Idempotent, best-effort, and it never raises; a machine that refuses the
    # job still runs xcore, it just says so.
    containment.contain_children()
    # Register only what is missing, so calling bootstrap() twice is a no-op
    # instead of raising "capability already registered" from deep inside a
    # provider — which is exactly what broke the first agent run.
    #
    # workbench goes first: it is the substrate the agent uses to reach
    # everything else, so a failure to register it should surface before the
    # domain capabilities that depend on the same working directory.
    for mod in (workbench_provider, code_provider, jobs_provider,
                investigation_provider, engine_provider, native_provider,
                web_provider, llm_provider, memory_provider,
                knowledge_provider, agent_provider):
        for spec in mod.SPECS:
            if not reg.has(spec.id):
                reg.register(spec, mod.HANDLERS[spec.id])
    return reg
