"""
Kernel Channel — the capability contract.

Design decision (see docs/client_architecture.md §2.2): the kernel channel is a
*contract*, not a component. Every capability in the system — the C++ engine,
Node modules, LLM routing, memory, vision, and later a Windows kernel driver —
registers here, and every consumer (GUI, CLI, MCP, automation) is a client of
the same interface.

Two consequences that shape this module:

1. **Everything is a stream.** ``invoke()`` returns an async iterator of Events,
   never a bare return value. Progress bars, CLI output and MCP responses are
   all rendered from the same event stream, so no consumer reimplements
   progress reporting. A capability that only produces a final value simply
   emits ``started`` then ``result``.

2. **The spec is data, the handler is code.** ``CapabilitySpec`` is fully
   JSON-serialisable so the GUI can render parameter forms from it without
   importing anything; the handler stays server-side and is never exposed.

The contract is deliberately language-neutral (plain dicts in, plain dicts out)
so that moving the registry from Python to Rust later is a migration, not a
rewrite of every provider.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Awaitable, Callable

# ── Event types ─────────────────────────────────────────────────────────────

EVENT_STARTED = "started"
EVENT_PROGRESS = "progress"
EVENT_LOG = "log"
EVENT_ARTIFACT = "artifact"
EVENT_RESULT = "result"
EVENT_ERROR = "error"

EVENT_TYPES = (EVENT_STARTED, EVENT_PROGRESS, EVENT_LOG, EVENT_ARTIFACT,
               EVENT_RESULT, EVENT_ERROR)

# ── Cost / sensitivity vocabularies ─────────────────────────────────────────
# cost drives budget policy; sensitivity decides whether a payload may leave
# the machine at all (see the scheduler's routing rules).

COST_FREE = "free"
COST_LOCAL = "local"
COST_CLOUD = "cloud"

SENS_PUBLIC = "public"        # safe to send anywhere
SENS_INTERNAL = "internal"    # must be sanitised before leaving the machine
SENS_SECRET = "secret"        # never leaves the machine

SENSITIVITY_ORDER = {SENS_PUBLIC: 0, SENS_INTERNAL: 1, SENS_SECRET: 2}


class CapabilityError(Exception):
    """Raised by a handler for a domain failure (bad params, missing file).

    Distinct from an unexpected exception: the registry converts this into a
    clean ``error`` event, whereas an unhandled exception is a bug and is
    reported with a traceback in the event payload.
    """

    def __init__(self, message: str, *, code: str = "failed", detail: str = ""):
        super().__init__(message)
        self.code = code
        self.detail = detail


@dataclass
class Event:
    """One item in a capability's output stream."""

    type: str
    capability: str
    data: dict = field(default_factory=dict)
    ts: float = 0.0
    seq: int = 0

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "capability": self.capability,
            "ts": self.ts or time.time(),
            "seq": self.seq,
            "data": self.data,
        }


@dataclass(frozen=True)
class CapabilitySpec:
    """Human/machine readable description of one capability.

    ``params`` and ``returns`` are JSON Schema fragments so the GUI can build
    forms and validate input without knowing anything about the implementation.
    """

    id: str
    kind: str                 # engine | web | native | llm | memory | vision | kernel
    name: str
    description: str = ""
    params: dict = field(default_factory=dict)
    returns: dict = field(default_factory=dict)
    streaming: bool = False
    cost: str = COST_LOCAL
    sensitivity: str = SENS_INTERNAL
    backend: str = ""         # which provider module implements this
    tags: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "name": self.name,
            "description": self.description,
            "params": self.params,
            "returns": self.returns,
            "streaming": self.streaming,
            "cost": self.cost,
            "sensitivity": self.sensitivity,
            "backend": self.backend,
            "tags": list(self.tags),
        }


@dataclass
class InvokeContext:
    """Per-invocation state handed to a handler."""

    request_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    session_id: str = ""
    # Cooperative cancellation: handlers should poll this in long loops.
    cancelled: Callable[[], bool] = field(default_factory=lambda: (lambda: False))
    # Free-form, provider-specific knobs (timeout override, device, etc).
    options: dict = field(default_factory=dict)
    # The registry this invocation came through, injected by Registry.invoke.
    # Capabilities that orchestrate other capabilities (the agent) need it, and
    # passing it here keeps them from reaching for a module-level global.
    registry: Any = None

    def check_cancelled(self) -> None:
        if self.cancelled():
            raise CapabilityError("cancelled", code="cancelled")


Handler = Callable[[dict, InvokeContext], AsyncIterator[Event]]
AsyncHandler = Callable[[dict, InvokeContext], Awaitable[Any]]


@dataclass
class Registration:
    spec: CapabilitySpec
    handler: Handler


# ── Small helpers providers share ───────────────────────────────────────────

class EventEmitter:
    """Sequences Event construction so providers don't repeat boilerplate."""

    def __init__(self, capability: str):
        self.capability = capability
        self._seq = 0

    def _next(self) -> int:
        self._seq += 1
        return self._seq

    def started(self, **data) -> Event:
        return Event(EVENT_STARTED, self.capability, data, time.time(), self._next())

    def progress(self, fraction: float | None = None, **data) -> Event:
        if fraction is not None:
            data = {"fraction": max(0.0, min(1.0, fraction)), **data}
        return Event(EVENT_PROGRESS, self.capability, data, time.time(), self._next())

    def log(self, message: str, level: str = "info") -> Event:
        return Event(EVENT_LOG, self.capability, {"message": message, "level": level},
                     time.time(), self._next())

    def artifact(self, path: str, kind: str = "", **data) -> Event:
        return Event(EVENT_ARTIFACT, self.capability,
                     {"path": path, "kind": kind, **data}, time.time(), self._next())

    def result(self, value: Any, **data) -> Event:
        return Event(EVENT_RESULT, self.capability, {"value": value, **data},
                     time.time(), self._next())

    def error(self, message: str, code: str = "failed", **data) -> Event:
        return Event(EVENT_ERROR, self.capability,
                     {"message": message, "code": code, **data},
                     time.time(), self._next())


def schema(properties: dict, required: list[str] | None = None,
           **extra) -> dict:
    """Build a JSON Schema object node. Keeps provider specs terse."""
    node = {"type": "object", "properties": properties, "additionalProperties": False}
    if required:
        node["required"] = required
    node.update(extra)
    return node


def string(description: str = "", **kw) -> dict:
    return {"type": "string", "description": description, **kw}


def integer(description: str = "", **kw) -> dict:
    return {"type": "integer", "description": description, **kw}


def boolean(description: str = "", default: bool | None = None, **kw) -> dict:
    node = {"type": "boolean", "description": description, **kw}
    if default is not None:
        node["default"] = default
    return node
