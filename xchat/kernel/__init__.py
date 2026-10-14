"""
Kernel Channel — the single contract every capability in xcore is exposed
through. See docs/client_architecture.md §2.2.

    from xchat.kernel import registry

    registry.bootstrap()
    async for event in registry.default.invoke("engine.db_stats", {}):
        print(event.type, event.data)
"""

from . import contract, registry  # noqa: F401
from .contract import (  # noqa: F401
    EVENT_ARTIFACT,
    EVENT_ERROR,
    EVENT_LOG,
    EVENT_PROGRESS,
    EVENT_RESULT,
    EVENT_STARTED,
    CapabilityError,
    CapabilitySpec,
    Event,
    InvokeContext,
)
from .registry import Registry, bootstrap  # noqa: F401

__all__ = [
    "contract", "registry", "Registry", "bootstrap",
    "CapabilitySpec", "CapabilityError", "Event", "InvokeContext",
    "EVENT_STARTED", "EVENT_PROGRESS", "EVENT_LOG", "EVENT_ARTIFACT",
    "EVENT_RESULT", "EVENT_ERROR",
]
