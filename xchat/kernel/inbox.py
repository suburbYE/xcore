"""
Inbox: messages that arrive while a turn is already running.

Two modes, and the split is the same one DSH makes between `nextStep` and
`nextTurn`:

**interject** — the message joins the turn that is already running, at its next
round boundary. That is the useful form of "steering": the agent has just
finished a tool call and is about to decide what to do next, which is exactly
the moment a new thought from the human can change the plan. It cannot
interrupt a tool call in flight, and pretending otherwise would be a lie.

**queue** — the message waits until the running turn finishes and is then sent
as a fresh turn. Nothing is interrupted; the thought is simply not lost.

Why a boundary and not a callback: the agent loop already stops at each round
to assemble context. Checking an inbox there costs nothing and needs no
cancellation machinery — and it means an interjection is never delivered
half-way through a tool call, which would leave the transcript inconsistent.

In-memory on purpose. A pending interjection is only meaningful while a turn is
running, and a restart invalidates it; the durable record is the conversation
itself, which is written to disk as each turn completes.
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field

INTERJECT = "interject"
QUEUE = "queue"

# A turn will absorb at most this many interjections. Beyond that the agent is
# being steered faster than it can act, and the honest move is to leave the rest
# for the next turn rather than thrash.
MAX_INTERJECT_PER_TURN = 4


@dataclass
class Note:
    text: str
    mode: str = QUEUE
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    ts: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {"id": self.id, "text": self.text, "mode": self.mode, "ts": self.ts}


class Inbox:
    def __init__(self) -> None:
        self._by_conv: dict[str, list[Note]] = {}
        self._lock = threading.RLock()

    def push(self, conversation_id: str, text: str, mode: str = QUEUE) -> Note:
        note = Note(text=text, mode=mode if mode in (INTERJECT, QUEUE) else QUEUE)
        with self._lock:
            self._by_conv.setdefault(conversation_id or "", []).append(note)
        return note

    def pending(self, conversation_id: str) -> list[dict]:
        with self._lock:
            return [n.to_dict() for n in self._by_conv.get(conversation_id or "", [])]

    def take_interjections(self, conversation_id: str,
                           limit: int = MAX_INTERJECT_PER_TURN) -> list[Note]:
        """Remove and return interjections, oldest first.

        Interjections are consumed by the running turn, so they are removed
        here; queued notes stay put until the turn is over.
        """
        with self._lock:
            items = self._by_conv.get(conversation_id or "", [])
            taken = [n for n in items if n.mode == INTERJECT][:limit]
            if taken:
                remaining = [n for n in items if n not in taken]
                self._by_conv[conversation_id or ""] = remaining
            return taken

    def take_queued(self, conversation_id: str, limit: int = 1) -> list[Note]:
        """Remove and return queued notes — called once the turn is finished."""
        with self._lock:
            items = self._by_conv.get(conversation_id or "", [])
            taken = [n for n in items if n.mode == QUEUE][:limit]
            if taken:
                remaining = [n for n in items if n not in taken]
                self._by_conv[conversation_id or ""] = remaining
            return taken

    def clear(self, conversation_id: str = "") -> int:
        with self._lock:
            if conversation_id:
                return len(self._by_conv.pop(conversation_id, []))
            n = sum(len(v) for v in self._by_conv.values())
            self._by_conv.clear()
            return n


# Process-wide: an interjection has to reach a turn that is already executing,
# so it cannot be scoped to the invocation that happens to be starting it.
INBOX = Inbox()
