"""
Parallel execution semantics for routed LLM tasks.

Three shapes, each answering a different question:

* ``fanout`` — "these subtasks are independent, run them at once." Buys
  throughput. Nothing is duplicated, so nothing is billed twice.
* ``race`` — "I need this answer fast; ask several and take the winner."
  Buys latency at the cost of paying N times. Only worth it when the task is
  cheap or the wait is expensive.
* ``hedge`` — "send one, and only if it is slow send a backup." The tail-latency
  compromise: normally costs one call, occasionally two.

Every attempt is written to the usage ledger, including the losers of a race —
otherwise the cost report would understate what a race actually spends, which
is precisely the number needed to decide whether racing is worth it.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field

from .routing import Router, Task, Target


@dataclass
class Attempt:
    target_id: str
    ok: bool
    text: str = ""
    error: str = ""
    latency_ms: int = 0
    cost_usd: float = 0.0
    cancelled: bool = False


@dataclass
class Outcome:
    """Result of an execution, with enough detail to audit the decision."""

    text: str = ""
    winner: str = ""
    attempts: list[Attempt] = field(default_factory=list)
    strategy: str = ""

    @property
    def ok(self) -> bool:
        return bool(self.text)

    @property
    def total_cost_usd(self) -> float:
        return sum(a.cost_usd for a in self.attempts)

    @property
    def wasted_cost_usd(self) -> float:
        """Spend on attempts that did not produce the winning answer."""
        return sum(a.cost_usd for a in self.attempts if a.target_id != self.winner)

    def to_dict(self) -> dict:
        return {
            "strategy": self.strategy,
            "winner": self.winner,
            "ok": self.ok,
            "total_cost_usd": round(self.total_cost_usd, 6),
            "wasted_cost_usd": round(self.wasted_cost_usd, 6),
            "attempts": [
                {"target": a.target_id, "ok": a.ok, "latency_ms": a.latency_ms,
                 "cost_usd": round(a.cost_usd, 6), "cancelled": a.cancelled,
                 "error": a.error[:200]}
                for a in self.attempts
            ],
        }


# A caller is anything that can turn (Task, Target) into (text, usage).
# The LLM provider supplies this; tests supply a fake.
Caller = "Callable[[Task, Target], Awaitable[Attempt]]"


class Executor:
    def __init__(self, router: Router, caller):
        self.router = router
        self.caller = caller

    async def single(self, task: Task, target: Target | None = None,
                     cloud_targets=None) -> Outcome:
        route = self.router.route(task, cloud_targets)
        chosen = target or route.best
        if chosen is None:
            return Outcome(strategy="single",
                           attempts=[Attempt("none", False,
                                             error=route.reason)])
        att = await self.caller(task, chosen)
        return Outcome(text=att.text, winner=chosen.id if att.ok else "",
                       attempts=[att], strategy="single")

    async def fanout(self, tasks: list[Task], cloud_targets=None) -> list[Outcome]:
        """Independent subtasks, routed individually, run concurrently.

        Each task picks its own target — a light one may stay local while a
        heavy sibling goes to cloud in the same batch.
        """
        async def one(t: Task) -> Outcome:
            return await self.single(t, cloud_targets=cloud_targets)

        return list(await asyncio.gather(*(one(t) for t in tasks)))

    async def race(self, task: Task, n: int = 2, cloud_targets=None,
                   min_delay_ms: int = 0) -> Outcome:
        """Ask up to `n` targets at once; first success wins, rest are cancelled.

        Timing out at ``min_delay_ms`` staggers the start so a clearly-faster
        primary usually wins before the duplicates are even billed.
        """
        route = self.router.route(task, cloud_targets)
        targets = [t for t, _ in route.ranked[:max(1, n)]]
        if not targets:
            return Outcome(strategy="race",
                           attempts=[Attempt("none", False, error=route.reason)])

        async def attempt(target: Target, delay_ms: int) -> Attempt:
            if delay_ms:
                await asyncio.sleep(delay_ms / 1000.0)
            return await self.caller(task, target)

        tasks = [asyncio.create_task(attempt(t, i * min_delay_ms))
                 for i, t in enumerate(targets)]

        attempts: list[Attempt] = []
        try:
            for coro in asyncio.as_completed(tasks):
                att = await coro
                attempts.append(att)
                if att.ok:
                    return Outcome(text=att.text, winner=att.target_id,
                                   attempts=attempts, strategy="race")
        finally:
            for t, task_obj in zip(targets, tasks):
                if not task_obj.done():
                    task_obj.cancel()
                    attempts.append(Attempt(t.id, False, cancelled=True))
            # let cancellations settle without leaking warnings
            await asyncio.gather(*tasks, return_exceptions=True)

        return Outcome(attempts=attempts, strategy="race")

    async def hedge(self, task: Task, delay_ms: int = 1200,
                    cloud_targets=None) -> Outcome:
        """Start the top target; if it has not finished by `delay_ms`, start the
        next one too and take whichever lands first."""
        route = self.router.route(task, cloud_targets)
        ranked = [t for t, _ in route.ranked[:2]]
        if not ranked:
            return Outcome(strategy="hedge",
                           attempts=[Attempt("none", False, error=route.reason)])

        primary = asyncio.create_task(self.caller(task, ranked[0]))
        attempts: list[Attempt] = []
        try:
            done, _pending = await asyncio.wait({primary}, timeout=delay_ms / 1000.0)
            if done:
                att = primary.result()
                attempts.append(att)
                if att.ok:
                    return Outcome(text=att.text, winner=att.target_id,
                                   attempts=attempts, strategy="hedge")

            if len(ranked) < 2:
                att = await primary
                attempts.append(att)
                return Outcome(text=att.text, winner=att.target_id if att.ok else "",
                               attempts=attempts, strategy="hedge")

            backup = asyncio.create_task(self.caller(task, ranked[1]))
            pending = {primary, backup}
            while pending:
                done, pending = await asyncio.wait(
                    pending, return_when=asyncio.FIRST_COMPLETED)
                for d in done:
                    att = d.result()
                    attempts.append(att)
                    if att.ok:
                        return Outcome(text=att.text, winner=att.target_id,
                                       attempts=attempts, strategy="hedge")
            return Outcome(attempts=attempts, strategy="hedge")
        finally:
            for t in (primary,):
                if not t.done():
                    t.cancel()
                    attempts.append(Attempt(ranked[0].id, False, cancelled=True))
            await asyncio.gather(primary, return_exceptions=True)


def make_usage_caller(complete_fn, ledger_recorder=None):
    """Adapt a (target, prompt) -> response function into an Executor caller.

    ``complete_fn(task, target)`` must return a dict with at least
    ``{"text", "prompt_tokens", "completion_tokens"}`` or raise.
    ``ledger_recorder`` receives every attempt, winners and losers alike.
    """
    async def caller(task: Task, target: Target) -> Attempt:
        t0 = time.monotonic()
        try:
            res = await complete_fn(task, target)
        except Exception as e:  # noqa: BLE001 - attempt failure is data, not a crash
            return Attempt(target.id, False,
                           error=f"{type(e).__name__}: {e}",
                           latency_ms=int((time.monotonic() - t0) * 1000))
        latency = int((time.monotonic() - t0) * 1000)
        pt = int(res.get("prompt_tokens", 0) or 0)
        ct = int(res.get("completion_tokens", 0) or 0)
        cost = target.cost_usd(pt, ct) if not target.is_local else 0.0
        att = Attempt(target.id, True, text=res.get("text", ""),
                      latency_ms=latency, cost_usd=cost)
        if ledger_recorder is not None:
            try:
                ledger_recorder(target, res, latency, cost)
            except Exception:
                pass  # accounting must never break an inference call
        return att

    return caller
