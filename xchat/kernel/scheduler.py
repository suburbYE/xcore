"""
Scheduler: concurrency, rate limiting and circuit breaking around capabilities.

Why this exists separately from the registry: the registry answers "how do I run
this capability", the scheduler answers "should I run it now, and how many at
once". Keeping them apart means a capability provider never has to think about
back-pressure, and the policy can change without touching providers.

Three mechanisms:

* **ConcurrencyLimiter** — caps in-flight invocations per key. Sub-process
  capabilities (xcore.exe, node) are the reason: spawning 50 copies of the
  native scanner would thrash the machine long before the CPU saturated.
* **RateLimiter** — token bucket, for provider quotas (RPM). Needed once the
  LLM scheduler lands in P2; in place now so the interface is stable.
* **CircuitBreaker** — after N consecutive failures a target is short-circuited
  for a cooldown. Without it, one dead provider turns every request into a
  timeout, which is exactly the failure mode a multi-provider setup must avoid.

Deliberately not included: retries. Retrying an analysis that failed on a bad
input just burns time; the caller decides whether a retry is meaningful.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import AsyncIterator

from .contract import (
    EVENT_ERROR,
    EVENT_RESULT,
    Event,
    InvokeContext,
)


class CircuitOpen(Exception):
    """Raised when a target is short-circuited. Carries the retry delay."""

    def __init__(self, target: str, retry_after: float):
        super().__init__(
            f"circuit open for '{target}' (retry in {retry_after:.1f}s)")
        self.target = target
        self.retry_after = retry_after


class RateLimited(Exception):
    def __init__(self, key: str, retry_after: float):
        super().__init__(f"rate limited on '{key}' (retry in {retry_after:.2f}s)")
        self.key = key
        self.retry_after = retry_after


# ── concurrency ─────────────────────────────────────────────────────────────

class ConcurrencyLimiter:
    """Per-key semaphore pool. Keys are created lazily."""

    def __init__(self, default_limit: int = 4):
        self.default_limit = default_limit
        self._limits: dict[str, int] = {}
        self._sems: dict[str, asyncio.Semaphore] = {}
        self._inflight: dict[str, int] = {}
        self._peak: dict[str, int] = {}

    def set_limit(self, key: str, limit: int) -> None:
        self._limits[key] = max(1, limit)
        # Rebuild so the new limit takes effect for subsequent acquisitions;
        # in-flight holders finish against the old semaphore.
        self._sems.pop(key, None)

    def limit_for(self, key: str) -> int:
        return self._limits.get(key, self.default_limit)

    def _sem(self, key: str) -> asyncio.Semaphore:
        sem = self._sems.get(key)
        if sem is None:
            sem = asyncio.Semaphore(self.limit_for(key))
            self._sems[key] = sem
        return sem

    def inflight(self, key: str) -> int:
        return self._inflight.get(key, 0)

    def peak(self, key: str) -> int:
        return self._peak.get(key, 0)

    class _Slot:
        def __init__(self, owner: "ConcurrencyLimiter", key: str):
            self.owner, self.key = owner, key

        async def __aenter__(self):
            await self.owner._sem(self.key).acquire()
            n = self.owner._inflight.get(self.key, 0) + 1
            self.owner._inflight[self.key] = n
            self.owner._peak[self.key] = max(self.owner._peak.get(self.key, 0), n)
            return self

        async def __aexit__(self, *exc):
            n = self.owner._inflight.get(self.key, 1) - 1
            self.owner._inflight[self.key] = max(0, n)
            self.owner._sem(self.key).release()
            return False

    def slot(self, key: str) -> "ConcurrencyLimiter._Slot":
        return ConcurrencyLimiter._Slot(self, key)


# ── rate limiting ───────────────────────────────────────────────────────────

class RateLimiter:
    """Token bucket per key. `per_minute` of 0 disables limiting."""

    def __init__(self, per_minute: int = 0, burst: int | None = None):
        self.per_minute = per_minute
        self.burst = burst if burst is not None else max(1, per_minute or 1)
        self._tokens: dict[str, float] = {}
        self._updated: dict[str, float] = {}
        self._lock = asyncio.Lock()

    def set_limit(self, key: str, per_minute: int) -> None:
        self._limits_override = getattr(self, "_limits_override", {})
        self._limits_override[key] = per_minute

    def _rate(self, key: str) -> int:
        return getattr(self, "_limits_override", {}).get(key, self.per_minute)

    def available(self, key: str) -> float:
        rate = self._rate(key)
        if rate <= 0:
            return float("inf")
        now = time.monotonic()
        tokens = self._tokens.get(key, float(self.burst))
        last = self._updated.get(key, now)
        tokens = min(self.burst, tokens + (now - last) * (rate / 60.0))
        self._tokens[key] = tokens
        self._updated[key] = now
        return tokens

    async def acquire(self, key: str, timeout: float = 30.0) -> None:
        """Block until a token is available, or raise RateLimited."""
        rate = self._rate(key)
        if rate <= 0:
            return
        deadline = time.monotonic() + timeout
        while True:
            async with self._lock:
                if self.available(key) >= 1.0:
                    self._tokens[key] -= 1.0
                    return
            if time.monotonic() >= deadline:
                need = (1.0 - self.available(key)) / (rate / 60.0)
                raise RateLimited(key, max(0.0, need))
            await asyncio.sleep(0.05)


# ── circuit breaker ─────────────────────────────────────────────────────────

@dataclass
class BreakerState:
    consecutive_failures: int = 0
    open_until: float = 0.0
    total_calls: int = 0
    total_failures: int = 0
    last_error: str = ""


class CircuitBreaker:
    def __init__(self, threshold: int = 5, cooldown: float = 60.0):
        self.threshold = threshold
        self.cooldown = cooldown
        self._state: dict[str, BreakerState] = {}

    def state(self, target: str) -> BreakerState:
        return self._state.setdefault(target, BreakerState())

    def is_open(self, target: str) -> bool:
        st = self.state(target)
        if st.open_until and time.monotonic() < st.open_until:
            return True
        if st.open_until and time.monotonic() >= st.open_until:
            # half-open: allow one probe through
            st.open_until = 0.0
        return False

    def retry_after(self, target: str) -> float:
        st = self.state(target)
        return max(0.0, st.open_until - time.monotonic())

    def check(self, target: str) -> None:
        if self.is_open(target):
            raise CircuitOpen(target, self.retry_after(target))

    def record_success(self, target: str) -> None:
        st = self.state(target)
        st.total_calls += 1
        st.consecutive_failures = 0
        st.open_until = 0.0

    def record_failure(self, target: str, error: str = "") -> None:
        st = self.state(target)
        st.total_calls += 1
        st.total_failures += 1
        st.consecutive_failures += 1
        st.last_error = error[:300]
        if st.consecutive_failures >= self.threshold:
            st.open_until = time.monotonic() + self.cooldown

    def snapshot(self) -> dict:
        return {
            t: {
                "consecutive_failures": s.consecutive_failures,
                "open": self.is_open(t),
                "retry_after": round(self.retry_after(t), 1),
                "total_calls": s.total_calls,
                "total_failures": s.total_failures,
                "last_error": s.last_error,
            }
            for t, s in self._state.items()
        }


# ── capability metrics ──────────────────────────────────────────────────────

@dataclass
class CapMetrics:
    calls: int = 0
    failures: int = 0
    total_ms: int = 0
    last_ms: int = 0
    last_error: str = ""
    by_code: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "calls": self.calls,
            "failures": self.failures,
            "avg_ms": round(self.total_ms / self.calls) if self.calls else 0,
            "last_ms": self.last_ms,
            "last_error": self.last_error,
            "by_code": dict(self.by_code),
        }


# ── scheduler ───────────────────────────────────────────────────────────────

class Scheduler:
    """Wraps a Registry with concurrency limits, breakers and metrics."""

    # Sub-process capabilities get tighter limits: each invocation spawns a
    # process, so oversubscribing hurts far worse than for in-process work.
    DEFAULT_LIMITS = {
        "engine.scan": 4,
        "engine.native_scan": 2,
        "engine.deobfuscate": 2,
        "native.target_scan": 2,
        "native.apk_pipeline": 1,
        "web.pipeline": 4,
    }

    # Errors that mean the *caller* asked for something impossible. These are
    # not provider faults, so they must not count toward the circuit breaker —
    # otherwise a UI bug (wrong param name) would take a healthy capability
    # offline for the whole cooldown.
    CALLER_FAULTS = frozenset({
        "invalid_params", "unknown_capability", "not_found", "cancelled",
    })

    def __init__(self, registry, *, default_concurrency: int = 4,
                 breaker_threshold: int = 5, breaker_cooldown: float = 60.0):
        self.registry = registry
        self.limiter = ConcurrencyLimiter(default_concurrency)
        for cap_id, limit in self.DEFAULT_LIMITS.items():
            self.limiter.set_limit(cap_id, limit)
        self.breaker = CircuitBreaker(breaker_threshold, breaker_cooldown)
        self.metrics: dict[str, CapMetrics] = {}

    def metrics_for(self, cap_id: str) -> CapMetrics:
        return self.metrics.setdefault(cap_id, CapMetrics())

    def stats(self) -> dict:
        return {
            "capabilities": {k: v.to_dict() for k, v in sorted(self.metrics.items())},
            "breakers": self.breaker.snapshot(),
            "inflight": {k: self.limiter.inflight(k) for k in self.limiter._inflight},
            "limits": {k: self.limiter.limit_for(k)
                       for k in set(self.metrics) | set(self.DEFAULT_LIMITS)},
        }

    async def invoke(self, cap_id: str, params: dict | None = None,
                     ctx: InvokeContext | None = None) -> AsyncIterator[Event]:
        """Scheduled invocation. Same event contract as Registry.invoke."""
        ctx = ctx or InvokeContext()
        m = self.metrics_for(cap_id)
        started = time.monotonic()

        try:
            self.breaker.check(cap_id)
        except CircuitOpen as e:
            m.calls += 1
            m.failures += 1
            m.by_code["circuit_open"] = m.by_code.get("circuit_open", 0) + 1
            from .contract import EventEmitter
            yield EventEmitter(cap_id).error(str(e), code="circuit_open",
                                             retry_after=round(e.retry_after, 1))
            return

        async with self.limiter.slot(cap_id):
            m.calls += 1
            provider_fault = False
            async for ev in self.registry.invoke(cap_id, params, ctx):
                if ev.type == EVENT_ERROR:
                    code = ev.data.get("code", "error")
                    m.by_code[code] = m.by_code.get(code, 0) + 1
                    if code not in self.CALLER_FAULTS:
                        provider_fault = True
                        m.last_error = ev.data.get("message", "")[:300]
                yield ev

            elapsed = int((time.monotonic() - started) * 1000)
            m.total_ms += elapsed
            m.last_ms = elapsed
            if provider_fault:
                m.failures += 1
                self.breaker.record_failure(cap_id, m.last_error)
            else:
                self.breaker.record_success(cap_id)

    async def run_parallel(self, jobs: list[tuple[str, dict]]) -> list[list[Event]]:
        """Run several capabilities concurrently, returning each event list.

        Order matches the input. This is the raw fan-out primitive; P2's router
        decides *what* to fan out.
        """
        async def one(cap_id: str, params: dict) -> list[Event]:
            return [ev async for ev in self.invoke(cap_id, params)]

        return await asyncio.gather(*(one(c, p) for c, p in jobs))
