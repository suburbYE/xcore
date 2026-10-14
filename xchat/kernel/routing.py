"""
Task routing policy — the six-dimension decision behind "local does the light
work, cloud does the heavy lifting".

The dimensions, in the order they are applied (earlier ones are hard filters,
later ones only rank what survived):

1. **sensitivity** — ``secret`` never leaves the machine, full stop. ``internal``
   may go to cloud only because the outbound path is sanitised.
2. **capability** — context window must fit the estimated prompt; a task needing
   ``deep`` reasoning cannot be served by a ``fast`` model that lacks it.
3. **difficulty** — above a token threshold the task is cloud work by definition;
   the local model exists for cheap, quick turns, not for real analysis.
4. **speed** — ranked by *observed* p50 latency from the usage ledger, not by a
   hardcoded tier. A provider that is slow today is ranked slow today.
5. **cost** — estimated spend, filtered against any per-task budget.
6. **availability** — circuit-breaker state; an open breaker removes the target.

The policy returns a *ranked list*, not a single answer, because the parallel
executors (race / hedge) need runners-up.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field

from ..config import DIALOG_MODEL
from .contract import SENS_INTERNAL, SENS_PUBLIC, SENS_SECRET

# ── targets ─────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Target:
    """One place a task could run."""

    id: str                     # "local" | "gemini:gemini-3.6-flash"
    kind: str                   # local | cloud
    provider: str = ""          # "" for local
    model: str = ""
    context_window: int = 32768
    price_in: float = 0.0       # USD / 1M tokens
    price_out: float = 0.0
    speed: str = "medium"       # fast | medium | slow
    capability: str = "general"  # general | code | deep
    note: str = ""

    def cost_usd(self, prompt_tokens: int, completion_tokens: int) -> float:
        return (prompt_tokens * self.price_in
                + completion_tokens * self.price_out) / 1_000_000

    @property
    def is_local(self) -> bool:
        return self.kind == "local"


@dataclass
class Task:
    """A unit of work to be routed."""

    prompt: str
    kind: str = "chat"
    context: dict = field(default_factory=dict)
    sensitivity: str = SENS_INTERNAL
    est_completion_tokens: int = 512
    requires: set[str] = field(default_factory=set)   # e.g. {"deep"}, {"long_context"}
    latency_budget_ms: int = 0                        # 0 = no budget
    cost_budget_usd: float = 0.0                      # 0 = no budget
    # Difficulty hint from the caller; the router also derives one from size.
    difficulty: str = "auto"                          # auto | light | heavy

    @property
    def est_prompt_tokens(self) -> int:
        return estimate_tokens(self.prompt)

    @property
    def est_total_tokens(self) -> int:
        return self.est_prompt_tokens + self.est_completion_tokens


@dataclass
class Route:
    """A ranked routing decision."""

    ranked: list[tuple[Target, float]] = field(default_factory=list)
    rejected: list[tuple[Target, str]] = field(default_factory=list)
    reason: str = ""

    @property
    def best(self) -> Target | None:
        return self.ranked[0][0] if self.ranked else None

    @property
    def ok(self) -> bool:
        return bool(self.ranked)

    def alternatives(self, limit: int = 3) -> list[Target]:
        return [t for t, _ in self.ranked[1:1 + limit]]

    def explain(self) -> list[dict]:
        return [{"target": t.id, "score": round(s, 4), "note": t.note}
                for t, s in self.ranked]


# ── token estimation ────────────────────────────────────────────────────────

_CJK = re.compile(r"[\u3400-\u9fff\uf900-\ufaff\u3040-\u30ff\uac00-\ud7af]")


def estimate_tokens(text: str) -> int:
    """Cheap token estimate, good enough for routing decisions.

    Deliberately not a real tokenizer: routing only needs the right order of
    magnitude, and shipping per-provider tokenizers would couple the router to
    every vendor. CJK runs ~1 token per character, latin ~1 per 4.
    """
    if not text:
        return 0
    cjk = len(_CJK.findall(text))
    other = len(text) - cjk
    return int(cjk + other / 4) + 1


# ── policy knobs ────────────────────────────────────────────────────────────

@dataclass
class RoutingPolicy:
    # Above this many tokens a task is cloud work regardless of anything else.
    heavy_token_threshold: int = 4000
    # Below this, cloud is overkill for a private-safe task.
    light_token_threshold: int = 600
    # Cloud cost above this per task needs an explicit budget to proceed.
    cost_warn_usd: float = 0.02
    # Price assumed for a cloud model the registry has no pricing for.
    # Deliberately pessimistic: costing unknown models at $0 makes the cost
    # dimension actively prefer the models we know least about.
    assumed_price_in: float = 1.00    # USD / 1M
    assumed_price_out: float = 5.00
    # Weighting of the ranking score components.
    w_quality: float = 1.0
    w_speed: float = 0.45
    w_cost: float = 0.8
    w_locality: float = 0.25   # mild preference for keeping work local
    # Observed-latency used when a target has no ledger history.
    assumed_latency_ms: dict = field(default_factory=lambda: {
        "local": 2500, "fast": 3000, "medium": 6000, "slow": 15000,
    })


# ── router ──────────────────────────────────────────────────────────────────

class Router:
    def __init__(self, *, policy: RoutingPolicy | None = None,
                 latency_lookup=None, balance_lookup=None,
                 breaker=None, cloud_enabled: bool = True,
                 target_cache_ttl: float = 300.0):
        """
        latency_lookup(provider, model) -> {"p50_ms": int, "samples": int}
        balance_lookup(provider)        -> float | None   (account balance)
        breaker                          -> object with is_open(target_id)

        ``target_cache_ttl`` matters: building cloud targets hits the network
        (live model discovery per provider). Doing that inside every routing
        decision would make the router slower than the models it routes to.
        """
        self.policy = policy or RoutingPolicy()
        self._latency = latency_lookup or (lambda p, m: {})
        self._balance = balance_lookup or (lambda p: None)
        self.breaker = breaker
        self.cloud_enabled = cloud_enabled
        self._cache_ttl = target_cache_ttl
        self._cache: list[Target] | None = None
        self._cache_at: float = 0.0
        self._cache_lock = threading.Lock()

    # -- target construction ------------------------------------------------

    def local_target(self) -> Target:
        return Target(
            id="local", kind="local", model=DIALOG_MODEL,
            context_window=32768, speed="fast", capability="general",
            note="local dialog model",
        )

    def cloud_targets(self, only_configured: bool = True,
                      refresh: bool = False) -> list[Target]:
        import time as _time
        now = _time.monotonic()
        with self._cache_lock:
            fresh = (self._cache is not None
                     and (now - self._cache_at) < self._cache_ttl)
            if fresh and not refresh:
                return self._cache
            targets = self._build_cloud_targets(only_configured)
            self._cache = targets
            self._cache_at = now
            return targets

    def _build_cloud_targets(self, only_configured: bool) -> list[Target]:
        from ..providers import account, registry as preg

        configured = set((account._keys() or {}).keys()) if only_configured else set()
        out: list[Target] = []
        for pname in preg.known():
            if only_configured and pname not in configured:
                continue
            spec = preg.get(pname)
            models, _err = account.list_models(pname)
            seen = set()
            for m in models:
                if m.id in seen:
                    continue
                seen.add(m.id)
                ms = preg.model_spec(pname, m.id)
                ctx = m.context_window or ms.context_window or 32768
                out.append(Target(
                    id=f"{pname}:{m.id}", kind="cloud", provider=pname, model=m.id,
                    context_window=ctx,
                    price_in=ms.price_in, price_out=ms.price_out,
                    speed=ms.speed, capability=ms.capability,
                    note="pricing unknown" if not preg.pricing_known(pname, m.id) else "",
                ))
        return out

    # -- scoring ------------------------------------------------------------

    def _observed_latency_ms(self, target: Target) -> int:
        if target.is_local:
            stats = self._latency("local", target.model) or {}
            return int(stats.get("p50_ms") or self.policy.assumed_latency_ms["local"])
        stats = self._latency(target.provider, target.model) or {}
        if stats.get("p50_ms"):
            return int(stats["p50_ms"])
        return int(self.policy.assumed_latency_ms.get(target.speed, 6000))

    def _capability_score(self, target: Target, task: Task) -> float:
        """0..1 — how well the target's capability matches what the task needs."""
        needs = task.requires
        cap = target.capability
        if "deep" in needs:
            return 1.0 if cap == "deep" else (0.35 if not target.is_local else 0.1)
        if "code" in needs:
            return 1.0 if cap in ("code", "deep") else 0.5
        # No explicit need: heavier models are mildly better, local is fine.
        return {"deep": 1.0, "code": 0.9, "general": 0.75}.get(cap, 0.7)

    def _score(self, target: Target, task: Task) -> float:
        p = self.policy
        quality = self._capability_score(target, task)

        latency = self._observed_latency_ms(target)
        speed = 1.0 / (1.0 + latency / 3000.0)          # 3s -> 0.5, 15s -> 0.17

        cost = self.effective_cost_usd(target, task)
        cost_score = 1.0 if target.is_local else 1.0 / (1.0 + cost / 0.01)

        locality = 1.0 if target.is_local else 0.0

        return (p.w_quality * quality + p.w_speed * speed
                + p.w_cost * cost_score + p.w_locality * locality)

    def effective_cost_usd(self, target: Target, task: Task) -> float:
        """Cost estimate, substituting a pessimistic default for unknown pricing."""
        if target.is_local:
            return 0.0
        if target.price_in == 0.0 and target.price_out == 0.0:
            p = self.policy
            return (task.est_prompt_tokens * p.assumed_price_in
                    + task.est_completion_tokens * p.assumed_price_out) / 1_000_000
        return target.cost_usd(task.est_prompt_tokens, task.est_completion_tokens)

    # -- main entry ---------------------------------------------------------

    def route(self, task: Task, cloud_targets: list[Target] | None = None) -> Route:
        p = self.policy
        route = Route()
        candidates: list[Target] = [self.local_target()]
        if self.cloud_enabled:
            candidates += (cloud_targets if cloud_targets is not None
                           else self.cloud_targets())

        pt = task.est_prompt_tokens
        total = task.est_total_tokens
        heavy = (task.difficulty == "heavy"
                 or total >= p.heavy_token_threshold)
        light = (task.difficulty == "light"
                 or total <= p.light_token_threshold)
        # "Too heavy for local" is only a valid rejection when cloud is a real
        # alternative. For a secret task cloud is forbidden, so rejecting local
        # for size would leave the task with nowhere to run at all.
        cloud_permitted = self.cloud_enabled and task.sensitivity != SENS_SECRET

        for t in candidates:
            # 1. sensitivity
            if t.kind == "cloud":
                if not self.cloud_enabled:
                    route.rejected.append((t, "cloud disabled"))
                    continue
                if task.sensitivity == SENS_SECRET:
                    route.rejected.append((t, "task marked secret — must stay local"))
                    continue
                if task.sensitivity == SENS_PUBLIC and kind_needs_no_cloud(task):
                    pass  # public is always allowed

            # 2. capability
            if pt > t.context_window:
                route.rejected.append(
                    (t, f"prompt {pt} tok exceeds context {t.context_window}"))
                continue
            if "deep" in task.requires and t.capability != "deep" and not t.is_local:
                route.rejected.append((t, "requires deep capability"))
                continue

            # 3. difficulty — local is for light work; heavy work needs cloud
            if t.is_local and heavy and cloud_permitted:
                route.rejected.append(
                    (t, f"heavy task ({total} tok) — local is for light work"))
                continue

            # 4/5. speed budget + cost budget
            if task.latency_budget_ms and self._observed_latency_ms(t) > task.latency_budget_ms:
                route.rejected.append(
                    (t, f"p50 {self._observed_latency_ms(t)}ms exceeds "
                        f"budget {task.latency_budget_ms}ms"))
                continue
            cost = self.effective_cost_usd(t, task)
            if task.cost_budget_usd and cost > task.cost_budget_usd:
                route.rejected.append(
                    (t, f"cost ${cost:.4f} exceeds budget ${task.cost_budget_usd:.4f}"))
                continue

            # 6. availability
            if self.breaker is not None and self.breaker.is_open(t.id):
                route.rejected.append((t, "circuit open"))
                continue

            route.ranked.append((t, self._score(t, task)))

        route.ranked.sort(key=lambda x: -x[1])

        # Never return an empty route when a local model exists: a degraded
        # answer beats no answer, and `rejected` still explains the trade-offs.
        # This matters for e.g. a secret task too large for the local context —
        # there is no cloud fallback by definition, so local is the only option.
        if not route.ranked:
            local = self.local_target()
            if pt <= local.context_window:
                route.ranked.append((local, 0.0))
                route.reason = ("fallback: no target satisfied the policy, "
                                "running locally degraded")
            else:
                route.reason = (f"no viable target: prompt {pt} tok exceeds every "
                                f"context window")
        else:
            best = route.ranked[0][0]
            bits = [f"{best.kind} chosen"]
            if light:
                bits.append("light task")
            if heavy:
                bits.append("heavy task")
            bits.append(f"~{total} tok")
            route.reason = ", ".join(bits)
        return route


def kind_needs_no_cloud(task: Task) -> bool:
    """Placeholder hook for future per-kind cloud bans (e.g. raw memory dumps)."""
    return False


def route_to_dict(route: Route) -> dict:
    return {
        "best": route.best.id if route.best else None,
        "reason": route.reason,
        "ranked": route.explain(),
        "rejected": [{"target": t.id, "why": w} for t, w in route.rejected],
    }
