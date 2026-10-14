"""
Capability provider: LLM inference with automatic routing.

This is where the six-dimension policy becomes observable behaviour. A caller
asks a question and does not name a model; the router decides whether it stays
local or goes to cloud, which provider, and which execution strategy.

Safety invariant enforced here, not left to callers: **everything bound for a
cloud target is sanitised on the way out**. The router's `sensitivity` check
decides *whether* cloud is allowed; this module guarantees that if it is, no
path/token/hash leaks. Centralising it means a future caller cannot forget.
"""

from __future__ import annotations

import asyncio
import json
import urllib.error
import urllib.request

from ..contract import (
    COST_LOCAL,
    SENS_INTERNAL,
    CapabilityError,
    CapabilitySpec,
    EventEmitter,
    InvokeContext,
    integer,
    schema,
    string,
)
from ..executors import Executor, make_usage_caller
from ..routing import Router, Task, Target


# ── ledger-driven inputs to the router ──────────────────────────────────────

def _latency_lookup(provider: str, model: str) -> dict:
    try:
        from ...providers import usage
        if provider == "local":
            return usage.latency_stats("local", model)
        return usage.latency_stats(provider, model)
    except Exception:
        return {}


def _breaker_adapter():
    """Adapt the kernel scheduler's breaker to the router's is_open(id) shape."""
    # The scheduler's breaker is keyed by capability, not by provider/model, so
    # there is nothing meaningful to consult yet. P2.1 will key it by target.
    return None


def build_router(*, cloud_enabled: bool = True) -> Router:
    return Router(latency_lookup=_latency_lookup,
                  breaker=_breaker_adapter(),
                  cloud_enabled=cloud_enabled)


# ── completion backends ─────────────────────────────────────────────────────

def _ollama_chat(model: str, prompt: str, timeout: int) -> dict:
    from ...config import OLLAMA_URL
    payload = json.dumps({
        "model": model, "prompt": prompt, "stream": False,
        "options": {"num_predict": 1024, "temperature": 0.2},
    }).encode()
    req = urllib.request.Request(f"{OLLAMA_URL}/api/generate", data=payload,
                                 headers={"Content-Type": "application/json"})
    raw = json.loads(urllib.request.urlopen(req, timeout=timeout).read())
    return {
        "text": raw.get("response", "").strip(),
        "prompt_tokens": raw.get("prompt_eval_count", 0) or 0,
        "completion_tokens": raw.get("eval_count", 0) or 0,
        "model": raw.get("model", model),
    }


def _cloud_chat(target: Target, prompt: str, api_key: str,
                max_tokens: int, timeout: int) -> dict:
    from ...providers import registry as preg
    spec = preg.get(target.provider)
    if spec is None:
        raise CapabilityError(f"unknown provider '{target.provider}'",
                              code="unknown_provider")
    payload = json.dumps({
        "model": target.model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
    }).encode()
    req = urllib.request.Request(spec.chat_url, data=payload, method="POST")
    for k, v in spec.auth_headers(api_key, chat=True).items():
        req.add_header(k, v)
    raw = json.loads(urllib.request.urlopen(req, timeout=timeout).read())
    choice = (raw.get("choices") or [{}])[0]
    usage = raw.get("usage", {}) or {}
    details = usage.get("completion_tokens_details", {}) or {}
    return {
        "text": (choice.get("message", {}) or {}).get("content", "").strip(),
        # The provider echoes the model it ACTUALLY ran: legacy aliases such as
        # deepseek-chat resolve to deepseek-flash, so bill by this, not by the
        # requested name.
        "model": raw.get("model", target.model),
        "prompt_tokens": usage.get("prompt_tokens", 0) or 0,
        "completion_tokens": usage.get("completion_tokens", 0) or 0,
        "reasoning_tokens": details.get("reasoning_tokens", 0) or 0,
    }


def _record(target: Target, res: dict, latency_ms: int, cost: float) -> None:
    from ...providers import usage
    usage.record(usage.UsageRecord(
        provider="local" if target.is_local else target.provider,
        model=res.get("model", target.model),
        requested_model=target.model,
        kind="llm.ask",
        prompt_tokens=res.get("prompt_tokens", 0),
        completion_tokens=res.get("completion_tokens", 0),
        reasoning_tokens=res.get("reasoning_tokens", 0),
        cost_usd=cost,
        latency_ms=latency_ms,
    ))


def make_complete_fn(*, sanitize: bool = True, max_tokens: int = 1024,
                     timeout: int = 180):
    """Build the (task, target) -> response callable used by the executors."""
    from ...sanitizer import Sanitizer
    from ...api_key import APIKeyManager

    async def complete(task: Task, target: Target) -> dict:
        prompt = task.prompt
        if not target.is_local and sanitize:
            # Outbound boundary: nothing reaches a provider unsanitised.
            prompt = Sanitizer.prompt(prompt, task.context or {})

        if target.is_local:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                None, _ollama_chat, target.model, prompt, timeout)

        keys = (APIKeyManager.load() or {}).get("providers", {}) or {}
        key = keys.get(target.provider)
        if not key:
            raise CapabilityError(
                f"no API key configured for '{target.provider}'",
                code="no_api_key")
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, _cloud_chat, target, prompt, key, max_tokens, timeout)

    return complete


# ── capability handlers ─────────────────────────────────────────────────────

async def ask(params: dict, ctx: InvokeContext):
    """Route a question automatically and answer it.

    Params allow forcing a strategy, but not a target: the whole point is that
    the caller describes the *task* and the router picks the executor.
    """
    em = EventEmitter("llm.ask")
    prompt = (params.get("question") or "").strip()
    if not prompt:
        raise CapabilityError("'question' is required", code="invalid_params")

    task = Task(
        prompt=prompt,
        kind=params.get("kind", "chat"),
        context=params.get("context") or {},
        sensitivity=params.get("sensitivity", SENS_INTERNAL),
        difficulty=params.get("difficulty", "auto"),
        requires=set(params.get("requires") or []),
        latency_budget_ms=int(params.get("latency_budget_ms") or 0),
        cost_budget_usd=float(params.get("cost_budget_usd") or 0.0),
    )

    router = build_router(cloud_enabled=not params.get("local_only", False))
    route = router.route(task, router.cloud_targets())
    yield em.log(
        f"route: {route.best.id if route.best else 'none'} — {route.reason}",
        level="info")
    for entry in route.rejected:
        t, why = entry
        yield em.log(f"  rejected {t.id}: {why}", level="debug")

    if not route.ok:
        yield em.error(route.reason, code="no_route",
                       rejected=[{"target": t.id, "why": w} for t, w in route.rejected])
        return

    ex = Executor(router, make_usage_caller(make_complete_fn(), _record))
    strategy = params.get("strategy", "single")
    ctx.check_cancelled()

    if strategy == "race":
        outcome = await ex.race(task, n=int(params.get("n") or 2),
                                cloud_targets=router.cloud_targets())
    elif strategy == "hedge":
        outcome = await ex.hedge(task, delay_ms=int(params.get("hedge_delay_ms") or 1200),
                                 cloud_targets=router.cloud_targets())
    else:
        outcome = await ex.single(task, cloud_targets=router.cloud_targets())

    yield em.result({
        "answer": outcome.text,
        "route": {"best": route.best.id if route.best else None,
                  "reason": route.reason},
        "execution": outcome.to_dict(),
    }, strategy=outcome.strategy)


async def fanout(params: dict, ctx: InvokeContext):
    """Answer several independent questions concurrently, each routed on its own."""
    em = EventEmitter("llm.fanout")
    questions = params.get("questions") or []
    if not questions:
        raise CapabilityError("'questions' must be a non-empty list",
                              code="invalid_params")

    tasks = [Task(prompt=q, sensitivity=params.get("sensitivity", SENS_INTERNAL),
                  difficulty=params.get("difficulty", "auto"),
                  context=params.get("context") or {})
             for q in questions]

    router = build_router(cloud_enabled=not params.get("local_only", False))
    ex = Executor(router, make_usage_caller(make_complete_fn(), _record))
    yield em.progress(0.0, total=len(tasks))

    outcomes = await ex.fanout(tasks, cloud_targets=router.cloud_targets())

    results = []
    for q, o in zip(questions, outcomes):
        results.append({"question": q, "answer": o.text,
                        "winner": o.winner, "ok": o.ok,
                        "cost_usd": round(o.total_cost_usd, 6)})
    yield em.result({
        "results": results,
        "total_cost_usd": round(sum(o.total_cost_usd for o in outcomes), 6),
        "succeeded": sum(1 for o in outcomes if o.ok),
    })


async def plan(params: dict, ctx: InvokeContext):
    """Dry-run the router: show the decision without spending anything.

    Exists because "why did it go to cloud" is the most common question about an
    automatic router, and answering it should not require a paid call.
    """
    em = EventEmitter("llm.plan")
    prompt = (params.get("question") or "").strip()
    if not prompt:
        raise CapabilityError("'question' is required", code="invalid_params")

    task = Task(prompt=prompt, kind=params.get("kind", "chat"),
                sensitivity=params.get("sensitivity", SENS_INTERNAL),
                difficulty=params.get("difficulty", "auto"),
                requires=set(params.get("requires") or []),
                latency_budget_ms=int(params.get("latency_budget_ms") or 0),
                cost_budget_usd=float(params.get("cost_budget_usd") or 0.0))
    router = build_router(cloud_enabled=not params.get("local_only", False))
    route = router.route(task, router.cloud_targets())
    best = route.best
    pricing_known = True
    if best is not None and not best.is_local:
        from ...providers import registry as preg
        pricing_known = preg.pricing_known(best.provider, best.model)

    yield em.result({
        "chosen": best.id if best else None,
        "reason": route.reason,
        "est_prompt_tokens": task.est_prompt_tokens,
        "est_total_tokens": task.est_total_tokens,
        "est_cost_usd": round(router.effective_cost_usd(best, task), 6) if best else 0,
        "pricing_known": pricing_known,
        "est_cost_note": ("" if pricing_known else
                          "model absent from the pricing registry; cost is a "
                          "pessimistic assumption, not a quote"),
        "ranked": route.explain(),
        "rejected": [{"target": t.id, "why": w} for t, w in route.rejected],
    })


# ── registration ────────────────────────────────────────────────────────────

SPECS = (
    CapabilitySpec(
        id="llm.ask",
        kind="llm",
        name="智能问答",
        description="自动路由的问答：按敏感度/能力/难度/速度/成本/可用性六维决定本地或云端",
        params=schema(
            {
                "question": string("问题正文"),
                "kind": string("任务类型标签", default="chat"),
                "context": {"type": "object", "description": "扫描上下文（出境前会脱敏）"},
                "sensitivity": string("public | internal | secret", default="internal"),
                "difficulty": string("auto | light | heavy", default="auto"),
                "requires": {"type": "array", "items": {"type": "string"},
                             "description": "能力要求，如 deep / code / long_context"},
                "strategy": string("single | race | hedge", default="single"),
                "n": integer("race 的候选数", default=2),
                "hedge_delay_ms": integer("hedge 的备份触发延迟", default=1200),
                "latency_budget_ms": integer("延迟上限（0=不限）", default=0),
                "cost_budget_usd": {"type": "number", "description": "单次成本上限"},
                "local_only": {"type": "boolean", "default": False},
            },
            required=["question"],
        ),
        returns=schema({"answer": {"type": "string"}, "route": {"type": "object"}}),
        streaming=True,
        cost=COST_LOCAL,
        sensitivity=SENS_INTERNAL,
        backend="providers.llm",
        tags=("llm", "routing"),
    ),
    CapabilitySpec(
        id="llm.plan",
        kind="llm",
        name="路由预演",
        description="只做路由决策不实际调用，用于回答「为什么走了云端」",
        params=schema({"question": string("问题正文"),
                       "sensitivity": string("public | internal | secret", default="internal"),
                       "difficulty": string("auto | light | heavy", default="auto"),
                       "requires": {"type": "array", "items": {"type": "string"}},
                       "local_only": {"type": "boolean", "default": False}},
                      required=["question"]),
        returns=schema({"chosen": {"type": "string"}}),
        cost=COST_LOCAL,
        sensitivity=SENS_INTERNAL,
        backend="providers.llm",
        tags=("llm", "routing", "dry-run"),
    ),
    CapabilitySpec(
        id="llm.fanout",
        kind="llm",
        name="并发问答",
        description="多个独立问题并发执行，各自独立路由",
        params=schema(
            {
                "questions": {"type": "array", "items": {"type": "string"}},
                "context": {"type": "object"},
                "sensitivity": string("public | internal | secret", default="internal"),
                "difficulty": string("auto | light | heavy", default="auto"),
                "local_only": {"type": "boolean", "default": False},
            },
            required=["questions"],
        ),
        returns=schema({"results": {"type": "array"}}),
        streaming=True,
        cost=COST_LOCAL,
        sensitivity=SENS_INTERNAL,
        backend="providers.llm",
        tags=("llm", "parallel"),
    ),
)

HANDLERS = {
    "llm.ask": ask,
    "llm.plan": plan,
    "llm.fanout": fanout,
}


def register_all(registry) -> None:
    for spec in SPECS:
        registry.register(spec, HANDLERS[spec.id])
