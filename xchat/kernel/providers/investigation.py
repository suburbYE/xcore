"""
Capability provider: the investigation (goal object + claim ledger, read side).

The ledger is **written by `verify.gate`, never by the agent**. That is not a
stylistic choice: if the agent could record its own "verified" claims, the
ledger would be a transcript of assertions rather than of evidence, and the
whole point is that a claim carries proof it was measured. `verify.gate(...,
record=true)` is the only writer, so a claim in the ledger is a claim whose
check was demonstrated to be capable of failing.

These two capabilities are the read side, which is what the agent needs when it
wakes up in a fresh context window and has to find out what is already
established before redoing it.

See `kernel.agentstate` for the schema and the reasoning behind each field.
"""

from __future__ import annotations

import json

from ..contract import (
    COST_FREE,
    SENS_INTERNAL,
    CapabilityError,
    CapabilitySpec,
    EventEmitter,
    InvokeContext,
    boolean,
    integer,
    schema,
    string,
)
from .. import agentstate
from .. import output as shaping


async def goal_set(params: dict, ctx: InvokeContext):
    """Create or update the active investigation goal."""
    em = EventEmitter("goal.set")
    objective = (params.get("objective") or "").strip()
    if not objective:
        raise CapabilityError("'objective' is required", code="invalid_params")

    current = agentstate.active_goal(ctx.session_id or "")
    if current and not params.get("replace"):
        agentstate.update_goal(
            current["id"],
            criteria=params.get("criteria") or current["criteria"],
            note=params.get("note") or current["note"])
        goal = agentstate.get_goal(current["id"]) or current
        yield em.log(f"updated goal {goal['id']}")
    else:
        # Build the Goal once and insert it. Round-tripping through to_dict()
        # dropped session_id (to_dict is the *model-facing* projection, not a
        # serialisation of every column) and the insert then blew up on it.
        gid = agentstate.create_goal(agentstate.Goal(
            objective=objective,
            criteria=params.get("criteria") or "",
            session_id=ctx.session_id or "",
            max_rounds=int(params.get("max_rounds") or 25),
            note=params.get("note") or "",
        ))
        goal = agentstate.get_goal(gid) or {"id": gid, "phase": "active",
                                            "activation": "armed",
                                            "rounds_started": 0,
                                            "max_rounds": params.get("max_rounds") or 25,
                                            "objective": objective,
                                            "criteria": params.get("criteria") or ""}
        yield em.log(f"created goal {gid}")

    criteria = goal["criteria"] or "(none given — completion cannot be checked without them)"
    yield em.result({
        **goal,
        "text": shaping.with_status(
            f"goal {goal['id']}: {goal['objective']}\n"
            f"criteria: {criteria}\n"
            f"rounds: {goal['rounds_started']}/{goal['max_rounds']}  "
            f"phase={goal['phase']}  activation={goal['activation']}",
            ok=True, detail=f"rounds {goal['rounds_started']}/{goal['max_rounds']}"),
    })


async def goal_get(params: dict, ctx: InvokeContext):
    """Read the active goal. The agent must call this before claiming done."""
    em = EventEmitter("goal.get")
    goal = (agentstate.get_goal(params["goal_id"]) if params.get("goal_id")
            else agentstate.active_goal(ctx.session_id or ""))
    if goal is None:
        yield em.result({"goal": None,
                         "text": shaping.with_status("no active goal", ok=True)})
        return
    goal["checkpoints"] = json.loads(goal.get("checkpoints") or "[]")
    yield em.result({
        "goal": goal,
        "text": shaping.with_status(
            f"goal {goal['id']}: {goal['objective']}\n"
            f"criteria: {goal['criteria'] or '(none)'}\n"
            f"phase={goal['phase']} activation={goal['activation']} "
            f"rounds={goal['rounds_started']}/{goal['max_rounds']}",
            ok=True),
    })


async def goal_update(params: dict, ctx: InvokeContext):
    """Change phase/activation. `complete` is gated on ledger evidence."""
    em = EventEmitter("goal.update")
    goal_id = params.get("goal_id") or ""
    if not goal_id:
        active = agentstate.active_goal(ctx.session_id or "")
        goal_id = (active or {}).get("id", "")
    if not goal_id:
        raise CapabilityError("no goal to update", code="not_found")

    phase = params.get("phase") or ""
    if phase not in ("", "active", "paused", "blocked", "complete"):
        raise CapabilityError(f"unknown phase {phase!r}", code="invalid_params")

    # The gate on "done". Marking a goal complete is the one update that
    # asserts the whole objective is achieved, so it needs the ledger to back
    # it. Staleness is reported before absence: when the harness changed, the
    # claims did not vanish, they expired — and "re-run them" is a different
    # instruction from "you have no evidence", so the more actionable message
    # has to win. (Checking `verified == 0` first masked this, because a stale
    # claim is not counted as verified.)
    if phase == "complete":
        stats = agentstate.ledger_stats(goal_id)
        if stats["stale"]:
            raise CapabilityError(
                f"cannot mark complete: {stats['stale']} claim(s) went stale "
                f"because the harness changed. Re-run them against the current "
                f"harness first — the results were measured with a different "
                f"ruler.",
                code="stale_evidence")
        if stats["verified"] == 0:
            raise CapabilityError(
                "cannot mark complete: the ledger holds no verified claim for "
                "this goal. Run verify.gate(record=true) first — a goal is "
                "achieved when evidence says so, not when the work stops.",
                code="no_evidence")

    fields = {}
    if phase:
        fields["phase"] = phase
    if params.get("note"):
        fields["note"] = params["note"]
    # Disarming on completion/pause is the safe default: an unarmed goal will
    # not be auto-continued by the round driver.
    if phase in ("complete", "paused"):
        fields["activation"] = "disarmed"
    agentstate.update_goal(goal_id, **fields)

    goal = agentstate.get_goal(goal_id) or {}
    yield em.result({
        **goal,
        "text": shaping.with_status(
            f"goal {goal_id} -> phase={goal.get('phase')} "
            f"activation={goal.get('activation')}", ok=True),
    })


async def ledger_stats(params: dict, ctx: InvokeContext):
    """What is established, and what silently stopped being established."""
    em = EventEmitter("ledger.stats")
    goal_id = params.get("goal_id") or ""
    stats = agentstate.ledger_stats(goal_id)
    rows = agentstate.claims(goal_id)

    lines = [
        f"harness digest : {stats['harness_digest']}",
        f"claims         : {stats['total']} total, "
        f"{stats['verified']} verified, {stats['stale']} stale, "
        f"{stats['unverified']} unverified, {stats['refuted']} refuted",
    ]
    if stats["newly_stale"]:
        lines.append(f"JUST WENT STALE: {stats['newly_stale']} — the harness "
                     f"changed, so these were measured with a different ruler")
    if stats["verified_without_denominator"]:
        lines.append(f"WARNING: {stats['verified_without_denominator']} verified "
                     f"claim(s) carry no denominator — coverage is unknown")
    for c in rows:
        mark = {"verified": "OK ", "stale": "OLD", "refuted": "NO "}.get(
            c["status"], "?  ")
        cov = (f"{c['cases_passed']}/{c['cases_total']}"
               if c["cases_total"] is not None else "no denominator")
        lines.append(f"  [{mark}] {c['statement'][:70]}  ({cov})")
        if c["failures"]:
            lines.append(f"         failures: {len(c['failures'])} "
                         f"{c['failures'][:3]}")
    if not rows:
        lines.append("  (ledger empty)")

    yield em.result({
        **stats,
        "claims": [{k: v for k, v in c.items() if k != "evidence"} for c in rows],
        "text": shaping.with_status("\n".join(lines), ok=True,
                                    detail=f"{stats['verified']} verified"),
    })


async def chat_sessions(params: dict, ctx: InvokeContext):
    """List past conversations so a session can be resumed instead of restarted."""
    em = EventEmitter("chat.sessions")
    rows = agentstate.list_conversations(int(params.get("limit") or 30))
    lines = []
    for r in rows:
        import datetime
        when = datetime.datetime.fromtimestamp(r["updated"]).strftime("%m-%d %H:%M")
        mark = " [archived]" if r["archived"] else ""
        lines.append(f"  {r['id']}  {when}  {r['turns']:>3} turns  "
                     f"{r['title'] or '(untitled)'}{mark}")
    if not rows:
        lines.append("  (no conversations yet)")
    yield em.result({
        "conversations": rows,
        "text": shaping.with_status("\n".join(lines), ok=True,
                                    detail=f"{len(rows)} conversation(s)"),
    })


async def chat_history(params: dict, ctx: InvokeContext):
    """Read a conversation back — for the UI, and for resuming after a restart."""
    em = EventEmitter("chat.history")
    cid = params.get("conversation_id") or ""
    if not cid:
        latest = agentstate.latest_conversation()
        cid = (latest or {}).get("id", "")
    if not cid:
        yield em.result({"conversation_id": "", "turns": [],
                         "text": shaping.with_status("no conversation yet", ok=True)})
        return
    conv = agentstate.get_conversation(cid)
    if conv is None:
        raise CapabilityError(f"no conversation {cid}", code="not_found")
    turns = agentstate.conversation_turns(cid, int(params.get("limit") or 200))
    lines = [f"{t['role']}: {' '.join((t['content'] or '').split())[:100]}"
             for t in turns]
    yield em.result({
        "conversation_id": cid,
        "title": conv.get("title", ""),
        "turns": turns,
        "text": shaping.with_status(
            f"conversation {cid} ({conv.get('title') or 'untitled'}), "
            f"{len(turns)} turn(s)\n" + "\n".join(lines),
            ok=True, detail=f"{len(turns)} turns"),
    })


SPECS = (
    CapabilitySpec(
        id="goal.set",
        kind="goal",
        name="设定调查目标",
        description="创建/更新本次调查的目标对象：目标 + **完成判据** + 轮次上限。"
                    "完成判据由人给；没有判据就无法判定是否完成。",
        params=schema(
            {
                "objective": string("要达成什么"),
                "criteria": string("完成判据（怎么算做完了）"),
                "note": string("备注"),
                "max_rounds": integer("最多自动续轮次数", default=25),
                "replace": boolean("替换当前目标而不是更新", default=False),
            },
            required=["objective"],
        ),
        returns=schema({"id": {"type": "string"}, "phase": {"type": "string"}}),
        streaming=True, cost=COST_FREE, sensitivity=SENS_INTERNAL,
        backend="providers.investigation", tags=("goal", "long-horizon"),
    ),
    CapabilitySpec(
        id="goal.get",
        kind="goal",
        name="读取当前目标",
        description="读当前目标与完成判据。**宣布完成之前必须调用它**——"
                    "不能凭自己的叙述判断进度。",
        params=schema({"goal_id": string("指定目标，留空取当前活跃目标")}),
        returns=schema({"goal": {"type": "object"}}),
        streaming=True, cost=COST_FREE, sensitivity=SENS_INTERNAL,
        backend="providers.investigation", tags=("goal", "long-horizon"),
    ),
    CapabilitySpec(
        id="goal.update",
        kind="goal",
        name="更新目标状态",
        description="改 phase（active/paused/blocked/complete）或备注。"
                    "**标记 complete 需要账本里有已验证的主张**，且不能有失效的"
                    "（harness 变了导致失真的那些）。",
        params=schema(
            {
                "goal_id": string("目标 id，留空取当前"),
                "phase": string("active | paused | blocked | complete"),
                "note": string("备注"),
            },
        ),
        returns=schema({"phase": {"type": "string"}}),
        streaming=True, cost=COST_FREE, sensitivity=SENS_INTERNAL,
        backend="providers.investigation", tags=("goal", "long-horizon"),
    ),
    CapabilitySpec(
        id="ledger.stats",
        kind="goal",
        name="主张账本",
        description="列出已验证/失效/未验证的主张，含分母与失败清单，并标出"
                    "**因 harness 变更而失效**的那些。只能经 verify.gate(record=true) 写入。",
        params=schema({"goal_id": string("限定某个目标")}),
        returns=schema({"verified": {"type": "integer"}, "stale": {"type": "integer"}}),
        streaming=True, cost=COST_FREE, sensitivity=SENS_INTERNAL,
        backend="providers.investigation", tags=("goal", "ledger", "verify"),
    ),
    CapabilitySpec(
        id="chat.sessions",
        kind="goal",
        name="历史会话",
        description="列出过去的对话（按最近更新排序），用于**续接而不是重开**。"
                    "对话存在内核里，关掉客户端不会丢上下文。",
        params=schema({"limit": integer("最多返回几条", default=30)}),
        returns=schema({"conversations": {"type": "array"}}),
        streaming=True, cost=COST_FREE, sensitivity=SENS_INTERNAL,
        backend="providers.investigation", tags=("chat", "session", "history"),
    ),
    CapabilitySpec(
        id="chat.history",
        kind="goal",
        name="读取会话",
        description="读回某个会话的全部轮次（含工具调用记录）。留空 conversation_id 取最近一个。",
        params=schema(
            {
                "conversation_id": string("会话 id，留空取最近一个"),
                "limit": integer("最多返回几轮", default=200),
            },
        ),
        returns=schema({"conversation_id": {"type": "string"},
                        "turns": {"type": "array"}}),
        streaming=True, cost=COST_FREE, sensitivity=SENS_INTERNAL,
        backend="providers.investigation", tags=("chat", "session", "history"),
    ),
)

HANDLERS = {
    "goal.set": goal_set,
    "goal.get": goal_get,
    "goal.update": goal_update,
    "ledger.stats": ledger_stats,
    "chat.sessions": chat_sessions,
    "chat.history": chat_history,
}


def register_all(registry) -> None:
    for spec in SPECS:
        registry.register(spec, HANDLERS[spec.id])
