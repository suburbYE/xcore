"""
Capability provider: conversational agent.

The point of this module is that the user describes what they want and the model
decides which capabilities to run — nobody hand-picks `engine.native_scan` from a
dropdown.

The design choice that makes that maintainable: **tool schemas are derived from
the capability registry, not written by hand.** Every capability already carries
a JSON Schema for its params, so adding a capability automatically makes it
callable by the agent. There is no second list to keep in sync.

Loop: model -> tool calls -> execute through the kernel channel -> feed results
back -> repeat until the model answers, or the round budget runs out.

Safety: every capability invoked here goes through the same Registry, so the
scheduler's concurrency limits, the circuit breakers, and the memory layer's
read-only guarantees all still apply. The agent is a client of the channel, not
a bypass around it.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import time
import urllib.error
import urllib.request

from ..contract import (
    COST_CLOUD,
    SENS_INTERNAL,
    CapabilityError,
    CapabilitySpec,
    EventEmitter,
    InvokeContext,
    boolean,
    integer,
    schema,
    string,)
from .. import agentstate
from .. import inbox
from .. import jobs as jobmod
from .. import triage
from .. import workspace as workspace_mod
from ...config import AGENT_MAX_TOKENS
from .. import output as shaping

# OpenAI-style function names allow only [a-zA-Z0-9_-], so capability ids
# (`engine.native_scan`) are flattened and mapped back on execution.
_NAME_SAFE = re.compile(r"[^a-zA-Z0-9_-]")

# Capabilities that must never be agent-callable: destructive, so expensive that
# a misread instruction would be costly, or the agent itself.
#
# `agent.*` is excluded for a structural reason, not a cost one: exposing
# `agent.chat` as a tool lets the model invoke a nested agent run, which is
# recursive, doubles the spend, and hides what was actually executed behind an
# opaque "ok (1613 chars)". One agent, no nesting.
AGENT_DENY = {
    "agent.chat",            # recursion
    "agent.investigate",     # recursion (the round driver calls agent.chat)
    "agent.tools",           # introspection, not a task
    "job.submit",            # the loop starts jobs itself; see LONG_RUNNING
}

# Capabilities that take minutes. They are NOT excluded any more — excluding
# them meant the agent could not perform either of the two tasks it exists for.
# A minutes-long runtime is a scheduling constraint, so instead of banning them
# the loop offers a `background` flag on their tool schema and routes it to the
# job manager. `engine.deobfuscate` and `native.apk_pipeline` were in AGENT_DENY
# for exactly this reason and no longer need to be.
LONG_RUNNING = {
    "engine.deobfuscate",
    "native.apk_pipeline",
    "engine.native_scan",
    "native.target_scan",
    "web.pipeline",
}

# ── budget ──────────────────────────────────────────────────────────────────
#
# Replacing a hard step cap with a metered one. Both Codex and Anthropic
# converge here: Codex has **no** per-turn/task budget at all (only token
# metering plus threshold reminders), and Anthropic's task budget is explicitly
# advisory — a countdown the model can see, whose purpose is to let it "finish
# gracefully rather than cutting off mid-action".
#
# A hard `MAX_CALLS_TOTAL = 10` did exactly the cutting-off: an end-to-end test
# was stopped at call 7 mid-task and only produced an answer because the loop
# forces a summary. So the ceiling is now high enough not to be the binding
# constraint, and the loop tells the model how much room is left.
MAX_ROUNDS_DEFAULT = 12
MAX_CALLS_TOTAL = 40
BUDGET_WARN_AT = (0.75, 0.9)   # fractions of budget spent at which to remind

MAX_TOOL_RESULT_CHARS = 6000
# The whole transcript is re-sent on every round, so anything left in it is
# paid for once per remaining round. A 6000-char scan result kept across five
# more rounds costs 30k characters on its own, and the incoming history is
# likewise unbounded — the GUI hands back the conversation so far. Both are
# therefore bounded in total, not merely per item.
MAX_HISTORY_MSG_CHARS = 4000
MAX_HISTORY_CHARS = 8000
MAX_TRANSCRIPT_CHARS = 24000

# ── goal rounds ─────────────────────────────────────────────────────────────
#
# The continuation prompt is the whole mechanism for surviving a context
# boundary, and both halves of it are load-bearing:
#
#   * "inspect them instead of assuming earlier narration is still current" —
#     the antidote to the measured failure where an agent "would look around,
#     see that progress had been made, and declare the job done". xcore did
#     exactly that: it reported 已归档完成 while knowledge/ stayed at 115 files.
#     The fix is not one more rule; it is telling the agent to re-read the world
#     rather than trust its own narration.
#   * "gather evidence that the whole objective is achieved" — a completion
#     claim needs an executed gate behind it.
GOAL_ROUND_PROMPT = (
    "<goal_round>\n"
    "Objective: {objective}\n"
    "Completion criteria: {criteria}\n"
    "Round: {round}/{max_rounds}\n\n"
    "Continue working toward the objective in this same session. Treat the "
    "current workspace, tool results, and durable state as authoritative; "
    "inspect them instead of assuming earlier narration is still current. "
    "Make concrete progress and verify the result. Before claiming completion, "
    "gather evidence that the whole objective is achieved, read the current "
    "goal, and mark it complete. If work remains, leave the goal active for "
    "the next round.\n"
    "</goal_round>"
)

# Deterministic completion-claim detection. An LLM judge is the wrong tool
# here: no judge configuration exceeded AUROC 0.65 at spotting false success,
# while cheap lexical features reached 0.83-0.95 at ~1ms per trajectory and
# caught 4-8x more (arXiv:2606.09863). This is the cheap feature.
COMPLETION_MARKERS = (
    "已完成", "完成了", "已归档", "已入库", "搞定", "全部完成", "验证通过",
    "已验证", "已经完成", "done", "completed", "verified", "finished",
)
# ...but a bare mention is not a claim; these qualify it back out.
HEDGE_MARKERS = ("没有", "未", "还不能", "无法", "不算", "不能宣称", "尚未",
                 "not ", "cannot", "unverified")
# Observed failure mode: asked a follow-up whose answer was already in the
# previous turn's tool output, the model re-searched 11 times with reworded
# queries instead of reading what it had. Caps turn that into a bounded cost.
# (The per-round cap stays; the *total* cap now lives with the budget block
# above, where it is metered and visible rather than a silent cliff.)
MAX_CALLS_PER_ROUND = 4

# ── tool list cost ──────────────────────────────────────────────────────────
#
# Every round ships the tool schemas to the model, so the list length is a
# *recurring* cost, not a one-off: all 20 tools ≈ 3.5k tokens per round, up to
# 6 rounds. Sending the scanner schemas for "判例库有多少条案例" is most of the
# bill — and it also invites the model to call a scanner on a greeting.
#
# Two-stage selection:
#   1. TOOL_INTENT — a hand-written phrase table. Chinese phrasing does not
#      survive CJK-bigram matching against the schema text: "判例" appears in
#      both engine.scan and engine.db_stats, so registry order silently
#      decided the winner and four different questions produced four identical
#      tool sets. The disambiguation is written down instead of inferred.
#   2. Lexical scoring over id/kind/tags/description for anything the table
#      does not name, so a newly registered capability is still discoverable
#      without editing this file.
#
# Nothing is padded in: a turn matching no intent sends TOOL_CORE only, so
# "你好" costs one schema instead of twenty.
TOOL_PRESELECT = 8          # hard ceiling on tools sent in one turn
TOOL_CORE = (               # always sent, regardless of wording
    "memory.recall",        # the generic "look something up" escape hatch
    "sh.run",               # the universal verb: without it the agent can only
                            # reach what someone already wrapped as a capability
)

# (weight, trigger phrases, capability ids). Triggers match as lowercase
# substrings of the message; the heaviest matching row wins per capability.
TOOL_INTENT: tuple[tuple[int, tuple[str, ...], tuple[str, ...]], ...] = (
    # The substrate verbs come first: an agent that cannot reach the shell
    # cannot improvise, and "run this / search this / edit this" is the most
    # common thing a long investigation needs.
    (13, ("跑一下", "跑一遍", "执行", "运行脚本", "写个脚本", "写脚本", "试试",
          "run ", "execute", "shell", "命令行", "脚本"),
     ("sh.run",)),
    (12, ("吃进去", "喂进去", "录进去", "录入", "入库", "收录", "归档", "沉淀",
          "学一下", "学会", "ingest", "learn"),
     ("knowledge.learn",)),
    (12, ("验证", "对拍", "核对", "证明", "是不是真的", "确认一下", "负对照",
          "verify", "prove"),
     ("verify.gate",)),
    (11, ("进度", "做到哪了", "已完成什么", "账本", "哪些验证过", "还剩什么"),
     ("ledger.stats", "goal.get")),
    (12, ("批量", "逐个", "参数空间", "扫一遍", "对拍", "循环", "遍历",
          "多个样本", "一次跑"),
     ("code.run",)),
    (10, ("作业", "后台", "跑完没", "还没好", "进度条", "job"),
     ("job.output", "job.list")),
    (11, ("搜索", "找找文件", "哪些文件", "grep", "匹配", "检索代码"),
     ("fs.search",)),
    (10, ("改一下", "修改文件", "编辑", "patch", "改脚本", "修一下"),
     ("fs.patch",)),
    (11, ("多少条", "几条", "有多少", "多少个", "数量", "统计", "规模", "多大",
          "多大体积", "how many", "count", "stats"),
     ("engine.db_stats", "memory.stats", "knowledge.stats")),
    (10, ("脱壳", "加固", "加壳", "壳检测", "什么壳", "梆梆", "爱加密", "乐固",
          "聚安全", "360加固"),
     ("native.shell_classify", "native.apk_pipeline", "native.probe_generate")),
    (10, ("frida", "探针", "截获", "hook 点", "hook点", "注入点", "probe"),
     ("native.probe_generate", "native.target_scan")),
    (9, ("扫描", "扫一下", "扫一遍", "扫扫", "什么算法", "用了什么", "用了啥",
         "识别算法", "指纹", "符号表", "scan"),
     ("engine.native_scan", "native.target_scan", "engine.scan")),
    (9, ("混淆", "平坦化", "还原", "反混淆", "ast", "deobf", "等价性"),
     ("engine.deobfuscate", "engine.verify")),
    (9, ("wasm", "网页", "网站", "抓取", "签名参数", "接口", "js vm", "jsvm",
         "解释器"),
     ("web.pipeline", "web.wasm", "web.jsvm")),
    (9, ("重新索引", "重建索引", "重建向量", "清空索引", "重建", "rebuild"),
     ("memory.rebuild", "memory.index")),
    (8, ("建索引", "索引", "向量", "嵌入", "embed", "index"),
     ("memory.index", "memory.stats")),
    (8, ("记一下", "记录一下", "记录这", "备注", "备忘", "markdown"),
     ("memory.record",)),
    (8, ("有哪些算子", "哪些算法", "算法分布", "分布", "命中率", "置信度"),
     ("engine.db_stats",)),
    (7, ("分别", "批量", "各自", "并行", "一起问", "多个问题"),
     ("llm.fanout", "llm.ask")),
    (7, ("为什么走", "路由", "为什么用云", "哪个模型", "成本", "花了多少",
         "余额", "贵", "便宜", "省点", "预算", "token"),
     ("llm.plan", "llm.ask")),
    (6, ("之前", "以前", "上次", "记得", "找找", "检索", "召回", "查一下",
         "还记得"),
     ("memory.recall",)),
)


def _score_tool(tool: dict, cap_id: str, spec: dict, text: str) -> int:
    """Cheap lexical relevance between a capability and the user's message.

    Scored from both the OpenAI-shaped tool (name/description as the model sees
    them) and the registry spec (id/kind/tags, which the model does not).
    """
    if not text:
        return 0
    t = text.lower()
    score = 0

    if cap_id.lower() in t:
        score += 10
    kind = (spec.get("kind") or "").lower()
    if kind and kind in t:
        score += 4
    for tag in spec.get("tags") or []:
        if tag and str(tag).lower() in t:
            score += 6

    fn = tool.get("function") or {}
    name = f"{fn.get('name','')} {spec.get('name','')}".lower()
    desc = (fn.get("description") or "").lower()
    for token in _tokens(t):
        if len(token) < 2:
            continue
        if token in name:
            score += 3
        if token in desc:
            score += 2
        if token in cap_id.lower():
            score += 3
    return score


def _tokens(text: str) -> list[str]:
    """Split latin words and CJK trigrams — no tokenizer dependency.

    Trigrams rather than bigrams: at bigram width "判例" / "案例" / "多少" are
    common enough to match half the registry, which made the lexical pass add
    noise instead of signal.
    """
    out = re.findall(r"[a-z0-9_.:]{2,}", text)
    for run in re.findall(r"[\u4e00-\u9fff]+", text):
        if len(run) < 3:
            out.append(run)
            continue
        out.extend(run[i:i + 3] for i in range(len(run) - 2))
    return out


def _matched_intents(text: str) -> dict[str, int]:
    """capability id -> heaviest trigger weight this message matched."""
    t = (text or "").lower()
    hits: dict[str, int] = {}
    if not t:
        return hits
    for weight, triggers, caps in TOOL_INTENT:
        if any(tr in t for tr in triggers):
            for cap in caps:
                if weight > hits.get(cap, 0):
                    hits[cap] = weight
    return hits


def select_tools(registry, message: str, history: list[dict] | None = None,
                 limit: int = TOOL_PRESELECT) -> tuple[list[dict], dict[str, str], dict]:
    """Return (tools, reverse_map, stats) for one conversation turn.

    Selection happens ONCE per turn from the full message (plus a little recent
    history), not per round — the model may need the same tools across rounds,
    and re-selecting mid-turn would make the available set inconsistent.
    """
    everything, reverse_all = build_tool_schemas(registry)
    specs_by_id = {s["id"]: s for s in registry.specs()}
    by_name = {t["function"]["name"]: t for t in everything}

    context = message or ""
    for h in (history or [])[-3:]:
        if h.get("content"):
            context += " " + str(h["content"])

    intents = _matched_intents(context)

    # Intent hits are authoritative; lexical scoring only fills in the
    # capabilities the phrase table does not name.
    ranked: list[tuple[int, str, dict]] = []
    for tool in everything:
        cap_id = reverse_all.get(tool["function"]["name"], "")
        score = intents.get(cap_id) or _score_tool(
            tool, cap_id, specs_by_id.get(cap_id, {}), context)
        ranked.append((score, cap_id, tool))
    ranked.sort(key=lambda r: (-r[0], r[1]))

    chosen: list[dict] = []
    have: set[str] = set()

    def take(tool: dict) -> None:
        nm = tool["function"]["name"]
        if nm not in have and len(chosen) < limit:
            chosen.append(tool)
            have.add(nm)

    for cap_id in TOOL_CORE:
        tool = by_name.get(to_tool_name(cap_id))
        if tool is not None:
            take(tool)

    for score, _cap_id, tool in ranked:
        if score > 0:
            take(tool)

    reverse = {t["function"]["name"]: reverse_all[t["function"]["name"]]
               for t in chosen}
    stats = {
        "total_available": len(everything),
        "sent": len(chosen),
        "tools": sorted(reverse.values()),
        "intents": sorted(intents),
    }
    return chosen, reverse, stats


def to_tool_name(cap_id: str) -> str:
    return _NAME_SAFE.sub("_", cap_id)


def build_tool_schemas(registry, allow: list[str] | None = None,
                       deny: set[str] | None = None) -> tuple[list[dict], dict[str, str]]:
    """Derive tool schemas from the registry.

    Returns (tools, name->capability_id). The reverse map is what lets us run
    the right capability when the model answers with a flattened name.
    """
    deny = deny if deny is not None else AGENT_DENY
    tools: list[dict] = []
    reverse: dict[str, str] = {}
    for spec in registry.specs():
        cap_id = spec["id"]
        if cap_id in deny:
            continue
        # Belt and braces: anything in the agent's own kind is excluded even if
        # someone adds a new agent.* capability and forgets the denylist.
        if spec.get("kind") == "agent":
            continue
        if allow is not None and cap_id not in allow:
            continue
        name = to_tool_name(cap_id)
        params = spec.get("params") or {}
        # An object schema with no properties still needs a valid shape.
        if params.get("type") != "object":
            params = {"type": "object", "properties": {}}
        params = {k: v for k, v in params.items() if k != "additionalProperties"}
        params = {**params,
                  "properties": dict(params.get("properties") or {})}
        # Long-running capabilities carry the scheduling decision in their own
        # schema, so the model can choose to background a minutes-long scan
        # instead of blocking the turn on it.
        if cap_id in LONG_RUNNING:
            params["properties"]["background"] = {
                "type": "boolean", "default": False,
                "description": ("丢到后台跑并立刻返回 job_id，用 job.output 读进度。"
                                "这个能力可能要跑几分钟——想同时干别的就设 true。"),
            }
        params["additionalProperties"] = False
        tools.append({
            "type": "function",
            "function": {
                "name": name,
                "description": (spec.get("description") or spec.get("name") or "")[:900],
                "parameters": params,
            },
        })
        reverse[name] = cap_id
    return tools, reverse


# ── orchestration backends ──────────────────────────────────────────────────
# Both are normalised to OpenAI's tool-calling shape so the loop above does not
# care which one ran.

def _ollama_tools(model: str, messages: list[dict], tools: list[dict],
                  timeout: int) -> dict:
    import urllib.request
    from ...config import OLLAMA_URL

    payload = json.dumps({
        "model": model,
        "messages": messages,
        "tools": tools,
        "stream": False,
        "options": {"temperature": 0.1, "num_predict": 1024},
    }).encode()
    req = urllib.request.Request(f"{OLLAMA_URL}/api/chat", data=payload,
                                 headers={"Content-Type": "application/json"})
    raw = json.loads(urllib.request.urlopen(req, timeout=timeout).read())
    msg = raw.get("message", {}) or {}
    calls = []
    for tc in msg.get("tool_calls", []) or []:
        fn = tc.get("function", {}) or {}
        calls.append({
            "id": tc.get("id") or f"call_{len(calls)}",
            "name": fn.get("name", ""),
            "arguments": fn.get("arguments", {}) or {},
        })
    return {
        "content": (msg.get("content") or "").strip(),
        "tool_calls": calls,
        "model": raw.get("model", model),
        "prompt_tokens": raw.get("prompt_eval_count", 0) or 0,
        "completion_tokens": raw.get("eval_count", 0) or 0,
    }


def _cloud_tools(provider: str, model: str, messages: list[dict],
                 tools: list[dict], timeout: int) -> dict:
    import urllib.request
    from ...api_key import APIKeyManager
    from ...providers import registry as preg

    spec = preg.get(provider)
    if spec is None:
        raise CapabilityError(f"unknown provider '{provider}'", code="unknown_provider")
    keys = (APIKeyManager.load() or {}).get("providers", {}) or {}
    key = keys.get(provider)
    if not key:
        raise CapabilityError(f"no API key for '{provider}'", code="no_api_key")

    payload = json.dumps({
        "model": model,
        "messages": messages,
        "tools": tools,
        "tool_choice": "auto",
        # The orchestrator has to emit tool-call *arguments*, which for
        # `code.run` or `fs.patch` means a whole script inside a JSON string.
        # At the old hardcoded 1500 the model spent the entire budget on
        # reasoning (finish_reason=length, reasoning_tokens=1500), the argument
        # was truncated mid-generation, and the tool arrived missing its
        # required parameter — which reads as the model forgetting an argument
        # when the cause is the ceiling. Override with XCORE_AGENT_MAX_TOKENS.
        "max_tokens": int(os.environ.get("XCORE_AGENT_MAX_TOKENS")
                          or AGENT_MAX_TOKENS),
    }).encode()
    req = urllib.request.Request(spec.chat_url, data=payload, method="POST")
    for k, v in spec.auth_headers(key, chat=True).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = json.loads(r.read())
    except urllib.error.HTTPError as e:
        # The body carries the actual reason (unsupported schema field, unknown
        # model, tools not enabled). Without it a 400 is undebuggable.
        detail = e.read().decode("utf-8", "replace")[:700]
        raise CapabilityError(
            f"{provider} rejected tool calling: HTTP {e.code} {detail}",
            code="orchestrator_http_error") from None
    choice = (raw.get("choices") or [{}])[0]
    msg = choice.get("message", {}) or {}
    usage = raw.get("usage", {}) or {}
    calls = []
    for tc in msg.get("tool_calls", []) or []:
        fn = tc.get("function", {}) or {}
        args = fn.get("arguments", "{}")
        if isinstance(args, str):
            try:
                args = json.loads(args or "{}")
            except json.JSONDecodeError:
                args = {}
        calls.append({"id": tc.get("id") or f"call_{len(calls)}",
                      "name": fn.get("name", ""), "arguments": args})
    return {
        "content": (msg.get("content") or "").strip(),
        "tool_calls": calls,
        "model": raw.get("model", model),
        "prompt_tokens": usage.get("prompt_tokens", 0) or 0,
        "completion_tokens": usage.get("completion_tokens", 0) or 0,
        # Without this an empty reply is a mystery; with it we can tell a
        # truncation apart from a model that simply said nothing.
        "finish_reason": choice.get("finish_reason", "") or "",
        "reasoning_tokens": (usage.get("completion_tokens_details") or {})
                            .get("reasoning_tokens", 0) or 0,
    }


def _pick_orchestrator(backend: str) -> tuple[str, str, str]:
    """Return (kind, provider, model) for the orchestration model.

    Tool calling is the one job where a 3B model is genuinely unreliable, so the
    default prefers a cloud model and falls back to local.

    Provider order is NOT arbitrary — Gemini is deliberately last:

    * Gemini's OpenAI-compatible endpoint cannot do multi-turn tool calling. When
      the assistant's functionCall turn is sent back it answers
      ``400 Function call is missing a thought_signature in functionCall parts``
      — that signature is only produced by the native API, so the compat shim
      cannot round-trip tools. (Verified empirically: single-shot tool calls
      return 200, the follow-up round returns 400.)
    * Gemini's free tier also allows only ~5 requests/minute, and every agent
      round is at least one request, so it would throttle almost immediately.

    DeepSeek speaks the OpenAI protocol properly, including tool round-trips.
    """
    from ...api_key import APIKeyManager
    from ...config import DIALOG_MODEL
    from ...providers import registry as preg

    keys = (APIKeyManager.load() or {}).get("providers", {}) or {}

    if backend == "local":
        return ("local", "", DIALOG_MODEL)

    # Ordered by tool-calling reliability, not by preference or price.
    for provider in ("deepseek", "openai", "gemini"):
        if provider not in keys:
            continue
        if provider == "gemini" and backend != "cloud":
            # Only reach for it if the caller explicitly forced cloud and
            # nothing else is configured.
            continue
        spec = preg.get(provider)
        default = spec.default_model
        try:
            from ...providers import account
            models, _ = account.list_models(provider)
            ids = {m.id for m in models}
            if default not in ids and models:
                # Registry default retired; fall back to a listed model so a
                # vendor rename does not silently break the agent.
                default = models[0].id
        except Exception:
            pass
        return ("cloud", provider, default)

    # Forced-cloud with only Gemini available: better than nothing, but the
    # second round will fail on thought_signature.
    for provider in ("gemini",):
        if provider in keys:
            return ("cloud", provider, preg.get(provider).default_model)

    return ("local", "", DIALOG_MODEL)


# ── the loop ────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """你是 X-Core 逆向分析助手。你可以调用工具来完成任务。

规则：
- 需要分析文件、扫描二进制、查记忆库时，**直接调用工具**，不要问用户要参数。
- 用户给的是自然语言意图，你自己判断该用哪个工具、填什么参数。
- 路径不明确时，先用 memory.recall 查历史，或用最可能的路径试。
- 工具返回后，用中文简明总结结论；不要复述原始 JSON。
- 一次可以调用多个工具。信息够了就直接给结论，不要多余的话。
- 工具失败时说明失败原因，不要编造结果。

**重要 —— 存储类操作别搞混**：
- `knowledge.learn` = **写进知识库**（L1，永久资产）。用户说"吃进去 / 入库 / 存到知识库 / 记下来"时用这个。
- `memory.record` = 只记一条**情节**（L4 会话日志），**不是入库**。它不会让样本以后能被检索到。
- `memory.index` = 把**已有**的 L1/L2 建向量索引，**不会新增**任何知识条目。
- 用户让你"吃数据"时，**必须用 `knowledge.learn`**。只用 `memory.record` 然后说"已归档"
  是在谎报 —— 知识库一条都不会增加。
- 工具返回里 `stored: false` 就是**没存进去**，必须如实告知用户原因（`reason` 字段），
  不许说成"已完成"。

**重要 —— 不要重复劳动**：
- 回答前先看**上面已有的工具结果**。如果答案已经在里面，直接回答，不要再调工具。
- 不要为了同一个问题反复换措辞查询同一个工具。换一次没找到就应该停止。
- 每次最多调用 2-3 个工具。找不到就如实说找不到，不要一直搜。
- 调用 memory.recall 时 `query` 是必填参数，不能为空。

**你有手 —— 不要只会查库**：
- `sh.run` = 在工作台里跑命令。这是通用动词：分析脚本、跑引擎、驱动
  Unicorn/capstone 都走它。**没有现成工具可用时，写个脚本跑，不要卡住。**
- **这个 shell 是 Windows 的 cmd.exe，不是 POSIX shell。** 别用 `ls`/`cat`/`find`/
  `2>/dev/null`/`~` —— 用 `dir`/`type`/`where`/`2>nul`/`%USERPROFILE%`。
  要 PowerShell 就显式写 `powershell -Command "..."`。
  工具返回里会带翻译提示，看到了就照它改，别重复同一条命令。
- **脚本要落成文件**：用 `fs.patch(content=...)` 写到 `workbench/xxx.py`，再用
  `sh.run` 跑它。不要用 `python -c "..."` 内联一大段——cmd 不支持 heredoc
  （`<<EOF`），长内联的引号会把你坑死，而且**内联的东西留不下来**：下一轮想改一行
  得重写整段，也无法被复用或对拍。落成文件才能 `fs.patch` 改一行、反复跑。
- `fs.patch` 改工作台里的脚本（apply-or-fail，old 必须唯一匹配）。改的是**量具**，不是靶子。
- `fs.search` = 检索，**只返回计数和文件名**，要内容请显式读取。
- `code.run` = **一次往返里跑 N 次能力调用**。要扫参数空间、批量对拍、逐条比对时用它，
  别一轮一轮地调 —— 写一段 Python，里面用 `xcore.call("能力id", **参数)`，
  把 `{"cases_total":N,"cases_passed":M,"failures":[...]}` 放进 `result`，
  就能直接交给 `verify.gate` 当检查。这是既省时间又省钱的做法。
- 目标文件只读，工作台 `workbench/` 可写。写别处会被策略拒绝——那是设计，不是 bug。

**结论必须能被证伪**：
- 宣布"已验证/已完成"之前，用 `verify.gate` 过一遍：给它一条 `negative_control`
  （**必须失败**的命令），它先证明这个检查**能失败**，再跑真正的检查。
- 负对照通过 = 检查没有区分力 = 你的"通过"什么也证明不了。这时要**修检查**，不是换一句话说。
- 检查若能打印一行 `{"cases_total":N,"cases_passed":M,"failures":[...]}`，闸门会记下
  分母和失败清单。**只报百分比不算证据** —— 分母和失败的是哪些才是。
- 想让结论进账本，加 `record=true`。**账本只有闸门能写**，你没法自己记一条"已验证"。

**别凭自己的叙述判断进度**：
- 说"做完了"之前先 `goal.get` 读目标和完成判据，再 `ledger.stats` 看账本里
  到底有几条已验证、有没有**因量具变更而失效**的。
- 改了工作台里的脚本 = 换了量具 = 之前用它测出来的结论全部失效。这不是提醒，是机制：
  旧主张会被自动标成 stale，`ledger.stats` 会告诉你哪些要重跑。

**长任务丢后台，不要傻等**：
- 扫描/脱壳/反混淆这类可能跑几分钟的能力，schema 里有 `background` 参数。
  设 `background: true` 会立刻返回一个 `job_id`，你就能同时干别的。
- 读进度用 `job.output`（只返回**自上次读取以来**的新输出，末尾带状态行），
  要看全部作业用 `job.list`，不要了用 `job.kill`。
- **不要反复提交同一个作业，也不要空转等待** —— 作业结束时会在下一轮以提示的形式
  自动出现。别重复劳动。"""


async def _execute_tool(cap_id: str, args: dict, registry, em: EventEmitter,
                        ctx: InvokeContext, timeout: float = 900.0):
    """Run one capability and collapse its event stream into a result payload.

    Sub-process capabilities can take minutes; the caller wraps this in
    asyncio.wait_for so one slow tool cannot wedge the whole conversation.
    """
    events = []
    result, error = None, None

    async def _run():
        nonlocal result, error
        async for ev in registry.invoke(cap_id, args, ctx):
            events.append(ev)
            if ev.type == "result":
                result = ev.data.get("value")
            elif ev.type == "error":
                error = ev.data

    await asyncio.wait_for(_run(), timeout=timeout)
    return result, error, events


def _bounded_history(history: list[dict],
                     budget: int = MAX_HISTORY_CHARS) -> tuple[list[dict], int]:
    """Newest-first accumulation of whole turns that fit in `budget`.

    Returns (turns, dropped). The newest turn is always kept even if it alone
    exceeds the budget — dropping it would leave the model with no thread to
    follow — but it is clamped to MAX_HISTORY_MSG_CHARS first.
    """
    out: list[dict] = []
    used = 0
    dropped = 0
    for h in reversed(history[-12:]):
        role = h.get("role")
        content = h.get("content")
        if role not in ("user", "assistant") or not content:
            continue
        text = str(content)
        if len(text) > MAX_HISTORY_MSG_CHARS:
            text = text[:MAX_HISTORY_MSG_CHARS] + "…(单条历史过长，已截断)"
        cost = len(text)
        if out and used + cost > budget:
            dropped += 1
            continue
        out.append({"role": role, "content": text})
        used += cost
    out.reverse()
    return out, dropped


def _trim_transcript(messages: list[dict],
                     budget: int = MAX_TRANSCRIPT_CHARS) -> int:
    """Stub out the oldest tool results once they exceed `budget`.

    Tool results are the only part of the transcript that can be arbitrarily
    large, and the newest ones are what the model is actually reasoning over,
    so the oldest are released first. The assistant turns and the user's
    question are never touched — only the payloads.
    """
    idx = [i for i, m in enumerate(messages)
           if m.get("role") == "tool"
           and not str(m.get("content") or "").startswith("[elided")]
    total = sum(len(str(messages[i].get("content") or "")) for i in idx)
    dropped = 0
    for i in idx:
        if total <= budget:
            break
        total -= len(str(messages[i].get("content") or ""))
        messages[i]["content"] = ("[elided: 较早的工具结果已移除以控制上下文长度，"
                                  "如仍需要请重新调用]")
        dropped += 1
    return dropped


def detect_overclaim(answer: str, steps: list[dict]) -> dict:
    """Deterministic check: does the answer assert completion without evidence?

    Returns a verdict plus the features it was computed from, so the check can
    be audited rather than trusted. Deliberately not an LLM judge — see the
    note above COMPLETION_MARKERS.
    """
    text = (answer or "").lower()
    hit_markers = [m for m in COMPLETION_MARKERS if m.lower() in text]
    hedged = [h for h in HEDGE_MARKERS if h.lower() in text]
    gate_runs = sum(1 for s in steps
                    if s.get("capability") == "verify.gate" and s.get("ok"))
    recorded = sum(1 for s in steps if s.get("ledger_id"))
    # A sentence that both claims done and hedges is usually the honest
    # "I did not verify this" disclosure the prompt asks for; flagging it would
    # punish exactly the behaviour we want.
    claiming = bool(hit_markers) and not hedged
    return {
        "claims_completion": claiming,
        "markers": hit_markers,
        "hedges": hedged,
        "gate_runs": gate_runs,
        "ledger_entries": recorded,
        "overclaim": claiming and gate_runs == 0,
    }


async def chat(params: dict, ctx: InvokeContext):
    """Conversational entry point: intent in, capability calls decided by the model."""
    em = EventEmitter("agent.chat")
    message = (params.get("message") or "").strip()
    if not message:
        raise CapabilityError("'message' is required", code="invalid_params")

    registry = params.get("_registry") or ctx.registry
    if registry is None:
        from ..registry import bootstrap
        registry = bootstrap()

    history = params.get("history") or []

    # The kernel owns the conversation, not the renderer.
    #
    # History used to be a JS array in the chat panel, so closing the window
    # threw away the context and the next session opened by re-explaining the
    # task — the same understanding paid for twice. Now the stored turns are
    # authoritative and the `history` parameter is only a fallback for the very
    # first call against an empty store. `new_conversation` starts a fresh one.
    conversation_id = params.get("conversation_id") or ""
    stored: list[dict] = []
    if params.get("new_conversation"):
        conversation_id = agentstate.create_conversation(
            title=message, session_id=ctx.session_id or "")
    elif conversation_id:
        if agentstate.get_conversation(conversation_id) is None:
            conversation_id = agentstate.create_conversation(
                title=message, session_id=ctx.session_id or "")
        else:
            stored = agentstate.conversation_history(conversation_id)
    else:
        latest = agentstate.latest_conversation()
        if latest:
            conversation_id = latest["id"]
            stored = agentstate.conversation_history(conversation_id)
        else:
            conversation_id = agentstate.create_conversation(
                title=message, session_id=ctx.session_id or "")

    if stored:
        history = stored
    yield em.log(f"conversation {conversation_id}: "
                 f"{len(history)} turn(s) of context")
    agentstate.append_turn(conversation_id, "user", message)
    # One selection per turn, from the user's wording. The full list is a
    # recurring per-round cost, so shrinking it is the single biggest lever on
    # what a conversation costs.
    if params.get("all_tools"):
        tools, reverse = build_tool_schemas(registry)
        tool_stats = {"total_available": len(tools), "sent": len(tools),
                      "tools": sorted(reverse.values()), "preselected": False}
    else:
        tools, reverse, tool_stats = select_tools(registry, message, history)
        tool_stats["preselected"] = True

    if not tools:
        yield em.error("no capabilities available to the agent", code="no_tools")
        return

    kind, provider, model = _pick_orchestrator(params.get("backend", "auto"))
    max_rounds = int(params.get("max_rounds") or MAX_ROUNDS_DEFAULT)
    yield em.log(
        f"orchestrator: {kind}"
        + (f" {provider}/{model}" if kind == "cloud" else f" {model}")
        + f" | tools {tool_stats['sent']}/{tool_stats['total_available']}"
        + f", max {max_rounds} rounds")
    yield em.log("tools: " + ", ".join(tool_stats["tools"]), level="debug")

    messages: list[dict] = [{"role": "system", "content": SYSTEM_PROMPT}]
    hist, hist_dropped = _bounded_history(history)
    messages.extend(hist)
    if hist_dropped:
        yield em.log(f"history trimmed to {len(hist)} turn(s) / "
                     f"{sum(len(m['content']) for m in hist)} chars "
                     f"({hist_dropped} older turn(s) dropped)", level="debug")
    messages.append({"role": "user", "content": message})

    steps: list[dict] = []
    empty_retried = False
    calls_used = 0
    budget_warned = set()
    seen_calls: dict[str, str] = {}
    for round_no in range(1, max_rounds + 1):
        ctx.check_cancelled()
        yield em.progress(round_no / max_rounds, round=round_no)

        # Collect jobs that finished since the last round. This is the
        # turn-based substitute for a push notification: the loop asks at a
        # natural boundary instead of being interrupted mid-tool. Done before
        # the model call so the notice is available to the round that needs it.
        for job in jobmod.MANAGER.settled_unreported():
            note = (f"[job {job.id}] {job.capability} finished "
                    f"({job.status}, {job.to_dict()['duration_s']}s). "
                    f"Read its output with job.output.")
            messages.append({"role": "user", "content": note})
            yield em.log(note)

        # An interjection from the human joins the turn right here — between
        # tool calls, which is the moment a new thought can still change the
        # plan. It cannot interrupt a tool already running; this boundary is the
        # honest place to deliver it, and it keeps the transcript consistent
        # without any cancellation machinery.
        for note in inbox.INBOX.take_interjections(conversation_id):
            messages.append({"role": "user",
                             "content": f"[用户插话] {note.text}"})
            steps.append({"round": round_no, "capability": "(interjected)",
                          "arguments": {"text": note.text}, "ok": True,
                          "error": "", "ledger_id": None})
            yield em.log(f"user interjected: {note.text[:60]}")

        # A visible budget, not a silent cliff. The model is told how much room
        # is left at thresholds so it can wrap up deliberately; it is never cut
        # off at a number it could not see coming.
        spent = calls_used / MAX_CALLS_TOTAL
        for mark in BUDGET_WARN_AT:
            if spent >= mark and mark not in budget_warned:
                budget_warned.add(mark)
                left = MAX_CALLS_TOTAL - calls_used
                messages.append({
                    "role": "user",
                    "content": (f"[budget] {left} tool call(s) left of "
                                f"{MAX_CALLS_TOTAL}, and round {round_no} of "
                                f"{max_rounds}. If you are close to a result, "
                                f"finish and report what you have; if work "
                                f"remains, say what is left rather than "
                                f"starting something long."),
                })
                yield em.log(f"budget reminder: {left} call(s) left",
                             level="warning")

        try:
            loop = asyncio.get_running_loop()
            if kind == "cloud":
                resp = await loop.run_in_executor(
                    None, _cloud_tools, provider, model, messages, tools,
                    int(params.get("timeout") or 180))
            else:
                resp = await loop.run_in_executor(
                    None, _ollama_tools, model, messages, tools,
                    int(params.get("timeout") or 180))
        except Exception as e:  # noqa: BLE001 - a failed round must be reportable
            if kind == "cloud" and params.get("backend", "auto") == "auto":
                yield em.log(f"cloud orchestrator failed ({e}); falling back to local",
                             level="warning")
                kind, provider, model = "local", "", _pick_orchestrator("local")[2]
                continue
            yield em.error(f"orchestrator failed: {type(e).__name__}: {e}",
                           code="orchestrator_failed")
            return

        calls = resp.get("tool_calls") or []
        if not calls:
            answer = resp.get("content") or ""
            if not answer:
                # An empty completion is usually a truncation (the model spent
                # its budget on reasoning) rather than a refusal. Say which, and
                # retry once with a tighter instruction instead of handing the
                # user a bare "no content".
                fr = resp.get("finish_reason") or "unknown"
                rt = resp.get("reasoning_tokens") or 0
                yield em.log(
                    f"empty completion (finish_reason={fr}, reasoning_tokens={rt})",
                    level="warning")
                if round_no == 1 or not empty_retried:
                    empty_retried = True
                    messages.append({
                        "role": "user",
                        "content": "请直接给出最终答案（不要调用工具，不要输出思考过程）。",
                    })
                    yield em.log("retrying once with a direct-answer instruction")
                    continue
                answer = (f"模型没有返回内容（finish_reason={fr}"
                          f"{f', reasoning_tokens={rt}' if rt else ''}）。"
                          f"可以换个说法再问一次。")
            agentstate.append_turn(conversation_id, "assistant", answer,
                                   steps=steps)
            # An interjection that arrived after the last round boundary never
            # reached the model. Report it rather than letting it sit in the
            # inbox forever — the caller can immediately re-send it as a new
            # turn, which is what the human meant anyway.
            leftover = inbox.INBOX.take_interjections(conversation_id)
            for note in leftover:
                yield em.log(f"interjection arrived after the last round; "
                             f"returning it as queued: {note.text[:50]}",
                             level="warning")
            yield em.result({
                "answer": answer,
                "steps": steps,
                "rounds": round_no,
                "conversation_id": conversation_id,
                "undelivered": [n.to_dict() for n in leftover],
                "evidence": detect_overclaim(answer, steps),
                "orchestrator": {"kind": kind, "provider": provider, "model": model},
            })
            return

        # Record the assistant turn so the tool results have something to hang off.
        messages.append({
            "role": "assistant",
            "content": resp.get("content") or "",
            "tool_calls": [
                {"id": c["id"], "type": "function",
                 "function": {"name": c["name"],
                              "arguments": json.dumps(c["arguments"], ensure_ascii=False)}}
                for c in calls
            ],
        })

        # Trim this round's calls and de-duplicate against earlier ones. A model
        # that re-asks the same question with reworded arguments otherwise burns
        # the whole budget re-computing an answer it already has.
        kept = calls[:MAX_CALLS_PER_ROUND]
        if len(calls) > len(kept):
            dropped = [c["name"] for c in calls[len(kept):]]
            yield em.log(f"dropped {len(dropped)} excess call(s) this round "
                         f"(cap {MAX_CALLS_PER_ROUND}): {dropped}", level="warning")
        assistant_calls = kept
        messages[-1]["tool_calls"] = [
            {"id": c["id"], "type": "function",
             "function": {"name": c["name"],
                          "arguments": json.dumps(c["arguments"], ensure_ascii=False)}}
            for c in assistant_calls
        ]
        # Keep the transcript consistent: every announced call needs a result.
        for c in calls[len(kept):]:
            messages.append({"role": "tool", "tool_call_id": c["id"],
                             "content": "skipped: per-round tool call limit reached"})

        for call in assistant_calls:
            name = call["name"]
            cap_id = reverse.get(name)
            if cap_id is None:
                yield em.log(f"model asked for unknown tool '{name}'", level="warning")
                messages.append({"role": "tool", "tool_call_id": call["id"],
                                 "content": f"error: unknown tool '{name}'"})
                continue

            args = call.get("arguments") or {}
            signature = f"{cap_id}:{json.dumps(args, sort_keys=True, ensure_ascii=False)}"

            if calls_used >= MAX_CALLS_TOTAL:
                messages.append({"role": "tool", "tool_call_id": call["id"],
                                 "content": ("skipped: total tool call budget reached. "
                                             "Answer with what you already have.")})
                yield em.log(f"total tool budget ({MAX_CALLS_TOTAL}) reached; "
                             f"skipping {cap_id}", level="warning")
                continue

            if signature in seen_calls:
                # Same tool, same arguments: hand back the earlier result rather
                # than paying for an identical call again.
                messages.append({"role": "tool", "tool_call_id": call["id"],
                                 "content": seen_calls[signature]})
                yield em.log(f"↺ {cap_id} repeated with identical arguments; "
                             f"reusing previous result", level="warning")
                continue

            # Hand the conversation's folder to the tool. This is how sh.run,
            # fs.patch and code.run learn which session they are working in —
            # without it every conversation shared one workbench, and one
            # conversation writing a script invalidated another's claims.
            tool_ctx = InvokeContext(
                session_id=ctx.session_id or conversation_id,
                cancelled=ctx.cancelled,
                options={"workspace": str(workspace_mod.workspace(conversation_id))})
            # The scheduling decision belongs to the model when the capability
            # is a minutes-long one, and the loop honours it here.
            if cap_id in LONG_RUNNING and args.pop("background", False):
                job = jobmod.MANAGER.submit(cap_id, args, registry, tool_ctx,
                                            label=cap_id)
                payload = json.dumps({
                    "job_id": job.id, "status": job.status,
                    "note": ("started in background; read with job.output, "
                             "stop with job.kill. Do not resubmit."),
                }, ensure_ascii=False)
                steps.append({"round": round_no, "capability": cap_id,
                              "arguments": args, "ok": True, "error": "",
                              "job_id": job.id, "ledger_id": None})
                messages.append({"role": "tool", "tool_call_id": call["id"],
                                 "content": payload})
                yield em.log(f"→ {cap_id} backgrounded as job {job.id}")
                continue

            yield em.log(f"→ {cap_id} {json.dumps(args, ensure_ascii=False)[:200]}")
            calls_used += 1

            try:
                result, error, _evs = await _execute_tool(
                    cap_id, args, registry, em, tool_ctx)
            except asyncio.TimeoutError:
                result, error = None, {"message": "tool timed out", "code": "timeout"}
            except Exception as e:  # noqa: BLE001
                result, error = None, {"message": f"{type(e).__name__}: {e}",
                                       "code": "tool_failed"}

            if error is not None:
                payload = f"error [{error.get('code')}]: {error.get('message')}"
                if error.get("code") == "invalid_params":
                    payload += (". Fix the arguments and retry once, or answer "
                                "without this tool.")
                yield em.log(f"← {cap_id} failed: {error.get('message')}",
                             level="warning")
            else:
                payload = json.dumps(result, ensure_ascii=False, default=str)
                if len(payload) > MAX_TOOL_RESULT_CHARS:
                    payload = payload[:MAX_TOOL_RESULT_CHARS] + "\n…(truncated)"
                # Prepend the triage view: what the engine settled, what it did
                # not settle, and why. The agent works the `undecided` part
                # instead of re-deriving the settled part — this is the
                # mechanism behind "the engine filters out a big round".
                view = triage.triage(cap_id, result)
                if view and (view.get("decided") or view.get("undecided")):
                    payload = triage.render(view) + "\n" + payload
                seen_calls[signature] = payload
                yield em.log(f"← {cap_id} ok ({len(payload)} chars)")

            steps.append({"round": round_no, "capability": cap_id,
                          "arguments": args, "ok": error is None,
                          "error": (error or {}).get("message", ""),
                          # Set when verify.gate recorded a ledger entry, so
                          # overclaim detection can tell an asserted completion
                          # from an evidenced one.
                          "ledger_id": (result or {}).get("recorded") if not error else None})
            messages.append({"role": "tool", "tool_call_id": call["id"],
                             "content": payload})

        elided = _trim_transcript(messages)
        if elided:
            yield em.log(f"transcript over {MAX_TRANSCRIPT_CHARS} chars; "
                         f"released {elided} older tool result(s)", level="debug")

    # Budget exhausted: ask for a final answer from what has been gathered.
    yield em.log(f"round budget ({max_rounds}) exhausted after "
                 f"{calls_used} tool call(s); forcing a summary",
                 level="warning")
    messages.append({"role": "user",
                     "content": "轮次用尽。请仅根据以上工具结果直接给出最终结论，不要再调用工具。"})
    try:
        loop = asyncio.get_running_loop()
        if kind == "cloud":
            final = await loop.run_in_executor(
                None, _cloud_tools, provider, model, messages, [], 120)
        else:
            final = await loop.run_in_executor(
                None, _ollama_tools, model, messages, [], 120)
        answer = final.get("content") or "(轮次用尽，无结论)"
    except Exception as e:  # noqa: BLE001
        answer = f"(轮次用尽且总结失败: {e})"

    agentstate.append_turn(conversation_id, "assistant", answer, steps=steps)
    leftover2 = inbox.INBOX.take_interjections(conversation_id)
    yield em.result({"answer": answer, "steps": steps, "rounds": max_rounds,
                     "conversation_id": conversation_id,
                     "undelivered": [n.to_dict() for n in leftover2],
                     "evidence": detect_overclaim(answer, steps),
                     "orchestrator": {"kind": kind, "provider": provider,
                                      "model": model},
                     "note": "round budget exhausted"})


async def investigate(params: dict, ctx: InvokeContext):
    """Drive an objective across several conversational rounds.

    `agent.chat` answers one question. This keeps a *goal* alive: an objective
    plus completion criteria, a round budget, and a continuation prompt between
    rounds that tells the next round to re-read the world rather than trust the
    previous round's narration.

    Two stopping rules beyond the round cap, both structural rather than
    exhortative:

    * the goal can only be marked complete through `goal.update`, which refuses
      unless the ledger holds a verified, non-stale claim;
    * an answer that asserts completion while no verification ever ran is not
      accepted — the round is re-issued with the gap named.
    """
    em = EventEmitter("agent.investigate")
    message = (params.get("message") or "").strip()
    if not message:
        raise CapabilityError("'message' is required", code="invalid_params")

    registry = params.get("_registry") or ctx.registry
    if registry is None:
        from ..registry import bootstrap
        registry = bootstrap()

    goal = agentstate.active_goal(ctx.session_id or "")
    if goal is None or params.get("replace_goal"):
        gid = agentstate.create_goal(agentstate.Goal(
            objective=params.get("objective") or message,
            criteria=params.get("criteria") or "",
            session_id=ctx.session_id or "",
            max_rounds=int(params.get("max_goal_rounds") or 6),
        ))
        goal = agentstate.get_goal(gid) or {}
        yield em.log(f"goal {gid} created: {goal.get('objective', '')[:80]}")

    gid = goal["id"]
    max_rounds = int(goal.get("max_rounds") or 6)
    history: list[dict] = list(params.get("history") or [])
    rounds: list[dict] = []
    pending = message
    stopped = "round-limit"

    # Goal rounds continue the same conversation, so the transcript accumulates
    # in one durable place instead of being handed back and forth with the
    # renderer each round.
    conversation_id = params.get("conversation_id") or ""
    if conversation_id and agentstate.get_conversation(conversation_id):
        pass
    else:
        latest = agentstate.latest_conversation()
        conversation_id = (latest or {}).get("id") or agentstate.create_conversation(
            title=message, session_id=ctx.session_id or "")
    if not history:
        history = agentstate.conversation_history(conversation_id)
    yield em.log(f"conversation {conversation_id}: "
                 f"{len(history)} turn(s) of context")

    for goal_round in range(int(goal.get("rounds_started") or 0) + 1,
                            max_rounds + 1):
        ctx.check_cancelled()
        yield em.progress(goal_round / max_rounds, goal_round=goal_round)
        agentstate.bump_round(gid, {"round": goal_round,
                                    "at": time.time(),
                                    "pending": pending[:200]})
        yield em.log(f"goal round {goal_round}/{max_rounds}")

        answer, steps, error = "", [], None
        async for ev in registry.invoke(
                "agent.chat",
                {"message": pending, "history": history,
                 "max_rounds": params.get("max_rounds"),
                 "backend": params.get("backend", "auto")},
                InvokeContext(session_id=ctx.session_id,
                              cancelled=ctx.cancelled)):
            if ev.type == "result":
                value = ev.data.get("value") or {}
                answer = value.get("answer") or ""
                steps = value.get("steps") or []
                evidence = value.get("evidence") or {}
            elif ev.type == "error":
                error = ev.data
            elif ev.type == "log":
                yield em.log(ev.data.get("message", ""),
                             ev.data.get("level", "info"))

        if error:
            stopped = "error"
            rounds.append({"round": goal_round, "error": error.get("message")})
            break

        evidence = detect_overclaim(answer, steps)
        rounds.append({"round": goal_round, "answer": answer,
                       "steps": [s["capability"] for s in steps],
                       "ledger_ids": [s["ledger_id"] for s in steps
                                      if s.get("ledger_id")],
                       "evidence": evidence})
        yield em.log(f"  round {goal_round}: {len(steps)} tool call(s), "
                     f"{evidence['gate_runs']} verification(s)")

        history.append({"role": "user", "content": pending})
        history.append({"role": "assistant", "content": answer})

        fresh = agentstate.get_goal(gid) or {}
        if fresh.get("phase") != "active" or fresh.get("activation") != "armed":
            stopped = f"goal-{fresh.get('phase')}"
            yield em.log(f"goal {fresh.get('phase')}; stopping")
            break

        stats = agentstate.ledger_stats(gid)
        if evidence["overclaim"]:
            # The measured failure this exists for: an agent that says it is
            # done while nothing verified it. Name the gap and re-issue the
            # round instead of accepting the answer.
            stopped = "overclaim-corrected"
            yield em.log("completion claimed with no verification executed; "
                         "re-issuing the round", level="warning")
            pending = (
                "你上一条回复声称完成了，但这一轮**没有任何验证被执行**"
                f"（verify.gate 调用 0 次，账本新增 0 条，当前已验证 "
                f"{stats['verified']} 条）。\n"
                "请立刻二选一：\n"
                "1. 用 verify.gate 真正验证（必须提供 negative_control，"
                "并让检查打印 {\"cases_total\":N,\"cases_passed\":M,"
                "\"failures\":[...]}），然后说明分母与失败清单；\n"
                "2. 如实说明哪些部分**没有**验证、为什么。\n"
                "不要重复上一条结论。")
            continue

        pending = render_goal_round_prompt(fresh, goal_round + 1)
        stopped = "awaiting-human" if goal_round >= max_rounds else "continue"

    final = agentstate.get_goal(gid) or {}
    yield em.result({
        "goal_id": gid,
        "goal_phase": final.get("phase"),
        "rounds": rounds,
        "stopped": stopped,
        "ledger": agentstate.ledger_stats(gid),
        "text": shaping.with_status(
            f"investigation {gid}: {len(rounds)} round(s), stopped={stopped}\n"
            f"verified claims: {agentstate.ledger_stats(gid)['verified']}",
            ok=stopped not in ("error",),
            detail=f"stopped={stopped}"),
    })


def render_goal_round_prompt(goal: dict, round_no: int) -> str:
    return GOAL_ROUND_PROMPT.format(
        objective=goal.get("objective", ""),
        criteria=goal.get("criteria") or "(none given)",
        round=round_no,
        max_rounds=goal.get("max_rounds", "?"),
    )


async def tools(params: dict, ctx: InvokeContext):
    """List the tools the agent would expose — for the UI and for debugging."""
    em = EventEmitter("agent.tools")
    registry = params.get("_registry") or ctx.registry
    if registry is None:
        from ..registry import bootstrap
        registry = bootstrap()
    schemas, reverse = build_tool_schemas(registry)
    kind, provider, model = _pick_orchestrator(params.get("backend", "auto"))
    yield em.result({
        "count": len(schemas),
        "excluded": sorted(AGENT_DENY),
        "orchestrator": {"kind": kind, "provider": provider, "model": model},
        "tools": [{"name": s["function"]["name"],
                   "capability": reverse[s["function"]["name"]],
                   "description": s["function"]["description"]}
                  for s in schemas],
    })


SPECS = (
    CapabilitySpec(
        id="agent.chat",
        kind="agent",
        name="对话式分析",
        description="自然语言入口：由模型自行决定调用哪些能力，多轮工具调用后给出结论",
        params=schema(
            {
                "message": string("用户说的话"),
                "history": {"type": "array", "items": {"type": "object"},
                            "description": "[{role, content}] 历史消息"},
                "backend": string("auto | cloud | local", default="auto"),
                "max_rounds": integer("最多工具轮次", default=6),
                "timeout": integer("单次模型调用超时秒数", default=180),
                "conversation_id": string("续接哪个会话；留空则自动续接最近一个"),
                "new_conversation": boolean("开一个新会话", default=False),
            },
            required=["message"],
        ),
        returns=schema({"answer": {"type": "string"}, "steps": {"type": "array"}}),
        streaming=True,
        cost=COST_CLOUD,
        sensitivity=SENS_INTERNAL,
        backend="providers.agent",
        tags=("agent", "chat", "tools"),
    ),
    CapabilitySpec(
        id="agent.investigate",
        kind="agent",
        name="长时程调查",
        description="带目标对象的调查：给一个目标与**完成判据**，它会跨多轮持续推进，"
                    "每轮之间用续轮提示要求「去查世界状态，不要信自己的叙述」。"
                    "声称完成但没有任何验证执行过时，会**驳回并重发该轮**。"
                    "目标只有在账本里有已验证且未失效的主张时才允许标记完成。",
        params=schema(
            {
                "message": string("第一轮要说的话"),
                "objective": string("调查目标（留空则用 message）"),
                "criteria": string("完成判据：怎么算做完了"),
                "history": {"type": "array", "items": {"type": "object"},
                            "description": "[{role, content}] 历史消息"},
                "backend": string("auto | cloud | local", default="auto"),
                "max_rounds": integer("单轮内最多工具轮次", default=6),
                "max_goal_rounds": integer("最多自动续轮", default=6),
                "replace_goal": boolean("丢弃当前目标重建", default=False),
            },
            required=["message"],
        ),
        returns=schema({"goal_id": {"type": "string"},
                        "rounds": {"type": "array"},
                        "ledger": {"type": "object"}}),
        streaming=True,
        cost=COST_CLOUD,
        sensitivity=SENS_INTERNAL,
        backend="providers.agent",
        tags=("agent", "goal", "long-horizon"),
    ),
    CapabilitySpec(
        id="agent.tools",
        kind="agent",
        name="Agent 可用工具",
        description="列出 agent 暴露给模型的工具（由能力注册表自动生成）",
        params=schema({"backend": string("auto | cloud | local", default="auto")}),
        returns=schema({"count": {"type": "integer"}}),
        cost=COST_CLOUD,
        sensitivity=SENS_INTERNAL,
        backend="providers.agent",
        tags=("agent", "introspection"),
    ),
)

HANDLERS = {"agent.chat": chat, "agent.investigate": investigate,
            "agent.tools": tools}


def register_all(registry) -> None:
    for spec in SPECS:
        registry.register(spec, HANDLERS[spec.id])
