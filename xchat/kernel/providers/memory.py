"""
Capability provider: memory (L3 semantic + L4 episodic).

Exposes the memory layer through the same contract as everything else, so the
GUI, the CLI and the LLM router all reach it identically.

Two invariants worth stating, because they are what make this safe to expose:

* L1 (`knowledge/`) and L2 (`tools/cases.db`) are **read-only** here. The only
  thing written is `state/memory.db`, which is derived and rebuildable.
* Embedding text leaves for a cloud model, so it is sanitised on the way out —
  case summaries embed real target paths.
"""

from __future__ import annotations

from ..contract import (
    COST_CLOUD,
    COST_LOCAL,
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
from ...memory import index as indexer
from ...memory import recall as recaller
from ...memory import store
from ...memory.embed import EmbedError, get_embedder

DEFAULT_EMBEDDER = "gemini"
DEFAULT_DIM = 768
# Gemini's free tier rate-limits embedding; spacing calls keeps a full index
# from tripping 429 and losing the tail of the run.
DEFAULT_MIN_INTERVAL = 4.0

# ── write budget ────────────────────────────────────────────────────────────
#
# Everything stored here is retrieved from later, and retrieval output is fed
# back into a model's context. So a store that grows without bound is a token
# bill that grows without bound — the growth is invisible at write time and
# only shows up as an expensive conversation weeks later. The guards below
# make the writer pay attention instead.
MIN_EPISODE_CHARS = 12       # "ok" / "好的" are not memories
MAX_EPISODE_CHARS = 4000     # one episode; longer is truncated, visibly
MAX_EPISODES_PER_SESSION = 400
# Total characters of hit text returned by one recall. Per-hit text was already
# capped at 600 (recall.Hit.to_dict); that still allows 8 hits x 600 = 4800
# chars into a single tool message, per call, per round.
MAX_RECALL_CHARS = 3200


def _embedder(params: dict):
    provider = params.get("embedding_provider", DEFAULT_EMBEDDER)
    kw = {"dim": int(params.get("dim") or DEFAULT_DIM)}
    if provider == "gemini":
        kw.update(min_interval=float(params.get("min_interval", DEFAULT_MIN_INTERVAL)),
                  max_retries=int(params.get("max_retries", 6)))
    try:
        return get_embedder(provider, **kw)
    except EmbedError as e:
        raise CapabilityError(str(e), code="embedder_unavailable") from None


# ── memory.recall ───────────────────────────────────────────────────────────

async def recall(params: dict, ctx: InvokeContext):
    em = EventEmitter("memory.recall")
    query = (params.get("query") or "").strip()
    if not query:
        raise CapabilityError("'query' is required", code="invalid_params")

    emb = _embedder(params)
    yield em.log(f"embedding query with {emb.model} (dim={emb.dim})")

    try:
        result = await _run_blocking(recaller.recall, query, emb,
                                     limit=int(params.get("limit") or 8),
                                     sources=params.get("sources"),
                                     hydrate_results=bool(params.get("hydrate")),
                                     min_score=float(params.get("min_score") or 0.0))
    except EmbedError as e:
        yield em.error(str(e), code="embed_failed")
        return

    for h in result["hits"]:
        yield em.log(f"  {h['score']:.4f} [{h['source']}] {h['text'][:70]}",
                     level="debug")

    # Token budget. `limit` bounds how many hits come back, but not how much
    # text they carry, and this payload is pasted into the model's next prompt.
    # Cutting the ranking off by total characters keeps one recall from eating
    # a whole round's context.
    budget = int(params.get("max_chars") or MAX_RECALL_CHARS)
    matched = result["count"]
    kept: list[dict] = []
    used = 0
    for h in result["hits"]:
        cost = len(h.get("text") or "")
        if kept and used + cost > budget:
            break
        kept.append(h)
        used += cost
    if len(kept) < matched:
        yield em.log(f"recall budget {budget} chars reached; kept "
                     f"{len(kept)}/{matched} hits (低分的被截断，不是没有命中)",
                     level="warning")
    result["hits"] = kept
    result["count"] = len(kept)
    result["matched"] = matched
    result["chars"] = used
    yield em.result(result)


# ── memory.record ───────────────────────────────────────────────────────────

async def record(params: dict, ctx: InvokeContext):
    em = EventEmitter("memory.record")
    content = (params.get("content") or "").strip()
    if not content:
        raise CapabilityError("'content' is required", code="invalid_params")

    if len(content) < MIN_EPISODE_CHARS:
        raise CapabilityError(
            f"content is {len(content)} chars; minimum is {MIN_EPISODE_CHARS}. "
            "A fragment this short carries no retrievable information — record "
            "a sentence that would still make sense when read back alone.",
            code="too_short")

    truncated_from = 0
    if len(content) > MAX_EPISODE_CHARS:
        truncated_from = len(content)
        content = content[:MAX_EPISODE_CHARS]
        yield em.log(
            f"content {truncated_from} chars > MAX_EPISODE_CHARS "
            f"({MAX_EPISODE_CHARS}); stored the head only. Store a summary "
            f"instead of a transcript.", level="warning")

    # Session attribution falls back to the invocation context: the agent calls
    # this without knowing the session id, and episodes written under "" are
    # both unattributable and exempt from the per-session cap above.
    session_id = params.get("session_id") or ctx.session_id or ""

    # Same text, already stored: return the existing id instead of adding a
    # row that will score identically in every future recall.
    existing = await _run_blocking(store.find_episode, content)
    if existing:
        yield em.log(f"identical episode {existing} already stored; not duplicated")
        yield em.result({"id": existing, "indexed": True, "deduped": True,
                         "truncated_from": truncated_from,
                         "store": store.health()})
        return

    if session_id:
        used = await _run_blocking(store.count_episodes, session_id)
        if used >= MAX_EPISODES_PER_SESSION:
            raise CapabilityError(
                f"session '{session_id}' already holds {used} episodes "
                f"(cap {MAX_EPISODES_PER_SESSION}). Consolidate with "
                "knowledge.learn, or record under a new session_id.",
                code="memory_full")

    ep = store.Episode(
        content=content,
        session_id=session_id,
        kind=params.get("kind", "turn"),
        role=params.get("role", "assistant"),
        meta=params.get("meta") or {},
    )
    eid = store.add_episode(ep)
    yield em.log(f"episode {eid} recorded ({len(content)} chars)")

    indexed = False
    if params.get("index", True):
        emb = _embedder(params)
        try:
            rep = await _run_blocking(indexer.index_episodes, emb)
            indexed = rep.embedded > 0
            for err in rep.errors:
                yield em.log(f"indexing: {err}", level="warning")
        except EmbedError as e:
            # Recording succeeded; failing to index it is not a failure of the
            # record. The episode stays `indexed=0` and the next run picks it up.
            yield em.log(f"not indexed yet: {e}", level="warning")

    yield em.result({"id": eid, "indexed": indexed,
                     "truncated_from": truncated_from,
                     "store": store.health()})


# ── memory.index ────────────────────────────────────────────────────────────

async def build_index(params: dict, ctx: InvokeContext):
    em = EventEmitter("memory.index")
    emb = _embedder(params)
    yield em.log(f"embedder {emb.model} dim={emb.dim}")
    yield em.progress(0.05, phase="reading L1/L2")

    try:
        rep = await _run_blocking(
            indexer.index_all, emb,
            force=bool(params.get("force")),
            include_episodes=bool(params.get("include_episodes", True)))
    except EmbedError as e:
        yield em.error(str(e), code="embed_failed")
        return

    for r in rep["reports"]:
        yield em.log(
            f"{r['source']:<10} scanned={r['scanned']} embedded={r['embedded']} "
            f"skipped={r['skipped']} removed={r['removed']} errors={len(r['errors'])}")
        for e in r["errors"][:3]:
            yield em.log(f"   {e}", level="warning")

    yield em.result(rep)


# ── memory.stats ────────────────────────────────────────────────────────────

async def stats(params: dict, ctx: InvokeContext):
    em = EventEmitter("memory.stats")
    h = store.health()
    h["integrity"] = store.integrity_check()
    if params.get("recent"):
        h["recent"] = recaller.recent(session_id=params.get("session_id"),
                                      limit=int(params.get("recent")))
    yield em.result(h)


# ── memory.rebuild ──────────────────────────────────────────────────────────

async def rebuild(params: dict, ctx: InvokeContext):
    """Drop the derived index and rebuild it.

    Safe by construction: nothing here is authoritative. L1 and L2 are the
    sources of truth and are never modified.
    """
    em = EventEmitter("memory.rebuild")
    if not params.get("confirm"):
        yield em.error(
            "rebuild deletes the derived index; pass confirm=true to proceed",
            code="confirmation_required",
            note="L1 knowledge/ and L2 cases.db are NOT touched")
        return

    emb = _embedder(params)
    try:
        removed = await _run_blocking(_wipe_vectors)
        yield em.log(f"cleared {removed} vectors")
        rep = await _run_blocking(indexer.index_all, emb, True,
                                  bool(params.get("include_episodes", True)))
    except EmbedError as e:
        yield em.error(str(e), code="embed_failed")
        return
    yield em.result({"cleared": removed, **rep})


def _wipe_vectors() -> int:
    import sqlite3
    with store._lock:
        conn = store._connect()
        try:
            cur = conn.execute("DELETE FROM vectors")
            conn.execute("UPDATE episodes SET indexed=0")
            conn.commit()
            return cur.rowcount
        finally:
            conn.close()


async def _run_blocking(fn, *args, **kw):
    """Embedding calls are synchronous HTTP; keep the event loop free."""
    import asyncio
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, lambda: fn(*args, **kw))


# ── registration ────────────────────────────────────────────────────────────

SPECS = (
    CapabilitySpec(
        id="memory.recall",
        kind="memory",
        name="记忆检索",
        description="跨层检索：L1 精确 / L2 模糊 / L3 语义 / L4 情节。分数是相对的，"
                    "该嵌入模型基线偏高，请横向比较而非套用固定阈值",
        params=schema(
            {
                "query": string("检索文本"),
                "limit": integer("返回条数", default=8),
                "sources": {"type": "array", "items": {"type": "string"},
                            "description": "限定来源：knowledge / case / episode"},
                "hydrate": boolean("附带结构化原始记录", default=False),
                "min_score": {"type": "number", "description": "分数下限（谨慎使用）"},
                "max_chars": integer("返回正文总字符上限", default=MAX_RECALL_CHARS),
                "embedding_provider": string("gemini | local", default="gemini"),
                "dim": integer("向量维度", default=768),
            },
            required=["query"],
        ),
        returns=schema({"hits": {"type": "array"}, "top_score": {"type": "number"}}),
        streaming=True,
        cost=COST_CLOUD,
        sensitivity=SENS_INTERNAL,
        backend="providers.memory",
        tags=("memory", "recall", "semantic"),
    ),
    CapabilitySpec(
        id="memory.record",
        kind="memory",
        name="记忆写入",
        description="记录一条情节记忆（L4），并立即索引进 L3。有写入预算："
                    f"正文短于 {MIN_EPISODE_CHARS} 字符会被拒绝，超过 "
                    f"{MAX_EPISODE_CHARS} 字符只存开头，内容完全相同的条目不会重复写入，"
                    f"单会话上限 {MAX_EPISODES_PER_SESSION} 条。请存摘要而非逐字记录",
        params=schema(
            {
                "content": string("记忆正文"),
                "session_id": string("会话标识"),
                "kind": string("turn | result | note", default="turn"),
                "role": string("user | assistant | system", default="assistant"),
                "meta": {"type": "object"},
                "index": boolean("立即建立向量索引", default=True),
                "embedding_provider": string("gemini | local", default="gemini"),
                "dim": integer("向量维度", default=768),
            },
            required=["content"],
        ),
        returns=schema({"id": {"type": "string"}, "indexed": {"type": "boolean"}}),
        streaming=True,
        cost=COST_CLOUD,
        sensitivity=SENS_INTERNAL,
        backend="providers.memory",
        tags=("memory", "write"),
    ),
    CapabilitySpec(
        id="memory.index",
        kind="memory",
        name="建立语义索引",
        description="从 L1(knowledge) 与 L2(cases.db) 增量构建 L3。两者均为只读",
        params=schema(
            {
                "force": boolean("忽略 text_hash 全量重嵌", default=False),
                "include_episodes": boolean("同时索引未入索引的情节", default=True),
            },
        ),
        returns=schema({"totals": {"type": "object"}}),
        streaming=True,
        cost=COST_CLOUD,
        sensitivity=SENS_INTERNAL,
        backend="providers.memory",
        tags=("memory", "index"),
    ),
    CapabilitySpec(
        id="memory.stats",
        kind="memory",
        name="记忆库状态",
        description="各层条目数、向量模型、数据库完整性与体积",
        params=schema({"recent": integer("附带最近 N 条情节", default=0),
                       "session_id": string("限定会话")}),
        returns=schema({"vectors": {"type": "integer"}}),
        cost=COST_LOCAL,
        sensitivity=SENS_INTERNAL,
        backend="providers.memory",
        tags=("memory", "stats"),
    ),
    CapabilitySpec(
        id="memory.rebuild",
        kind="memory",
        name="重建语义索引",
        description="清空并重建 L3。L1/L2 不受影响，索引本身可随时重建",
        # `confirm` is deliberately NOT in `required`: declaring it required
        # makes the registry's generic pre-flight check answer with a bare
        # "missing required parameter", which buries the far more useful
        # explanation the handler gives (what gets deleted, what does not).
        params=schema(
            {
                "confirm": boolean("必须显式确认（默认 false，缺省即拒绝）",
                                   default=False),
                "include_episodes": boolean("一并重建情节索引", default=True),
            },
        ),
        returns=schema({"cleared": {"type": "integer"}}),
        streaming=True,
        cost=COST_CLOUD,
        sensitivity=SENS_INTERNAL,
        backend="providers.memory",
        tags=("memory", "rebuild", "destructive"),
    ),
)

HANDLERS = {
    "memory.recall": recall,
    "memory.record": record,
    "memory.index": build_index,
    "memory.stats": stats,
    "memory.rebuild": rebuild,
}


def register_all(registry) -> None:
    for spec in SPECS:
        registry.register(spec, HANDLERS[spec.id])
