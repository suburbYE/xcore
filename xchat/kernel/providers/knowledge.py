"""
Capability provider: knowledge ingestion (L1).

Why this exists
---------------
`xchat/case_learner.py` could always write the knowledge base, but it was never
registered as a capability — so the agent could not reach it. Asked to
"store this sample in the knowledge base", the agent ran a scan, wrote an L4
episode via `memory.record`, and reported **"archived"**. The knowledge base did
not gain a single entry.

That failure mode is worse than an outright error: an error tells you nothing
happened, whereas a false success leaves you believing the sample is searchable
when it is not. Exposing the real operation is the fix.

Two things this provider does that a naive wrapper would not:

* **Indexes what it stores.** Writing L1 without updating L3 leaves the new
  entry invisible to `memory.recall` until someone remembers to re-index — which
  is the same "it says it worked but retrieval misses it" problem in a different
  costume.
* **Reports exactly what happened.** The result distinguishes "stored", "rejected
  by the noise guard", and "nothing to learn from", because those are very
  different outcomes that a single boolean would flatten.
"""

from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path

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
    string,
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


async def _scan_hits(registry, path: str, ctx: InvokeContext) -> dict:
    """Reuse the engine's rule scan for the hits the learner needs."""
    hits: list[dict] = []
    async for ev in registry.invoke("engine.scan",
                                    {"file": path, "brief": True}, ctx):
        if ev.type == "result":
            payload = ev.data.get("value") or {}
            hits = payload.get("hits") or []
    return {"hits": hits}


async def _native_hits(registry, path: str, ctx: InvokeContext) -> dict:
    """L1-L5 native scan, used when the rule engine finds nothing.

    The learner's evidence gate only understood L1 rule hits, so a sample whose
    only evidence is CFG-level (e.g. a ChaCha20 quarter-round pattern with no
    string/constant signature) could not be ingested at all — even though the
    scanner had found something real. This synthesises the same shape from the
    native result so that evidence reaches the learner.
    """
    result: dict = {}
    async for ev in registry.invoke("engine.native_scan", {"so": path}, ctx):
        if ev.type == "result":
            result = ev.data.get("value") or {}
    if not result:
        return {"hits": []}

    algos = []
    if result.get("algorithm") and result["algorithm"] != "unknown":
        algos.append(result["algorithm"])
    for name, layer in (result.get("layers") or {}).items():
        for h in layer.get("hits") or []:
            if isinstance(h, dict):
                label = h.get("constant") or h.get("symbol") or h.get("fingerprint")
                if label:
                    algos.append(label)
            elif isinstance(h, str):
                algos.append(h)

    score = float(result.get("final_score") or 0.0)
    # Only treat it as evidence if the scanner actually concluded something;
    # a `clean` verdict with score 0 is not evidence worth learning from.
    if not algos or (score <= 0 and result.get("verdict") == "clean"):
        return {"hits": []}

    seen, uniq = set(), []
    for a in algos:
        if a not in seen:
            seen.add(a)
            uniq.append(a)
    return {"hits": [{
        "algos": uniq,
        "sim": score,
        "source": "native_scan",
        "note": f"verdict={result.get('verdict')} arch={result.get('arch')}",
    }]}


async def _evidence(registry, path: str, ctx: InvocationContext, em) -> tuple[dict, str]:
    """Rule hits first, native L1-L5 scan as fallback. Returns (hits, source)."""
    scan = await _scan_hits(registry, path, ctx)
    if scan.get("hits"):
        return scan, "rule_scan"
    em_note = "rule engine found nothing; falling back to L1-L5 native scan"
    native = await _native_hits(registry, path, ctx)
    if native.get("hits"):
        return native, "native_scan"
    return {"hits": []}, "none"


async def learn(params: dict, ctx: InvokeContext):
    em = EventEmitter("knowledge.learn")
    target = params.get("file")
    if not target:
        raise CapabilityError("'file' is required", code="invalid_params")
    p = Path(target)
    if not p.is_file():
        raise CapabilityError(f"file not found: {target}", code="not_found")

    registry = params.get("_registry") or ctx.registry
    if registry is None:
        from ..registry import bootstrap
        registry = bootstrap()

    data = p.read_bytes()
    digest = _sha256(data)
    yield em.log(f"{p.name}  {len(data)} bytes  sha256={digest[:16]}…")

    # The learner's own guard: tiny files make the local model hallucinate.
    from ...case_learner import CaseLearner
    if len(data) < CaseLearner.MIN_LEARN_SIZE:
        yield em.result({
            "stored": False, "reason": "too_small",
            "detail": (f"{len(data)} bytes < MIN_LEARN_SIZE "
                       f"({CaseLearner.MIN_LEARN_SIZE}); skipped to avoid "
                       f"LLM hallucination on near-empty input"),
            "sha256": digest,
        })
        return

    if params.get("scan_first", True):
        yield em.log("gathering evidence (rule scan → L1-L5 native scan)…")
        try:
            scan, source = await _evidence(registry, str(p), ctx, em)
            if source == "native_scan":
                yield em.log("rule engine found nothing; using L1-L5 native evidence",
                             level="warning")
        except Exception as e:  # noqa: BLE001
            scan, source = {"hits": []}, "none"
            yield em.log(f"evidence gathering failed: {e}", level="warning")
    else:
        scan, source = {"hits": []}, "none"

    if not scan.get("hits"):
        yield em.result({
            "stored": False, "reason": "no_evidence",
            "detail": ("neither the rule engine nor the L1-L5 native scanner "
                       "produced anything; the learner needs evidence and "
                       "nothing was written"),
            "sha256": digest,
            "hint": "try engine.native_scan directly to see the raw layer scores",
        })
        return

    yield em.log(f"evidence from {source}: "
                 f"{scan['hits'][0].get('algos', [])[:6]}; running deep analysis…")
    from ...llm_router import LLMRouter
    learner = CaseLearner(LLMRouter())

    loop = asyncio.get_running_loop()
    before = _knowledge_count()
    try:
        analysis = await learner.learn(p.name, data, digest, scan)
    except Exception as e:  # noqa: BLE001
        yield em.error(f"analysis failed: {type(e).__name__}: {e}",
                       code="analysis_failed")
        return
    after = _knowledge_count()

    if analysis is None:
        yield em.result({
            "stored": False, "reason": "analysis_empty",
            "detail": "the model returned nothing usable; knowledge base unchanged",
            "sha256": digest,
        })
        return

    stored = after > before or _knowledge_has(digest)
    if not stored:
        # save() silently declines records matching the hallucination pattern.
        yield em.result({
            "stored": False, "reason": "rejected_by_noise_guard",
            "detail": ("every block reported one algorithm at conf>0.9, which is "
                       "the local-model hallucination signature — rejected"),
            "sha256": digest, "analysis": analysis,
        })
        return

    yield em.log(f"stored to knowledge/{digest[:16]}.json")

    indexed = 0
    if params.get("index", True):
        # Store and index together: an unindexed entry is invisible to recall,
        # which reproduces the original "it said it worked" problem.
        yield em.log("indexing into L3 so it is immediately searchable…")
        try:
            from ...memory.embed import get_embedder
            from ...memory import index as indexer
            emb = get_embedder(params.get("embedding_provider", "gemini"),
                               dim=int(params.get("dim") or 768),
                               min_interval=float(params.get("min_interval", 4.0)))
            rep = await loop.run_in_executor(None, indexer.index_knowledge, emb)
            indexed = rep.embedded
            for err in rep.errors[:2]:
                yield em.log(f"indexing: {err}", level="warning")
        except Exception as e:  # noqa: BLE001
            # Storage succeeded; failing to index is not a storage failure.
            yield em.log(f"stored but not indexed ({e}); run memory.index later",
                         level="warning")

    yield em.result({
        "stored": True,
        "sha256": digest,
        "knowledge_file": f"knowledge/{digest[:16]}.json",
        "knowledge_count": after,
        "indexed_vectors": indexed,
        "searchable": indexed > 0,
        "analysis": analysis,
    })


async def stats(params: dict, ctx: InvokeContext):
    em = EventEmitter("knowledge.stats")
    from ...case_learner import CaseLearner
    from ...llm_router import LLMRouter
    learner = CaseLearner(LLMRouter())
    yield em.result(learner.stats())


def _knowledge_count() -> int:
    from ...config import KNOWLEDGE_DIR
    if not KNOWLEDGE_DIR.exists():
        return 0
    return len(list(KNOWLEDGE_DIR.glob("*.json")))


def _knowledge_has(digest: str) -> bool:
    from ...config import KNOWLEDGE_DIR
    return (KNOWLEDGE_DIR / f"{digest[:16]}.json").exists()


SPECS = (
    CapabilitySpec(
        id="knowledge.learn",
        kind="knowledge",
        name="样本入库（L1 知识库）",
        description="分析样本并写入知识库（knowledge/），随后立即建立语义索引使其可被检索。"
                    "这是「把数据吃进去」真正对应的操作 —— 与 memory.record（只记情节）不同",
        params=schema(
            {
                "file": string("待入库的样本路径"),
                "scan_first": boolean("先跑规则扫描作为证据", default=True),
                "index": boolean("入库后立即索引到 L3", default=True),
                "embedding_provider": string("gemini | local", default="gemini"),
                "dim": integer("向量维度", default=768),
                "min_interval": {"type": "number", "description": "嵌入调用最小间隔秒"},
            },
            required=["file"],
        ),
        returns=schema({
            "stored": {"type": "boolean"},
            "sha256": {"type": "string"},
            "searchable": {"type": "boolean"},
        }),
        streaming=True,
        cost=COST_CLOUD,
        sensitivity=SENS_INTERNAL,
        backend="providers.knowledge",
        tags=("knowledge", "ingest", "learn"),
    ),
    CapabilitySpec(
        id="knowledge.stats",
        kind="knowledge",
        name="知识库统计",
        description="L1 知识库条目数与算法分布",
        params=schema({}),
        returns=schema({"total": {"type": "integer"}}),
        cost=COST_CLOUD,
        sensitivity=SENS_INTERNAL,
        backend="providers.knowledge",
        tags=("knowledge", "stats"),
    ),
)

HANDLERS = {"knowledge.learn": learn, "knowledge.stats": stats}


def register_all(registry) -> None:
    for spec in SPECS:
        registry.register(spec, HANDLERS[spec.id])
