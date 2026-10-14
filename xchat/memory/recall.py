"""
Recall: unified retrieval across the four memory layers.

    L1 exact    — knowledge/<sha256[:16]>.json   (hit by file hash)
    L2 fuzzy    — tools/cases.db            (Jaccard over algorithm signature)
    L3 semantic — state/memory.db vectors   (this module)
    L4 episodic — state/memory.db episodes  (what happened, in order)

L1/L2 lookups live in `xchat.case_learner` / the engine; this module adds L3
and L4 and presents all four behind one call so callers do not have to know
which layer would answer them.

Ranking note: Gemini embeddings sit around 0.48 cosine even for unrelated text,
so an absolute cutoff would either admit everything or nothing. Results are
ranked and the score is reported instead of being thresholded on a magic number.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from ..config import BASE_DIR
from . import store
from .embed import Embedder, EmbedError, cosine, unpack

KNOWLEDGE_DIR = BASE_DIR / "knowledge"


@dataclass
class Hit:
    source: str          # knowledge | case | episode
    ref: str
    score: float
    text: str
    detail: dict = field(default_factory=dict)
    # Other refs that carry identical text and were collapsed into this hit.
    also_from: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = {"source": self.source, "ref": self.ref,
             "score": round(self.score, 4), "text": self.text[:600],
             "detail": self.detail}
        if self.also_from:
            d["also_from"] = self.also_from
        return d


def semantic(query: str, embedder: Embedder, *, limit: int = 8,
             sources: list[str] | None = None,
             min_score: float = 0.0, dedupe: bool = True) -> list[Hit]:
    """Rank stored vectors by cosine similarity to `query`."""
    if not query.strip():
        return []
    try:
        qvec = embedder.embed(query)
    except EmbedError as e:
        raise EmbedError(f"query embedding failed: {e}") from None

    rows = store.all_vectors(model=embedder.model)
    if sources:
        rows = [r for r in rows if r["source"] in sources]

    scored: list[Hit] = []
    for r in rows:
        if r["dim"] != len(qvec):
            # A vector from a different dimension belongs to another model's
            # index; comparing would be meaningless.
            continue
        s = cosine(qvec, unpack(r["vec"]))
        if s < min_score:
            continue
        scored.append(Hit(source=r["source"], ref=r["ref"], score=s,
                          text=r["text"]))
    scored.sort(key=lambda h: -h.score)

    if not dedupe:
        return scored[:limit]

    # Collapse identical texts. The same content legitimately exists under
    # several refs — an episode replayed in a later session, or two knowledge
    # entries sharing a summary — and without this they would each consume a
    # result slot at the same score, crowding out genuinely different hits.
    merged: list[Hit] = []
    by_text: dict[str, Hit] = {}
    for h in scored:
        key = store.text_digest(h.text.strip())
        first = by_text.get(key)
        if first is not None:
            first.also_from.append(h.ref)
            continue
        by_text[key] = h
        merged.append(h)
        if len(merged) >= limit:
            break
    return merged


def hydrate(hits: list[Hit]) -> list[Hit]:
    """Attach the original record so callers get structured data, not just text."""
    for h in hits:
        try:
            if h.source == "knowledge":
                # L1 files are named by the SHORT digest — case_learner.save()
                # and knowledge._knowledge_has() both use sha256[:16]. The
                # indexer stores the FULL digest as the vector ref (index.py
                # falls back to path.stem when the field is absent), so slicing
                # to 16 is what makes this resolve for both. Using h.ref whole
                # meant every knowledge lookup missed, silently, because the
                # except below swallows the miss.
                p = KNOWLEDGE_DIR / f"{h.ref[:16]}.json"
                if p.exists():
                    h.detail = json.loads(p.read_text(encoding="utf-8"))
            elif h.source == "case":
                import sqlite3
                conn = sqlite3.connect(
                    f"file:{BASE_DIR / 'tools' / 'cases.db'}?mode=ro", uri=True)
                try:
                    conn.row_factory = sqlite3.Row
                    row = conn.execute("SELECT * FROM cases WHERE id=?",
                                       (h.ref,)).fetchone()
                    if row:
                        h.detail = dict(row)
                finally:
                    conn.close()
            elif h.source == "episode":
                for ep in store.episodes(limit=500):
                    if ep["id"] == h.ref:
                        h.detail = ep
                        break
        except Exception:
            # Hydration is best-effort: a missing original must not sink recall.
            pass
    return hits


def recall(query: str, embedder: Embedder, *, limit: int = 8,
           sources: list[str] | None = None, hydrate_results: bool = False,
           min_score: float = 0.0) -> dict:
    """One call across the semantic and episodic layers."""
    hits = semantic(query, embedder, limit=limit, sources=sources,
                    min_score=min_score)
    if hydrate_results:
        hydrate(hits)
    top = hits[0].score if hits else 0.0
    return {
        "query": query,
        "count": len(hits),
        "top_score": round(top, 4),
        "hits": [h.to_dict() for h in hits],
        "note": ("分数是相对值：该嵌入模型对任意文本都有约 0.5 的基线相似度，"
                 "请横向比较命中之间的高低，不要套用固定阈值"),
    }


def recent(session_id: str | None = None, limit: int = 20) -> list[dict]:
    """L4: the episodic tail, newest first."""
    return store.episodes(session_id=session_id, limit=limit)
