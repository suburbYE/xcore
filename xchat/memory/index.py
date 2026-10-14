"""
Indexer: builds the L3 semantic layer from L1 (knowledge) and L2 (cases).

Strictly read-only with respect to those stores. It reads them, derives a text
representation worth embedding, and writes vectors into `state/memory.db`.

Indexing is incremental: a vector whose `text_hash` is unchanged is skipped, so
re-running after adding one case costs one embedding call, not 137.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from ..config import BASE_DIR
from . import store
from .embed import Embedder, EmbedError, pack

KNOWLEDGE_DIR = BASE_DIR / "knowledge"
CASES_DB = BASE_DIR / "tools" / "cases.db"

# One embedding call per N texts. Kept modest so a 429 mid-run loses little
# work — and because Gemini's free tier rejects large bursts outright.
BATCH_SIZE = 12


@dataclass
class IndexReport:
    source: str
    scanned: int = 0
    skipped: int = 0
    embedded: int = 0
    removed: int = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "source": self.source, "scanned": self.scanned,
            "skipped": self.skipped, "embedded": self.embedded,
            "removed": self.removed, "errors": self.errors[:5],
        }


# ── text derivation ─────────────────────────────────────────────────────────
# The embedded text is what retrieval matches against, so it must read like
# something a person would search for: algorithm names, parameters, evidence.

def knowledge_text(entry: dict) -> str:
    """Flatten a knowledge entry's history into searchable prose."""
    parts: list[str] = []
    for h in entry.get("_history", []) or []:
        if h.get("summary"):
            parts.append(str(h["summary"]))
        for a in h.get("algorithms", []) or []:
            if isinstance(a, dict):
                name = a.get("name") or ""
                lib = a.get("library") or ""
                params = a.get("parameters") or {}
                ev = a.get("evidence") or ""
                bit = " ".join(x for x in (name, lib) if x)
                if params:
                    bit += " " + json.dumps(params, ensure_ascii=False)
                if ev:
                    bit += " " + str(ev)[:200]
                if bit.strip():
                    parts.append(bit.strip())
    if not parts:
        # Older entries predate the `_history` wrapper and keep their analysis at
        # the top level. Reading only `_history` made those entries return "",
        # which the indexer treats as "nothing to embed" — so a fully analysed
        # sample sat in L1 completely invisible to semantic recall while every
        # count still looked right.
        for key in ("algorithm", "description", "summary",
                    "inference_reason", "source"):
            val = entry.get(key)
            if val:
                parts.append(str(val))
        for fp in entry.get("false_positives", []) or []:
            parts.append(str(fp))
    return " | ".join(parts)[:4000]


def case_text(row: sqlite3.Row | dict) -> str:
    """Flatten a case row into searchable prose."""
    bits = []
    for key in ("llm_algorithms", "rules_hits", "notes"):
        try:
            val = row[key]
        except (KeyError, IndexError):
            continue
        if not val:
            continue
        if isinstance(val, str):
            try:
                parsed = json.loads(val)
                bits.append(json.dumps(parsed, ensure_ascii=False))
            except json.JSONDecodeError:
                bits.append(val)
        else:
            bits.append(json.dumps(val, ensure_ascii=False))
    return " | ".join(bits)[:4000]


# ── indexers ────────────────────────────────────────────────────────────────

def _embed_and_store(source: str, items: list[tuple[str, str]],
                     embedder: Embedder, report: IndexReport) -> None:
    """items: [(ref, text)] — embeds in batches and stores."""
    if not items:
        return
    for i in range(0, len(items), BATCH_SIZE):
        chunk = items[i:i + BATCH_SIZE]
        try:
            vecs = embedder.embed_batch([t for _, t in chunk])
        except EmbedError as e:
            report.errors.append(f"batch {i//BATCH_SIZE}: {e}")
            continue
        recs = []
        for (ref, text), vec in zip(chunk, vecs):
            if not vec:
                continue
            recs.append(store.VectorRecord(
                source=source, ref=ref, model=embedder.model,
                dim=len(vec), vec=pack(vec), text=text,
            ))
        report.embedded += store.upsert_vectors(recs)


def index_knowledge(embedder: Embedder, force: bool = False) -> IndexReport:
    rep = IndexReport(source="knowledge")
    if not KNOWLEDGE_DIR.exists():
        rep.errors.append(f"knowledge dir missing: {KNOWLEDGE_DIR}")
        return rep

    known = {} if force else store.existing_refs("knowledge", embedder.model)
    todo: list[tuple[str, str]] = []
    seen_refs: set[str] = set()

    for path in sorted(KNOWLEDGE_DIR.glob("*.json")):
        rep.scanned += 1
        try:
            entry = json.loads(path.read_text(encoding="utf-8"))
        except Exception as e:
            rep.errors.append(f"{path.name}: {type(e).__name__}")
            continue
        # Lowercased: one legacy entry stores its digest in uppercase, which
        # would make the ref differ from every lowercase caller (L1 lookup and
        # recall hydration both build the name from a lowercase hexdigest) and
        # only match on a case-insensitive filesystem.
        ref = str(entry.get("sha256") or path.stem).lower()
        seen_refs.add(ref)
        text = knowledge_text(entry)
        if not text.strip():
            rep.skipped += 1
            continue
        if known.get(ref) == store.text_digest(text):
            rep.skipped += 1
            continue
        todo.append((ref, text))

    _embed_and_store("knowledge", todo, embedder, rep)

    stale = [ref for ref in known if ref not in seen_refs]
    rep.removed = store.delete_vectors("knowledge", stale)
    return rep


def index_cases(embedder: Embedder, force: bool = False) -> IndexReport:
    rep = IndexReport(source="case")
    if not CASES_DB.exists():
        rep.errors.append(f"cases db missing: {CASES_DB}")
        return rep

    # Read-only connection: the indexer must never be able to write L2.
    try:
        conn = sqlite3.connect(f"file:{CASES_DB}?mode=ro", uri=True)
    except Exception as e:
        rep.errors.append(f"cannot open cases db: {e}")
        return rep

    known = {} if force else store.existing_refs("case", embedder.model)
    todo: list[tuple[str, str]] = []
    seen_refs: set[str] = set()
    try:
        conn.row_factory = sqlite3.Row
        for row in conn.execute("SELECT * FROM cases"):
            rep.scanned += 1
            ref = str(row["id"])
            seen_refs.add(ref)
            text = case_text(row)
            if not text.strip():
                rep.skipped += 1
                continue
            if known.get(ref) == store.text_digest(text):
                rep.skipped += 1
                continue
            todo.append((ref, text))
    except Exception as e:
        rep.errors.append(f"read failed: {e}")
    finally:
        conn.close()

    _embed_and_store("case", todo, embedder, rep)
    stale = [ref for ref in known if ref not in seen_refs]
    rep.removed = store.delete_vectors("case", stale)
    return rep


def index_episodes(embedder: Embedder, limit: int = 200) -> IndexReport:
    rep = IndexReport(source="episode")
    pending = store.unindexed_episodes(limit)
    rep.scanned = len(pending)
    if not pending:
        return rep

    todo = [(e["id"], e["content"][:4000]) for e in pending if e["content"].strip()]
    rep.skipped = len(pending) - len(todo)
    _embed_and_store("episode", todo, embedder, rep)

    # Only mark indexed the ones we actually stored, so a failed batch retries.
    stored = {v["ref"] for v in store.all_vectors(source="episode",
                                                  model=embedder.model)}
    done = [eid for eid, _ in todo if eid in stored]
    store.mark_indexed(done)
    return rep


def index_all(embedder: Embedder, force: bool = False,
              include_episodes: bool = True) -> dict:
    reports = [index_knowledge(embedder, force), index_cases(embedder, force)]
    if include_episodes:
        reports.append(index_episodes(embedder))
    return {
        "embedder": embedder.info().__dict__,
        "reports": [r.to_dict() for r in reports],
        "totals": {
            "scanned": sum(r.scanned for r in reports),
            "embedded": sum(r.embedded for r in reports),
            "skipped": sum(r.skipped for r in reports),
            "removed": sum(r.removed for r in reports),
            "errors": sum(len(r.errors) for r in reports),
        },
        "store": store.health(),
    }
