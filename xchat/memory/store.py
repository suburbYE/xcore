"""
Memory store (L3 semantic + L4 episodic).

Design rule, stated once and enforced everywhere: **this database is derived.**
It never writes to `knowledge/` (L1) or `tools/cases.db` (L2). Everything here
can be deleted and rebuilt from those two, which is what makes it safe to add
schema changes and re-index freely.

Splitting the layers this way also means a corrupt or half-built index can never
damage the assets the project cannot regenerate.
"""

from __future__ import annotations

import hashlib
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..config import STATE_DIR

MEMORY_DB = STATE_DIR / "memory.db"

SCHEMA_VERSION = 1

_lock = threading.RLock()
# Reentrant on purpose: helpers here legitimately nest (health() calls
# schema_version() while already holding the lock). A plain Lock deadlocks on
# that — and did, hanging the first indexing run with no output.
_ready = False

_SCHEMA = f"""
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- L3: semantic index over L1 knowledge entries, L2 cases, and episodes.
-- `source` + `ref` identify where the text came from so a hit can be hydrated
-- from the original store rather than duplicated here.
CREATE TABLE IF NOT EXISTS vectors (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    source     TEXT NOT NULL,            -- knowledge | case | episode
    ref        TEXT NOT NULL,            -- sha256 / case id / episode id
    model      TEXT NOT NULL,            -- embedder that produced the vector
    dim        INTEGER NOT NULL,
    vec        BLOB NOT NULL,
    text_hash  TEXT NOT NULL,            -- sha256 of the embedded text
    text       TEXT NOT NULL DEFAULT '', -- kept for re-embedding & display
    ts         REAL NOT NULL,
    UNIQUE(source, ref, model)
);
CREATE INDEX IF NOT EXISTS idx_vectors_source ON vectors(source);
CREATE INDEX IF NOT EXISTS idx_vectors_model  ON vectors(model);

-- L4: episodic memory — what was asked, what was concluded.
CREATE TABLE IF NOT EXISTS episodes (
    id          TEXT PRIMARY KEY,
    session_id  TEXT NOT NULL DEFAULT '',
    ts          REAL NOT NULL,
    kind        TEXT NOT NULL DEFAULT 'turn',  -- turn | result | note
    role        TEXT NOT NULL DEFAULT 'user',  -- user | assistant | system
    content     TEXT NOT NULL,
    meta        TEXT NOT NULL DEFAULT '{{}}',
    indexed     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_episodes_ts      ON episodes(ts);
CREATE INDEX IF NOT EXISTS idx_episodes_session ON episodes(session_id);
CREATE INDEX IF NOT EXISTS idx_episodes_indexed ON episodes(indexed);
"""


def _connect() -> sqlite3.Connection:
    global _ready
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(MEMORY_DB, timeout=15)
    conn.row_factory = sqlite3.Row
    if not _ready:
        conn.executescript(_SCHEMA)
        cur = conn.execute("SELECT value FROM meta WHERE key='schema_version'")
        row = cur.fetchone()
        if row is None:
            conn.execute("INSERT INTO meta(key,value) VALUES('schema_version',?)",
                         (str(SCHEMA_VERSION),))
        conn.commit()
        _ready = True
    return conn


def schema_version() -> int:
    with _lock:
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT value FROM meta WHERE key='schema_version'").fetchone()
            return int(row["value"]) if row else 0
        finally:
            conn.close()


def health() -> dict:
    """Counts per layer. Used by the GUI and by the integrity check."""
    try:
        with _lock:
            conn = _connect()
            try:
                by_source = {r["source"]: r["count"] for r in conn.execute(
                    "SELECT source, COUNT(*) AS count FROM vectors GROUP BY source")}
                models = [dict(r) for r in conn.execute(
                    "SELECT model, dim, COUNT(*) AS count FROM vectors"
                    " GROUP BY model, dim")]
                ep = conn.execute("SELECT COUNT(*) AS c FROM episodes").fetchone()["c"]
                unindexed = conn.execute(
                    "SELECT COUNT(*) AS c FROM episodes WHERE indexed=0").fetchone()["c"]
                size = MEMORY_DB.stat().st_size if MEMORY_DB.exists() else 0
                return {
                    "ok": True,
                    "schema_version": schema_version(),
                    "path": str(MEMORY_DB),
                    "bytes": size,
                    "vectors": sum(by_source.values()),
                    "by_source": by_source,
                    "models": models,
                    "episodes": ep,
                    "episodes_unindexed": unindexed,
                }
            finally:
                conn.close()
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def integrity_check() -> str:
    try:
        with _lock:
            conn = _connect()
            try:
                return conn.execute("PRAGMA integrity_check").fetchone()[0]
            finally:
                conn.close()
    except Exception as e:
        return f"ERROR {e}"


def text_digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ── vectors ─────────────────────────────────────────────────────────────────

@dataclass
class VectorRecord:
    source: str
    ref: str
    model: str
    dim: int
    vec: bytes
    text: str
    ts: float = 0.0

    @property
    def text_hash(self) -> str:
        return text_digest(self.text)


def upsert_vectors(records: list[VectorRecord]) -> int:
    """Insert or replace vectors. Returns the number written."""
    if not records:
        return 0
    with _lock:
        conn = _connect()
        try:
            conn.executemany(
                "INSERT INTO vectors (source, ref, model, dim, vec, text_hash,"
                " text, ts) VALUES (?,?,?,?,?,?,?,?)"
                " ON CONFLICT(source, ref, model) DO UPDATE SET"
                "   dim=excluded.dim, vec=excluded.vec, text_hash=excluded.text_hash,"
                "   text=excluded.text, ts=excluded.ts",
                [(r.source, r.ref, r.model, r.dim, r.vec, r.text_hash, r.text,
                  r.ts or time.time()) for r in records],
            )
            conn.commit()
            return len(records)
        finally:
            conn.close()


def all_vectors(source: str | None = None, model: str | None = None):
    with _lock:
        conn = _connect()
        try:
            sql = "SELECT * FROM vectors"
            clauses, params = [], []
            if source:
                clauses.append("source=?"); params.append(source)
            if model:
                clauses.append("model=?"); params.append(model)
            if clauses:
                sql += " WHERE " + " AND ".join(clauses)
            return [dict(r) for r in conn.execute(sql, params)]
        finally:
            conn.close()


def existing_refs(source: str, model: str) -> dict[str, str]:
    """ref -> text_hash, so indexing can skip unchanged entries."""
    with _lock:
        conn = _connect()
        try:
            return {r["ref"]: r["text_hash"] for r in conn.execute(
                "SELECT ref, text_hash FROM vectors WHERE source=? AND model=?",
                (source, model))}
        finally:
            conn.close()


def delete_vectors(source: str, refs: list[str]) -> int:
    if not refs:
        return 0
    with _lock:
        conn = _connect()
        try:
            marks = ",".join("?" * len(refs))
            cur = conn.execute(
                f"DELETE FROM vectors WHERE source=? AND ref IN ({marks})",
                (source, *refs))
            conn.commit()
            return cur.rowcount
        finally:
            conn.close()


# ── episodes (L4) ───────────────────────────────────────────────────────────

@dataclass
class Episode:
    content: str
    session_id: str = ""
    kind: str = "turn"
    role: str = "user"
    meta: dict = field(default_factory=dict)
    id: str = ""
    ts: float = 0.0

    def resolved_id(self) -> str:
        if self.id:
            return self.id
        raw = f"{self.session_id}|{self.ts or time.time()}|{self.content[:200]}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def add_episode(ep: Episode) -> str:
    import json
    eid = ep.resolved_id()
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                "INSERT OR REPLACE INTO episodes"
                " (id, session_id, ts, kind, role, content, meta, indexed)"
                " VALUES (?,?,?,?,?,?,?,0)",
                (eid, ep.session_id, ep.ts or time.time(), ep.kind, ep.role,
                 ep.content, json.dumps(ep.meta, ensure_ascii=False)),
            )
            conn.commit()
            return eid
        finally:
            conn.close()


def find_episode(content: str) -> str | None:
    """Id of an existing episode with byte-identical content, if any.

    Recall already collapses identical texts when reading, but storing them
    repeatedly still grows the table the index is built from — and every
    indexed row is a candidate for a future context window. Deduplicating at
    write time keeps the store from accumulating the same turn over and over.
    """
    with _lock:
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT id FROM episodes WHERE content=? LIMIT 1",
                (content,)).fetchone()
            return row["id"] if row else None
        finally:
            conn.close()


def count_episodes(session_id: str | None = None) -> int:
    with _lock:
        conn = _connect()
        try:
            if session_id:
                row = conn.execute(
                    "SELECT COUNT(*) AS n FROM episodes WHERE session_id=?",
                    (session_id,)).fetchone()
            else:
                row = conn.execute("SELECT COUNT(*) AS n FROM episodes").fetchone()
            return int(row["n"])
        finally:
            conn.close()


def unindexed_episodes(limit: int = 200) -> list[dict]:
    with _lock:
        conn = _connect()
        try:
            return [dict(r) for r in conn.execute(
                "SELECT * FROM episodes WHERE indexed=0 ORDER BY ts LIMIT ?",
                (limit,))]
        finally:
            conn.close()


def mark_indexed(ids: list[str]) -> int:
    if not ids:
        return 0
    with _lock:
        conn = _connect()
        try:
            marks = ",".join("?" * len(ids))
            cur = conn.execute(
                f"UPDATE episodes SET indexed=1 WHERE id IN ({marks})", ids)
            conn.commit()
            return cur.rowcount
        finally:
            conn.close()


def episodes(session_id: str | None = None, limit: int = 50) -> list[dict]:
    with _lock:
        conn = _connect()
        try:
            if session_id:
                rows = conn.execute(
                    "SELECT * FROM episodes WHERE session_id=? ORDER BY ts DESC LIMIT ?",
                    (session_id, limit))
            else:
                rows = conn.execute(
                    "SELECT * FROM episodes ORDER BY ts DESC LIMIT ?", (limit,))
            return [dict(r) for r in rows]
        finally:
            conn.close()
