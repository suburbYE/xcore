"""
Usage ledger: durable record of every LLM call, with cost accounting.

This is the data source the scheduler and the GUI both read: the scheduler needs
observed latency to route by speed, and the GUI needs spend per provider/model/day.

SQLite (stdlib) because the project already ships sqlite3 and the write volume is
trivial. Writes are best-effort: a ledger failure must never break an inference
call, so every entry point swallows its own errors.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from dataclasses import dataclass

from ..config import STATE_DIR, USAGE_DB

_lock = threading.Lock()
_initialised = False

_SCHEMA = """
CREATE TABLE IF NOT EXISTS calls (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    ts                REAL    NOT NULL,
    provider          TEXT    NOT NULL,
    model             TEXT    NOT NULL,
    requested_model   TEXT    NOT NULL DEFAULT '',
    kind              TEXT    NOT NULL DEFAULT 'chat',
    prompt_tokens     INTEGER NOT NULL DEFAULT 0,
    completion_tokens INTEGER NOT NULL DEFAULT 0,
    reasoning_tokens  INTEGER NOT NULL DEFAULT 0,
    cost_usd          REAL    NOT NULL DEFAULT 0,
    latency_ms        INTEGER NOT NULL DEFAULT 0,
    ok                INTEGER NOT NULL DEFAULT 1,
    error             TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_calls_ts       ON calls(ts);
CREATE INDEX IF NOT EXISTS idx_calls_provider ON calls(provider, model);
"""


def _migrate(conn: sqlite3.Connection) -> None:
    """Add columns introduced after the first schema revision.

    `model` must hold the model the provider ACTUALLY ran: DeepSeek silently
    maps legacy aliases (deepseek-chat / deepseek-reasoner) onto deepseek-flash,
    so billing by the requested name would be wrong.
    """
    have = {r[1] for r in conn.execute("PRAGMA table_info(calls)")}
    for col, decl in (("requested_model", "TEXT NOT NULL DEFAULT ''"),
                      ("reasoning_tokens", "INTEGER NOT NULL DEFAULT 0")):
        if col not in have:
            conn.execute(f"ALTER TABLE calls ADD COLUMN {col} {decl}")
    conn.commit()


def _connect() -> sqlite3.Connection:
    global _initialised
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(USAGE_DB, timeout=10)
    if not _initialised:
        conn.executescript(_SCHEMA)
        _migrate(conn)
        _initialised = True
    return conn


@dataclass
class UsageRecord:
    provider: str
    model: str                       # the model the provider ACTUALLY ran
    requested_model: str = ""        # what we asked for (may be a legacy alias)
    kind: str = "chat"
    prompt_tokens: int = 0
    completion_tokens: int = 0
    reasoning_tokens: int = 0
    cost_usd: float = 0.0
    latency_ms: int = 0
    ok: bool = True
    error: str = ""
    ts: float = 0.0


def record(rec: UsageRecord) -> bool:
    """Append one call. Returns False on failure (never raises)."""
    try:
        with _lock:
            conn = _connect()
            try:
                conn.execute(
                    "INSERT INTO calls (ts, provider, model, requested_model, kind,"
                    " prompt_tokens, completion_tokens, reasoning_tokens, cost_usd,"
                    " latency_ms, ok, error) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (rec.ts or time.time(), rec.provider, rec.model,
                     rec.requested_model or rec.model, rec.kind,
                     rec.prompt_tokens, rec.completion_tokens, rec.reasoning_tokens,
                     rec.cost_usd, rec.latency_ms, 1 if rec.ok else 0, rec.error[:500]),
                )
                conn.commit()
                return True
            finally:
                conn.close()
    except Exception:
        return False


def _rows(sql: str, params: tuple = ()) -> list[sqlite3.Row]:
    try:
        with _lock:
            conn = _connect()
            try:
                conn.row_factory = sqlite3.Row
                return conn.execute(sql, params).fetchall()
            finally:
                conn.close()
    except Exception:
        return []


def summary(since_ts: float = 0.0) -> dict:
    """Totals grouped by provider+model, plus a grand total."""
    rows = _rows(
        "SELECT provider, model, COUNT(*) AS calls,"
        " SUM(prompt_tokens) AS pt, SUM(completion_tokens) AS ct,"
        " SUM(cost_usd) AS cost,"
        " SUM(CASE WHEN ok=0 THEN 1 ELSE 0 END) AS failures,"
        " AVG(CASE WHEN ok=1 THEN latency_ms END) AS avg_latency"
        " FROM calls WHERE ts >= ? GROUP BY provider, model"
        " ORDER BY cost DESC",
        (since_ts,),
    )
    by_model = []
    total_cost = 0.0
    total_calls = 0
    for r in rows:
        d = dict(r)
        d["cost"] = round(d["cost"] or 0.0, 6)
        d["avg_latency"] = round(d["avg_latency"] or 0.0, 1)
        by_model.append(d)
        total_cost += d["cost"]
        total_calls += d["calls"]
    return {
        "since": since_ts,
        "total_calls": total_calls,
        "total_cost_usd": round(total_cost, 6),
        "by_model": by_model,
    }


def latency_stats(provider: str, model: str, limit: int = 50) -> dict:
    """Recent observed latency for one model — the scheduler's speed signal."""
    rows = _rows(
        "SELECT latency_ms FROM calls WHERE provider=? AND model=? AND ok=1"
        " ORDER BY ts DESC LIMIT ?",
        (provider, model, limit),
    )
    vals = [r["latency_ms"] for r in rows if r["latency_ms"]]
    if not vals:
        return {"samples": 0, "avg_ms": 0, "p50_ms": 0, "p95_ms": 0}
    vals.sort()
    n = len(vals)
    return {
        "samples": n,
        "avg_ms": int(sum(vals) / n),
        "p50_ms": vals[n // 2],
        "p95_ms": vals[min(n - 1, int(n * 0.95))],
    }


def recent(limit: int = 50) -> list[dict]:
    return [dict(r) for r in _rows(
        "SELECT ts, provider, model, kind, prompt_tokens, completion_tokens,"
        " cost_usd, latency_ms, ok, error FROM calls ORDER BY ts DESC LIMIT ?",
        (limit,),
    )]


def daily(days: int = 14) -> list[dict]:
    since = time.time() - days * 86400
    return [dict(r) for r in _rows(
        "SELECT date(ts, 'unixepoch', 'localtime') AS day, provider,"
        " COUNT(*) AS calls, SUM(cost_usd) AS cost,"
        " SUM(prompt_tokens + completion_tokens) AS tokens"
        " FROM calls WHERE ts >= ? GROUP BY day, provider ORDER BY day DESC",
        (since,),
    )]
