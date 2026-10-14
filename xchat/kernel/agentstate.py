"""
Durable agent state: the investigation goal, the claim ledger, and the harness
fingerprint that makes claims expire.

Three things live here, and they are the reason a long investigation can survive
a context boundary at all:

**The goal** is an object, not a paragraph. It carries the objective, the
completion criteria (supplied by the human, per Codex's `/goal` which asks for
Outcome / Constraints / *Verification*), a phase, a round counter, and a budget.
Anthropic's long-running-agent writeup names the failure this prevents: a later
agent instance "would look around, see that progress had been made, and declare
the job done". xcore hit exactly that — it reported 已归档完成 while
`knowledge/` stayed at 115 files.

**The ledger** is a claim, not a score. Each entry records the statement, the
ground-truth denominator, the identity of the failures, the negative control
that proved the check can fail, and the harness digest it was verified against.
Recording `9649` and *which 18* rather than `98.1%` matters: 27.2–32.1% of agent
sessions lose the denominator entirely and then overclaim coverage in 80.4% of
those cases (arXiv:2609.20812).

**The harness fingerprint** is the mechanism that makes a fixed instrument
invalidate its own results. Every claim stores the digest of the workbench
scripts it was verified with. Fix `read_rva()` and the digest changes, so every
claim verified against the old instrument is marked stale and must be re-run.
That is the structural answer to the 18-failure episode, where the formula was
right and the ruler was wrong: nobody had to *remember* that the change mattered.

Storage is `state/agent.db`, a fresh SQLite file. It is deliberately not
`state/memory.db`: memory L1–L4 are semantic layers (what was learned), while
this is bookkeeping (what was attempted, asserted and verified). L4 episodes are
derived from the work; a claim is a commitment about correctness.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from ..config import STATE_DIR
from . import workspace

AGENT_DB = STATE_DIR / "agent.db"

_lock = threading.RLock()
_ready = False

_SCHEMA = """
CREATE TABLE IF NOT EXISTS goals (
    id            TEXT PRIMARY KEY,
    ts            REAL NOT NULL,
    updated       REAL NOT NULL,
    session_id    TEXT NOT NULL DEFAULT '',
    objective     TEXT NOT NULL,
    criteria      TEXT NOT NULL DEFAULT '',
    phase         TEXT NOT NULL DEFAULT 'active',
    activation    TEXT NOT NULL DEFAULT 'armed',
    rounds_started INTEGER NOT NULL DEFAULT 0,
    max_rounds    INTEGER NOT NULL DEFAULT 25,
    note          TEXT NOT NULL DEFAULT '',
    checkpoints   TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_goals_phase ON goals(phase);

CREATE TABLE IF NOT EXISTS claims (
    id             TEXT PRIMARY KEY,
    ts             REAL NOT NULL,
    updated        REAL NOT NULL,
    goal_id        TEXT NOT NULL DEFAULT '',
    statement      TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'unverified',
    cases_total    INTEGER,
    cases_passed   INTEGER,
    failures       TEXT NOT NULL DEFAULT '[]',
    negative_control   TEXT NOT NULL DEFAULT '',
    check_cmd      TEXT NOT NULL DEFAULT '',
    harness_digest TEXT NOT NULL DEFAULT '',
    scope          TEXT NOT NULL DEFAULT '',
    stale          INTEGER NOT NULL DEFAULT 0,
    evidence       TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_claims_goal   ON claims(goal_id);
CREATE INDEX IF NOT EXISTS idx_claims_status ON claims(status);
CREATE INDEX IF NOT EXISTS idx_claims_stale  ON claims(stale);

-- Conversations live here, not in the renderer.
--
-- The first version kept history in a JS array in the chat panel, so closing
-- the window lost the whole context and the next session began by
-- re-explaining everything — paying twice for the same understanding. A
-- conversation is durable state; the renderer is a view of it.
CREATE TABLE IF NOT EXISTS conversations (
    id         TEXT PRIMARY KEY,
    ts         REAL NOT NULL,
    updated    REAL NOT NULL,
    title      TEXT NOT NULL DEFAULT '',
    session_id TEXT NOT NULL DEFAULT '',
    goal_id    TEXT NOT NULL DEFAULT '',
    archived   INTEGER NOT NULL DEFAULT 0,
    turns      INTEGER NOT NULL DEFAULT 0,
    dir        TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_conv_updated ON conversations(archived, updated);

"""


def _connect() -> sqlite3.Connection:
    global _ready
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(AGENT_DB, timeout=15)
    conn.row_factory = sqlite3.Row
    if not _ready:
        conn.executescript(_SCHEMA)
        conn.commit()
        _ready = True
    return conn


def integrity_check() -> str:
    with _lock:
        conn = _connect()
        try:
            return conn.execute("PRAGMA integrity_check").fetchone()[0]
        finally:
            conn.close()


# ── harness fingerprint ─────────────────────────────────────────────────────

def harness_digest(conversation_id: str = "") -> str:
    """Digest of *this conversation's* scripts.

    Was global, over one shared workbench — which meant a script written in one
    conversation marked every other conversation's verified claims stale. A
    claim is scoped to the instrument that measured it, and the instrument
    belongs to one investigation, so the digest is scoped the same way.
    """
    return workspace.harness_digest(conversation_id)


def revalidate() -> dict:
    """Mark claims stale when the harness *of their own conversation* changed.

    Scoped per conversation. The previous global version made one
    investigation's script edit invalidate another investigation's results,
    which is not a conservative default — it is a wrong answer, and one that
    trains people to ignore the stale flag.
    """
    rows = [r for r in _claims_raw()
            if r["status"] == "verified" and not r["stale"]]
    by_scope: dict[str, list[dict]] = {}
    for r in rows:
        by_scope.setdefault(r.get("scope") or "", []).append(r)

    current: dict[str, str] = {}
    stale_ids: list[str] = []
    for scope, group in by_scope.items():
        digest = workspace.harness_digest(scope)
        current[scope] = digest
        for r in group:
            if r["harness_digest"] and r["harness_digest"] != digest:
                stale_ids.append(r["id"])

    if stale_ids:
        with _lock:
            conn = _connect()
            try:
                for cid in stale_ids:
                    conn.execute(
                        "UPDATE claims SET stale=1, status='stale', updated=? "
                        "WHERE id=?", (time.time(), cid))
                conn.commit()
            finally:
                conn.close()
    return {"digests": current, "newly_stale": stale_ids}


# ── goals ───────────────────────────────────────────────────────────────────

@dataclass
class Goal:
    objective: str
    criteria: str = ""
    session_id: str = ""
    max_rounds: int = 25
    phase: str = "active"          # active | paused | blocked | complete
    activation: str = "armed"      # armed | disarmed
    note: str = ""
    id: str = ""
    rounds_started: int = 0
    checkpoints: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "objective": self.objective, "criteria": self.criteria,
            "phase": self.phase, "activation": self.activation,
            "rounds_started": self.rounds_started, "max_rounds": self.max_rounds,
            "note": self.note, "checkpoints": self.checkpoints[-8:],
        }


def create_goal(goal: Goal) -> str:
    gid = goal.id or uuid.uuid4().hex[:12]
    now = time.time()
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                "INSERT INTO goals (id, ts, updated, session_id, objective, "
                "criteria, phase, activation, rounds_started, max_rounds, note, "
                "checkpoints) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (gid, now, now, goal.session_id, goal.objective, goal.criteria,
                 goal.phase, goal.activation, goal.rounds_started,
                 goal.max_rounds, goal.note, json.dumps(goal.checkpoints,
                                                        ensure_ascii=False)))
            conn.commit()
            return gid
        finally:
            conn.close()


def active_goal(session_id: str = "") -> dict | None:
    """The newest active goal for a session (or globally when session is '')."""
    with _lock:
        conn = _connect()
        try:
            if session_id:
                row = conn.execute(
                    "SELECT * FROM goals WHERE phase='active' AND session_id=? "
                    "ORDER BY updated DESC LIMIT 1", (session_id,)).fetchone()
            else:
                row = conn.execute(
                    "SELECT * FROM goals WHERE phase='active' "
                    "ORDER BY updated DESC LIMIT 1").fetchone()
            return dict(row) if row else None
        finally:
            conn.close()


def get_goal(goal_id: str) -> dict | None:
    with _lock:
        conn = _connect()
        try:
            row = conn.execute("SELECT * FROM goals WHERE id=?",
                               (goal_id,)).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()


def update_goal(goal_id: str, **fields) -> bool:
    allowed = {"phase", "activation", "rounds_started", "note", "criteria",
               "checkpoints"}
    sets = {k: v for k, v in fields.items() if k in allowed}
    if not sets:
        return False
    if "checkpoints" in sets:
        sets["checkpoints"] = json.dumps(sets["checkpoints"], ensure_ascii=False)
    cols = ", ".join(f"{k}=?" for k in sets)
    with _lock:
        conn = _connect()
        try:
            cur = conn.execute(
                f"UPDATE goals SET {cols}, updated=? WHERE id=?",
                (*sets.values(), time.time(), goal_id))
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()


def bump_round(goal_id: str, checkpoint: dict | None = None) -> int:
    """Increment the round counter, recording a checkpoint. Returns the new count."""
    with _lock:
        conn = _connect()
        try:
            row = conn.execute("SELECT rounds_started, checkpoints FROM goals "
                               "WHERE id=?", (goal_id,)).fetchone()
            if row is None:
                return 0
            rounds = int(row["rounds_started"]) + 1
            marks = json.loads(row["checkpoints"] or "[]")
            if checkpoint:
                # Cap the log: a checkpoint is a breadcrumb, not a transcript.
                marks = (marks + [checkpoint])[-40:]
            conn.execute(
                "UPDATE goals SET rounds_started=?, checkpoints=?, updated=? "
                "WHERE id=?",
                (rounds, json.dumps(marks, ensure_ascii=False), time.time(),
                 goal_id))
            conn.commit()
            return rounds
        finally:
            conn.close()


def list_goals(limit: int = 20) -> list[dict]:
    with _lock:
        conn = _connect()
        try:
            return [dict(r) for r in conn.execute(
                "SELECT * FROM goals ORDER BY updated DESC LIMIT ?", (limit,))]
        finally:
            conn.close()


# ── claims ──────────────────────────────────────────────────────────────────

def record_claim(statement: str, *, goal_id: str = "", status: str = "unverified",
                 cases_total: int | None = None,
                 cases_passed: int | None = None,
                 failures: list | None = None,
                 negative_control: str = "", check_cmd: str = "",
                 digest: str | None = None, scope: str = "",
                 evidence: dict | None = None) -> dict:
    """Insert a claim. A `verified` claim without a negative control is refused.

    The refusal lives here rather than only in the capability so that no future
    caller can route around it: a claim whose check was never shown to be
    capable of failing is not evidence, and the ledger is worthless if it
    accepts one.
    """
    if status == "verified" and not negative_control:
        raise ValueError(
            "a claim cannot be recorded as verified without a negative control: "
            "nothing has shown the check can fail")
    if (cases_total is not None and cases_passed is not None
            and cases_passed > cases_total):
        raise ValueError("cases_passed exceeds cases_total")

    cid = uuid.uuid4().hex[:12]
    now = time.time()
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                "INSERT INTO claims (id, ts, updated, goal_id, statement, status,"
                " cases_total, cases_passed, failures, negative_control, check_cmd,"
                " harness_digest, scope, stale, evidence)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,0,?)",
                (cid, now, now, goal_id, statement, status, cases_total,
                 cases_passed, json.dumps(failures or [], ensure_ascii=False),
                 negative_control, check_cmd,
                 digest if digest is not None else harness_digest(scope),
                 scope, json.dumps(evidence or {}, ensure_ascii=False)))
            conn.commit()
        finally:
            conn.close()
    return {"id": cid, "statement": statement, "status": status,
            "cases_total": cases_total, "cases_passed": cases_passed,
            "failures": failures or [], "stale": False}


def _claims_raw(goal_id: str = "", include_stale: bool = True) -> list[dict]:
    """Read claims without triggering revalidation.

    `revalidate()` needs to read the ledger to decide what to invalidate, so it
    must use this one; going through `claims()` made the two call each other
    until the stack ran out.
    """
    with _lock:
        conn = _connect()
        try:
            sql = "SELECT * FROM claims"
            args: tuple = ()
            where = []
            if goal_id:
                where.append("goal_id=?")
                args += (goal_id,)
            if not include_stale:
                where.append("stale=0")
            if where:
                sql += " WHERE " + " AND ".join(where)
            sql += " ORDER BY ts"
            out = []
            for r in conn.execute(sql, args):
                d = dict(r)
                d["failures"] = json.loads(d["failures"] or "[]")
                d["evidence"] = json.loads(d["evidence"] or "{}")
                out.append(d)
            return out
        finally:
            conn.close()


def claims(goal_id: str = "", include_stale: bool = True) -> list[dict]:
    revalidate()
    return _claims_raw(goal_id, include_stale)


def ledger_stats(goal_id: str = "") -> dict:
    """Counts plus the honest denominators, which is what a summary must carry."""
    reval = revalidate()
    rows = claims(goal_id)
    verified = [c for c in rows if c["status"] == "verified" and not c["stale"]]
    with_denom = [c for c in verified if c["cases_total"] is not None]
    return {
        "total": len(rows),
        "verified": len(verified),
        "stale": sum(1 for c in rows if c["stale"]),
        "unverified": sum(1 for c in rows if c["status"] == "unverified"),
        "refuted": sum(1 for c in rows if c["status"] == "refuted"),
        # A claim with no denominator cannot be audited; surface the count
        # rather than letting "verified" imply measurable coverage.
        "verified_without_denominator": len(verified) - len(with_denom),
        "total_failures_recorded": sum(len(c["failures"]) for c in verified),
        "harness_digest": reval["digests"],
        "newly_stale": reval["newly_stale"],
    }


# ── conversations ───────────────────────────────────────────────────────────
#
# A conversation owns a folder (see `kernel.workspace`) and its turns live in
# that folder's `transcript.jsonl` — the durable record. The database row is an
# *index over* the folder, not the owner of the content: it makes "list my
# sessions" and "which claims went stale" cheap, while the transcript stays
# greppable and recoverable by hand.


def create_conversation(title: str = "", session_id: str = "",
                        goal_id: str = "") -> str:
    cid = uuid.uuid4().hex[:12]
    now = time.time()
    folder = workspace.workspace(cid)
    workspace.write_meta(cid, {
        "title": (title or "")[:120], "created": now,
        "session_id": session_id, "goal_id": goal_id,
    })
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                "INSERT INTO conversations (id, ts, updated, title, session_id,"
                " goal_id, archived, turns, dir) VALUES (?,?,?,?,?,?,0,0,?)",
                (cid, now, now, (title or "")[:120], session_id, goal_id,
                 str(folder)))
            conn.commit()
            return cid
        finally:
            conn.close()


def latest_conversation(include_archived: bool = False) -> dict | None:
    with _lock:
        conn = _connect()
        try:
            sql = "SELECT * FROM conversations"
            if not include_archived:
                sql += " WHERE archived=0"
            sql += " ORDER BY updated DESC LIMIT 1"
            row = conn.execute(sql).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()


def get_conversation(conversation_id: str) -> dict | None:
    with _lock:
        conn = _connect()
        try:
            row = conn.execute("SELECT * FROM conversations WHERE id=?",
                               (conversation_id,)).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()


def list_conversations(limit: int = 30) -> list[dict]:
    with _lock:
        conn = _connect()
        try:
            rows = [dict(r) for r in conn.execute(
                "SELECT id, ts, updated, title, turns, archived, goal_id, dir "
                "FROM conversations ORDER BY updated DESC LIMIT ?", (limit,))]
        finally:
            conn.close()
    for r in rows:
        r["workspace"] = workspace.summary(r["id"])
    return rows


def append_turn(conversation_id: str, role: str, content: str,
                steps: list | None = None, meta: dict | None = None) -> dict:
    """Append one turn to the transcript. The first user turn also names it.

    A session that is never named is unfindable in a list of sessions, so the
    title is derived from the first user message rather than left blank.

    The user turn is written *before* the model call (write-ahead: a crash
    mid-turn leaves a record of what was being attempted rather than silence).
    The cost of that ordering is a duplicate when a failed call is retried, so
    an immediately repeated identical user turn is collapsed.
    """
    existing = workspace.read_turns(conversation_id)
    if role == "user" and existing:
        last = existing[-1]
        if last.get("role") == "user" and last.get("content") == content[:20000]:
            return {"id": "", "seq": 0, "role": role, "deduped": True}

    turn = {
        "id": uuid.uuid4().hex[:12],
        "seq": len(existing) + 1,
        "ts": time.time(),
        "role": role,
        "content": content[:20000],
        # Tool calls are kept for the UI and for auditing but are deliberately
        # NOT replayed into the model's context: the outputs are large, they are
        # re-derivable by running the tool again, and re-billing them every turn
        # is the waste this design exists to avoid. Durable *conclusions* live
        # in the ledger and the goal, which are replayed.
        "steps": steps or [],
        "meta": meta or {},
    }
    workspace.append_turn(conversation_id, turn)

    with _lock:
        conn = _connect()
        try:
            row = conn.execute("SELECT title FROM conversations WHERE id=?",
                               (conversation_id,)).fetchone()
            title = ""
            if row is not None and not row["title"] and role == "user":
                title = " ".join(content.split())[:60]
                workspace.write_meta(conversation_id, {"title": title})
            conn.execute(
                "UPDATE conversations SET updated=?, turns=turns+1"
                + (", title=?" if title else "") + " WHERE id=?",
                ((time.time(), title, conversation_id) if title
                 else (time.time(), conversation_id)))
            conn.commit()
        finally:
            conn.close()
    return {"id": turn["id"], "seq": turn["seq"], "role": role}


def conversation_history(conversation_id: str,
                         limit: int = workspace.REPLAY_TURNS) -> list[dict]:
    """The most recent `limit` turns, text only, bounded per turn."""
    return workspace.replay(conversation_id, limit=limit)


def conversation_turns(conversation_id: str, limit: int = 200) -> list[dict]:
    """Full turns including tool steps — for the UI, not for the model."""
    return workspace.read_turns(conversation_id, limit=limit)


def archive_conversation(conversation_id: str, archived: bool = True) -> bool:
    with _lock:
        conn = _connect()
        try:
            cur = conn.execute(
                "UPDATE conversations SET archived=?, updated=? WHERE id=?",
                (1 if archived else 0, time.time(), conversation_id))
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()


def shaping_text(text: str, budget: int) -> str:
    """Head+tail clip whose marker is charged against the budget.

    Kept local rather than importing the kernel's output module from a storage
    layer (that would invert the dependency). The marker must count against the
    budget: an earlier version appended it on top, so every clipped turn came
    out slightly over the cap and the aggregate replay budget leaked.
    """
    if len(text) <= budget:
        return text
    marker = f"\n…[{len(text)} chars total, middle elided]…\n"
    room = budget - len(marker)
    if room <= 0:
        return marker
    head = room // 2
    tail = room - head
    return text[:head] + marker + text[len(text) - tail:]
