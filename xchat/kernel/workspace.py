"""
Workspace: one folder per conversation.

Why a folder and not just rows in a database. A conversation about reversing a
binary is a *working context*: it accumulates scripts, sweep dumps, logs and
reports, and those are files whether or not anyone admits it. Keeping them in a
single global `workbench/` produced a bug that is worth stating plainly, because
it is the reason this module exists:

    Two conversations shared one harness directory. The harness fingerprint —
    the digest that invalidates claims when the *instrument* changes — hashed
    that shared directory. So writing a script in conversation B marked every
    claim in conversation A stale. Demonstrated: A records a verified claim
    (stale=0), B writes one unrelated script, A's claim becomes stale=1.

A verified claim is scoped to the instrument that measured it, and an
instrument belongs to one investigation. Scoping the folder scopes the digest,
and the cross-contamination disappears by construction rather than by care.

What goes where, and why the split is not arbitrary:

    sessions/<id>/             the working context — files, human-readable
        session.json           metadata, so a folder explains itself
        transcript.jsonl       append-only turn log (authoritative)
        scripts/               the harness; the digest is taken over this only
        logs/                  job output, sweep dumps, intermediate JSON
        reports/               deliverables
        progress.md            optional running notes the agent maintains

    state/agent.db             the cross-cutting index — conversations, goals,
                               claims. Queryable across investigations, which
                               is what makes "list my sessions" and "which
                               claims went stale" cheap.

This mirrors what the mature harnesses converged on, in both directions: Codex
and Claude Code persist one JSONL transcript per session under a date- or
cwd-partitioned directory, while opencode and Goose keep sessions in SQLite.
Both work. What none of them do is put every session's *scripts* in one shared
pile, which is the part that was actually wrong here.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import time
from pathlib import Path

from ..config import SESSIONS_DIR

SESSION_ROOT = SESSIONS_DIR

# Subdirectories created for every conversation. `scripts` is separated because
# the harness digest is taken over it alone — a dump in `logs/` must not
# invalidate a verified claim.
LAYOUT = ("scripts", "logs", "reports")


def workspace(conversation_id: str, *, create: bool = True) -> Path:
    path = SESSION_ROOT / (conversation_id or "unassigned")
    if create:
        ensure(path)
    return path


def ensure(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    for sub in LAYOUT:
        (path / sub).mkdir(exist_ok=True)
    return path


def scripts_dir(conversation_id: str) -> Path:
    return workspace(conversation_id) / "scripts"


def logs_dir(conversation_id: str) -> Path:
    return workspace(conversation_id) / "logs"


def reports_dir(conversation_id: str) -> Path:
    return workspace(conversation_id) / "reports"


def write_meta(conversation_id: str, meta: dict) -> None:
    """Keep a self-describing session.json beside the transcript.

    A folder of scripts with no metadata is unidentifiable six months later,
    and that is exactly when someone opens it.
    """
    path = workspace(conversation_id) / "session.json"
    existing = {}
    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            existing = {}
    existing.update(meta)
    existing["id"] = conversation_id
    existing["updated"] = time.time()
    path.write_text(json.dumps(existing, ensure_ascii=False, indent=2),
                    encoding="utf-8")


def read_meta(conversation_id: str) -> dict:
    path = workspace(conversation_id, create=False) / "session.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def harness_digest(conversation_id: str) -> str:
    """Digest of *this conversation's* instrument, not of a shared pile.

    Scoped to `scripts/` so that a log dump or a report never invalidates a
    claim, and scoped to the conversation so that another investigation's work
    never does either.
    """
    h = hashlib.sha256()
    root = scripts_dir(conversation_id)
    if not root.exists():
        return h.hexdigest()[:16]
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        try:
            h.update(str(path.relative_to(root)).replace("\\", "/").encode())
            h.update(b"\0")
            h.update(path.read_bytes())
            h.update(b"\0")
        except OSError:
            continue
    return h.hexdigest()[:16]


# ── transcript ──────────────────────────────────────────────────────────────

TRANSCRIPT = "transcript.jsonl"

# Replay budget. Persistence must not become its own cost: replaying everything
# that was ever saved is how a stored conversation gets more expensive than a
# fresh one.
REPLAY_TURNS = 12
REPLAY_CHARS_PER_TURN = 1500


def transcript_path(conversation_id: str) -> Path:
    return workspace(conversation_id) / TRANSCRIPT


def append_turn(conversation_id: str, turn: dict) -> dict:
    """Append one turn to the JSONL log.

    JSONL rather than a binary column because this file is the durable record:
    it can be read with `type`, grepped, diffed, and recovered by hand if the
    database is lost. The database is the index over it, not its owner.
    """
    path = transcript_path(conversation_id)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(turn, ensure_ascii=False, default=str) + "\n")
    return turn


def read_turns(conversation_id: str, limit: int | None = None) -> list[dict]:
    """All turns, or the last `limit`. Skips malformed lines rather than dying.

    A half-written final line is what a crash looks like; losing the whole
    transcript to it would be the wrong trade.
    """
    path = transcript_path(conversation_id)
    if not path.exists():
        return []
    turns: list[dict] = []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    turns.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        return []
    return turns[-limit:] if limit else turns


def replay(conversation_id: str, limit: int = REPLAY_TURNS) -> list[dict]:
    """Recent turns, text only, head+tail clipped — what the model is given."""
    out = []
    for t in read_turns(conversation_id, limit=limit):
        text = t.get("content") or ""
        if len(text) > REPLAY_CHARS_PER_TURN:
            text = clip(text, REPLAY_CHARS_PER_TURN)
        out.append({"role": t.get("role", "user"), "content": text})
    return out


def clip(text: str, budget: int) -> str:
    """Head+tail clip with the marker charged against the budget."""
    if len(text) <= budget:
        return text
    marker = f"\n…[{len(text)} chars total, middle elided]…\n"
    room = budget - len(marker)
    if room <= 0:
        return marker
    head = room // 2
    return text[:head] + marker + text[len(text) - head:]


def summary(conversation_id: str) -> dict:
    """What is in this session's folder — for the GUI and for auditing."""
    root = workspace(conversation_id, create=False)
    if not root.exists():
        return {"dir": str(root), "exists": False, "files": 0, "bytes": 0,
                "scripts": 0, "reports": 0, "harness_digest": ""}
    files = [p for p in root.rglob("*") if p.is_file()]
    return {
        "dir": str(root),
        "exists": True,
        "files": len(files),
        "bytes": sum(p.stat().st_size for p in files if p.exists()),
        "scripts": len(list(scripts_dir(conversation_id).glob("*")))
        if (root / "scripts").exists() else 0,
        "reports": len(list(reports_dir(conversation_id).glob("*")))
        if (root / "reports").exists() else 0,
        "harness_digest": harness_digest(conversation_id),
    }


def delete(conversation_id: str) -> bool:
    """Remove a session folder. Only ever called with an explicit id."""
    root = SESSION_ROOT / (conversation_id or "")
    if not conversation_id or not root.exists():
        return False
    shutil.rmtree(root, ignore_errors=True)
    return True
