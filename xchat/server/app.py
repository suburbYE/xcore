"""
Local API server: the client-facing edge of the kernel channel.

Binds to loopback only. This process is the single holder of API keys and the
only thing the GUI talks to (see docs/client_architecture.md §2.4) — the Tauri
frontend never gets a credential and never touches the filesystem directly.

Endpoints
---------
GET  /api/health                 liveness + capability count
GET  /api/capabilities           full specs (GUI renders forms from these)
GET  /api/capabilities/{id}      one spec
POST /api/invoke/{id}            run to completion, return {events, result}
GET  /api/invoke/{id}/stream     Server-Sent Events, live progress
WS   /ws                         invoke + receive the event stream
GET  /api/stats                  scheduler metrics / breakers / in-flight
GET  /api/providers              balances + live model lists
GET  /api/usage                  ledger summary

SSE rather than POST-streaming for progress because EventSource is trivial in a
browser/webview and survives reconnects. WebSocket is offered for interactive
sessions where the client also needs to *send* mid-stream.
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import time
from pathlib import Path
from typing import Any

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse, PlainTextResponse, StreamingResponse
from starlette.routing import Route, WebSocketRoute

from ..kernel import EVENT_ERROR, EVENT_RESULT, InvokeContext, bootstrap
from ..kernel.scheduler import Scheduler

# ── security ────────────────────────────────────────────────────────────────
#
# This server spends money and reads the filesystem, so loopback binding alone
# is not enough. A page the user merely *visits* can still reach 127.0.0.1:
#
#   * POSTs with Content-Type: application/json need a preflight, so restricted
#     CORS already blocks them.
#   * EventSource cannot set headers and needs no preflight, so
#     `GET /api/invoke/<id>/stream` is CSRF-reachable and WOULD run a scan or
#     burn API credit.
#
# Hence a shared token on every /api route. It is accepted from the
# `X-XCore-Token` header or a `token` query parameter, because EventSource has
# no other way to carry it.

TOKEN_FILE = Path(__file__).resolve().parents[2] / "state" / "server_token"

# Tauri's webview origin on Windows, plus localhost for `vite dev`.
ALLOWED_ORIGINS = [
    "http://tauri.localhost",
    "https://tauri.localhost",
    "tauri://localhost",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

# Any loopback origin is acceptable: the CSRF threat is a page on the public
# web reaching 127.0.0.1, not another local dev server. The token remains the
# actual authorisation check.
ALLOWED_ORIGIN_REGEX = r"^https?://(127\.0\.0\.1|localhost|\[::1\])(:\d+)?$"


def load_or_create_token() -> str:
    env = os.environ.get("XCORE_TOKEN")
    if env:
        return env.strip()
    try:
        if TOKEN_FILE.exists():
            tok = TOKEN_FILE.read_text(encoding="utf-8").strip()
            if tok:
                return tok
        TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
        tok = secrets.token_hex(24)
        TOKEN_FILE.write_text(tok, encoding="utf-8")
        try:
            TOKEN_FILE.chmod(0o600)
        except Exception:
            pass
        return tok
    except Exception:
        # Never let token provisioning take the server down; fall back to a
        # per-process token so the server still works, just not across restarts.
        return secrets.token_hex(24)


SERVER_TOKEN = load_or_create_token()

# /api/health is exempt: it is read-only, reveals nothing, and both the Rust
# supervisor and the UI need it before they could possibly hold a token.
EXEMPT_PATHS = {"/api/health"}


class TokenMiddleware:
    """Reject /api requests without the shared token."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        path = scope.get("path", "")
        if not path.startswith("/api") or path in EXEMPT_PATHS:
            return await self.app(scope, receive, send)

        headers = {k.decode("latin-1").lower(): v.decode("latin-1")
                   for k, v in scope.get("headers", [])}
        supplied = headers.get("x-xcore-token", "")
        if not supplied:
            qs = scope.get("query_string", b"").decode("latin-1")
            for part in qs.split("&"):
                if part.startswith("token="):
                    supplied = part[6:]
                    break

        if not secrets.compare_digest(supplied, SERVER_TOKEN):
            body = json.dumps({
                "error": "missing or invalid token",
                "code": "unauthorized",
                "hint": f"send X-XCore-Token header (token file: {TOKEN_FILE})",
            }).encode()
            await send({"type": "http.response.start", "status": 401,
                        "headers": [(b"content-type", b"application/json"),
                                    (b"content-length", str(len(body)).encode())]})
            await send({"type": "http.response.body", "body": body})
            return

        return await self.app(scope, receive, send)

# ── app state ───────────────────────────────────────────────────────────────

_registry = None
_scheduler: Scheduler | None = None
_started_at = time.time()


def get_scheduler() -> Scheduler:
    global _registry, _scheduler
    if _scheduler is None:
        _registry = bootstrap(reset=True)
        _scheduler = Scheduler(_registry)
    return _scheduler


def _json(payload: Any, status: int = 200) -> JSONResponse:
    return JSONResponse(payload, status_code=status)


def _events_to_dicts(events) -> list[dict]:
    return [e.to_dict() for e in events]


async def _collect(sched: Scheduler, cap_id: str, params: dict) -> tuple[list, Any, dict | None]:
    """Drain an invocation. Returns (events, result_value, error_data)."""
    events, result, error = [], None, None
    async for ev in sched.invoke(cap_id, params, InvokeContext()):
        events.append(ev)
        if ev.type == EVENT_RESULT:
            result = ev.data.get("value")
        elif ev.type == EVENT_ERROR:
            error = ev.data
    return events, result, error


# ── handlers ────────────────────────────────────────────────────────────────

async def shutdown(request):
    """Stop the server, gracefully.

    Token-protected like everything else, and it answers *before* stopping: a
    client that asked for shutdown should learn the request landed, rather than
    watch the connection die with no reply.

    Graceful rather than abrupt because the SQLite databases recover fine but do
    not enjoy it, and because uvicorn's shutdown runs the lifespan hooks — the
    one place in-flight work gets a chance to settle.
    """
    import asyncio
    import os
    import signal

    def stop() -> None:
        # SIGINT is what uvicorn treats as a graceful shutdown request.
        try:
            os.kill(os.getpid(), signal.SIGINT)
        except Exception:
            pass

    asyncio.get_running_loop().call_later(0.4, stop)
    return _json({"stopping": True, "pid": os.getpid()})


async def health(request):
    sched = get_scheduler()
    # Reported on every health probe: a long-lived engine keeps the code it
    # loaded at startup, so an edit made since then changes nothing here and the
    # symptom is the *old* behaviour -- indistinguishable from "the fix did not
    # work". Saying so is the only way the client can tell the user.
    from ..kernel import freshness
    return _json({
        "ok": True,
        "uptime_s": round(time.time() - _started_at, 1),
        "capabilities": len(sched.registry),
        "kinds": sched.registry.kinds(),
        "code": freshness.staleness(_started_at),
    })


async def token_info(request):
    """Tell an already-authorised caller where the token lives.

    Kept minimal on purpose: this endpoint does not return the token itself, so
    possessing it proves nothing to an attacker.
    """
    return _json({"required": True, "header": "X-XCore-Token",
                  "query_param": "token", "token_file": str(TOKEN_FILE),
                  "exempt": sorted(EXEMPT_PATHS)})


async def list_capabilities(request):
    sched = get_scheduler()
    kind = request.query_params.get("kind")
    return _json({"capabilities": sched.registry.specs(kind)})


async def get_capability(request):
    sched = get_scheduler()
    cap_id = request.path_params["cap_id"]
    reg = sched.registry.get(cap_id)
    if reg is None:
        return _json({"error": "unknown capability", "id": cap_id,
                      "known": sched.registry.ids()}, 404)
    return _json(reg.spec.to_dict())


async def invoke(request):
    """Run a capability synchronously and return its full event list."""
    sched = get_scheduler()
    cap_id = request.path_params["cap_id"]
    try:
        params = await request.json()
    except Exception:
        params = {}
    if not isinstance(params, dict):
        return _json({"error": "body must be a JSON object"}, 400)

    events, result, error = await _collect(sched, cap_id, params)
    body = {
        "capability": cap_id,
        "events": _events_to_dicts(events),
        "result": result,
    }
    if error is not None:
        body["error"] = error
        code = error.get("code", "error")
        status = 404 if code in ("unknown_capability", "not_found") else 400
        if code == "internal_error":
            status = 500
        return _json(body, status)
    return _json(body)


async def chat_insert(request):
    """Accept a message while a turn is already running.

    The point of a separate endpoint is that the normal path is busy: the client
    is holding an open SSE stream, so it cannot send on the same channel. Modes
    match the kernel inbox — `interject` joins the running turn at its next
    round boundary, `queue` waits for the turn to end.

    Returns the pending list so the caller can render what is waiting.
    """
    from ..kernel import inbox as inbox_mod
    from ..kernel import agentstate as agentstate_mod

    try:
        body = await request.json()
    except Exception:
        return _json({"error": "body must be a JSON object"}, 400)
    text = (body.get("message") or "").strip()
    if not text:
        return _json({"error": "'message' is required"}, 400)
    mode = body.get("mode") or inbox_mod.QUEUE

    conversation_id = body.get("conversation_id") or ""
    if not conversation_id:
        latest = agentstate_mod.latest_conversation()
        conversation_id = (latest or {}).get("id", "")

    note = inbox_mod.INBOX.push(conversation_id, text, mode)
    return _json({
        "note": note.to_dict(),
        "mode": note.mode,
        "conversation_id": conversation_id,
        "pending": inbox_mod.INBOX.pending(conversation_id),
        "note_hint": ("会在本轮的下一个工具边界并入" if note.mode == inbox_mod.INTERJECT
                      else "会在当前任务结束后自动发出"),
    })


async def chat_inbox(request):
    """What is waiting, and a way to drop it."""
    from ..kernel import inbox as inbox_mod
    conversation_id = request.query_params.get("conversation_id") or ""
    if request.method == "DELETE":
        dropped = inbox_mod.INBOX.clear(conversation_id)
        return _json({"dropped": dropped})
    return _json({"conversation_id": conversation_id,
                  "pending": inbox_mod.INBOX.pending(conversation_id)})


async def invoke_stream(request):
    """SSE: `data: {event json}` per event, terminated by a `done` marker."""
    sched = get_scheduler()
    cap_id = request.path_params["cap_id"]
    raw = request.query_params.get("params")
    try:
        params = json.loads(raw) if raw else {}
    except json.JSONDecodeError as e:
        return _json({"error": f"params must be valid JSON: {e}"}, 400)

    async def gen():
        try:
            async for ev in sched.invoke(cap_id, params, InvokeContext()):
                yield f"data: {json.dumps(ev.to_dict(), ensure_ascii=False)}\n\n"
        except asyncio.CancelledError:
            # client disconnected mid-stream; not an error worth logging loudly
            raise
        finally:
            yield "event: done\ndata: {}\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream", headers={
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
    })


async def stats(request):
    return _json(get_scheduler().stats())


async def providers(request):
    """Balance + model discovery. Never raises: the GUI polls this on a timer."""
    def collect():
        from ..providers import account, registry as preg
        out = {}
        for p in preg.known():
            configured = p in (account._keys() or {})
            b = account.balance(p)
            models, err = account.list_models(p) if configured else ([], "")
            out[p] = {
                "label": preg.get(p).label,
                "configured": configured,
                "balance": {
                    "supported": b.supported,
                    "ok": b.ok,
                    "total": b.total,
                    "currency": b.currency,
                    "granted": b.granted,
                    "topped_up": b.topped_up,
                    "error": b.error,
                    "reason": b.reason,
                },
                "models": [{"id": m.id, "context_window": m.context_window,
                            "max_output": m.max_output, "source": m.source}
                           for m in models],
                "models_error": err,
            }
        return out

    return _json(await asyncio.get_running_loop().run_in_executor(None, collect))


async def usage(request):
    from ..providers import usage as u
    days = int(request.query_params.get("days", "14"))
    since = 0.0
    if request.query_params.get("since_hours"):
        since = time.time() - float(request.query_params["since_hours"]) * 3600
    return _json({
        "summary": u.summary(since),
        "daily": u.daily(days),
        "recent": u.recent(int(request.query_params.get("limit", "50"))),
    })


# ── websocket ───────────────────────────────────────────────────────────────

async def ws_endpoint(websocket):
    """Protocol: client sends {"capability": id, "params": {...}}; server
    streams event frames then {"type":"done"}. A new message starts a new run."""
    await websocket.accept()
    sched = get_scheduler()
    await websocket.send_json({"type": "hello",
                               "capabilities": sched.registry.ids()})
    try:
        while True:
            msg = await websocket.receive_json()
            cap_id = msg.get("capability")
            params = msg.get("params") or {}
            if not cap_id:
                await websocket.send_json({"type": "error",
                                           "data": {"message": "capability required"}})
                continue
            async for ev in sched.invoke(cap_id, params, InvokeContext()):
                await websocket.send_json(ev.to_dict())
            await websocket.send_json({"type": "done", "capability": cap_id})
    except Exception:
        # normal disconnect (WebSocketDisconnect) or malformed frame
        return


routes = [
    Route("/api/health", health),
    Route("/api/shutdown", shutdown, methods=["POST"]),
    Route("/api/token", token_info),
    Route("/api/capabilities", list_capabilities),
    Route("/api/capabilities/{cap_id}", get_capability),
    Route("/api/invoke/{cap_id}", invoke, methods=["POST"]),
    Route("/api/invoke/{cap_id}/stream", invoke_stream, methods=["GET"]),
    Route("/api/chat/insert", chat_insert, methods=["POST"]),
    Route("/api/chat/inbox", chat_inbox, methods=["GET", "DELETE"]),
    Route("/api/stats", stats),
    Route("/api/providers", providers),
    Route("/api/usage", usage),
    WebSocketRoute("/ws", ws_endpoint),
]

middleware = [
    Middleware(CORSMiddleware,
               allow_origins=ALLOWED_ORIGINS,
               allow_origin_regex=ALLOWED_ORIGIN_REGEX,
               allow_credentials=False,
               allow_methods=["GET", "POST", "OPTIONS"],
               allow_headers=["Content-Type", "X-XCore-Token"]),
    Middleware(TokenMiddleware),
]

app = Starlette(routes=routes, middleware=middleware)
