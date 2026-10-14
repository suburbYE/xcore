"""
MCP Server — exposes the capability registry to MCP clients.

Every capability the registry offers (except `agent.*` and a short deny list)
becomes one MCP tool, served over stdio with the official ``mcp`` SDK
(MCPServer high-level API, formerly FastMCP). This is the AI's interface to
xcore, so the tool surface is derived from the registry rather than written out
here — the two used to disagree, and the copy in this file was the wrong one.

Usage::

    from xchat.tools.mcp_server import start_server
    start_server()          # blocks, runs until stdio closes
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any


logger = logging.getLogger(__name__)

# ─── Tool Schemas ─────────────────────────────────────────────────────────────
# These describe the JSON Schema for each tool that will be exposed via MCP.

# ─── Tool surface ─────────────────────────────────────────────────────────────
#
# One source. This file used to hand-write five tools while the registry grew,
# and the two drifted in the way that matters most: the hand-written schema for
# run_native_scan said the parameter was `so_path`, while the registry -- and
# therefore every MCP client -- said `so`. One capability, two spellings, two
# audiences told different things, and the local model was the one being told
# wrong. The registry is the definition; everything here projects from it.


def tool_schemas(*, allow: set[str] | None = None,
                 deny: set[str] | None = None
                 ) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """The tool surface as `{name, description, inputSchema}` entries.

    Returns `(schemas, name -> capability_id)`. The shape is what both the MCP
    SDK and the Ollama/OpenAI function-calling format expect, so neither
    consumer needs a private copy.
    """
    pairs, _ = _registry_tools(deny)
    if allow is not None:
        pairs = [(cap, s) for cap, s in pairs if cap in allow]
    schemas = [{
        "name": s["name"],
        "description": s["description"],
        "inputSchema": s["parameters"],
    } for _, s in pairs]
    return schemas, {s["name"]: cap for cap, s in pairs}


def invoke_capability(cap_id: str, arguments: dict) -> Any:
    """Run one capability to completion and return its value.

    Synchronous on purpose: MCP tool handlers are called from the SDK's own
    loop, so a streaming capability has to be drained here into its final value
    before it can be returned.
    """
    import asyncio

    from ..kernel import bootstrap
    from ..kernel.contract import InvokeContext

    registry = bootstrap()

    async def collect():
        value, error = None, None
        async for ev in registry.invoke(cap_id, arguments, InvokeContext()):
            if ev.type == "result":
                value = ev.data.get("value")
            elif ev.type == "error":
                error = ev.data
        return value, error

    try:
        value, error = asyncio.run(collect())
    except RuntimeError:
        # Already inside a loop (the SDK runs one): use a private one.
        loop = asyncio.new_event_loop()
        try:
            value, error = loop.run_until_complete(collect())
        finally:
            loop.close()
    if error:
        return {"error": error.get("message"), "code": error.get("code")}
    return value


class MCPServer:
    """Dependency-free view of the same tool surface.

    `start_server()` is what an MCP client talks to. This class exists so the
    surface can be listed and invoked without the `mcp` SDK installed (tests,
    scripted calls). It reads the registry directly instead of keeping a list
    of its own, which is the only way the two can be guaranteed to agree.
    """

    def __init__(self, *, allow: set[str] | None = None,
                 deny: set[str] | None = None) -> None:
        self._schemas, self._reverse = tool_schemas(allow=allow, deny=deny)

    def list_tools(self) -> list[dict[str, Any]]:
        """Return the tool schemas."""
        return self._schemas

    def dispatch(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Invoke a tool by name and return its result.

        Raises:
            KeyError: If *tool_name* is not in the surface.
        """
        cap_id = self._reverse.get(tool_name)
        if cap_id is None:
            raise KeyError(
                f"unknown tool {tool_name!r}. "
                f"Available: {sorted(self._reverse)}")
        return invoke_capability(cap_id, arguments)


# ─── Entry point ──────────────────────────────────────────────────────────────



# Capabilities MCP must not expose. gent.* is excluded structurally by the
# deriver; these are the ones a remote MCP client should not be able to fire
# without the local session that erify.gate and the ledger depend on.
MCP_DENY: set[str] = {
    "agent.chat", "agent.investigate", "agent.tools",
}

def _registry_tools(deny: set[str] | None = None) -> tuple[list[tuple[str, dict]], dict]:
    """Derive the MCP tool surface from the capability registry.

    Returns ([(capability_id, json_schema)], reverse_map) — the same source the
    agent's tool list comes from, so the two cannot disagree. Previously this
    file hand-wrote five tools while the registry grew: the two surfaces
    disagreed about what existed and about what was permitted, and every
    capability added after v0.19 was invisible to MCP clients.

    Tools are named by capability id with `.` replaced by `_`, matching the
    agent's flattening so a name means the same thing on both surfaces.
    """
    from ..kernel import bootstrap
    registry = bootstrap()
    deny = deny if deny is not None else MCP_DENY
    tools: list[tuple[str, dict]] = []
    seen: set[str] = set()
    for spec in registry.specs():
        cap_id = spec["id"]
        if cap_id in deny or spec.get("kind") == "agent":
            continue
        params = spec.get("params") or {}
        if params.get("type") != "object":
            params = {"type": "object", "properties": {}}
        params = {k: v for k, v in params.items()
                  if k not in ("additionalProperties",)}
        params = dict(params)
        params["additionalProperties"] = False
        name = cap_id.replace(".", "_").replace("-", "_")
        if name in seen:
            continue
        seen.add(name)
        tools.append((cap_id, {"name": name, "description": (
            spec.get("description") or spec.get("name") or "")[:900],
            "parameters": params}))
    return tools, {cap: schema["name"] for cap, schema in tools}


def _signature_from_schema(params: dict) -> "inspect.Signature":
    """Turn a capability's JSON Schema into a callable signature.

    The MCP SDK takes no explicit input schema (neither `tool()` nor
    `add_tool()` accepts one); it derives the schema from the handler's
    signature. So the signature *is* the public interface here, and building it
    from the capability's own JSON Schema is what keeps the two from drifting.

    Required parameters get no default; optional ones fall back to the schema's
    default, or to `None` — annotated `T | None` so the generated model accepts
    it rather than rejecting a legitimate omission.
    """
    import inspect

    py_types = {
        "string": str, "integer": int, "number": float,
        "boolean": bool, "array": list, "object": dict,
    }

    props = params.get("properties") or {}
    required = set(params.get("required") or [])
    out = []
    for name, node in props.items():
        if not name.isidentifier():
            # inspect.Signature cannot carry it, and the SDK would fail later
            # with a message pointing at pydantic rather than at the schema.
            continue
        node = node or {}
        ann = py_types.get(node.get("type"), str)
        if name in required:
            out.append(inspect.Parameter(
                name, inspect.Parameter.KEYWORD_ONLY, annotation=ann))
        elif "default" in node:
            out.append(inspect.Parameter(
                name, inspect.Parameter.KEYWORD_ONLY,
                default=node["default"], annotation=ann))
        else:
            out.append(inspect.Parameter(
                name, inspect.Parameter.KEYWORD_ONLY,
                default=None, annotation=ann | None))
    return inspect.Signature(parameters=out)


def start_server(*, allow: set[str] | None = None,
                 deny: set[str] | None = None) -> None:
    """Start the MCP server over stdio using the official ``mcp`` SDK.

    The tool surface is derived from the capability registry, so anything xcore
    can do is reachable here without a second list to maintain. `allow` narrows
    it to an explicit set; otherwise everything not in `MCP_DENY` is exposed.

    Raises:
        ImportError: If the ``mcp`` package is not installed
            (``pip install mcp``).
    """
    try:
        from mcp.server.mcpserver import MCPServer as MCP
        from ..kernel import bootstrap
        from ..kernel.contract import InvokeContext
    except ImportError as exc:  # pragma: no cover - depends on env
        raise ImportError("mcp SDK not installed. Run: pip install mcp") from exc

    registry = bootstrap()
    pairs, _ = _registry_tools(deny if deny is not None else MCP_DENY)
    if allow is not None:
        pairs = [(cap, schema) for cap, schema in pairs if cap in allow]

    mcp = MCP("xcore")

    def _make(cap_id: str, params: dict):
        def run(**arguments):
            """Invoke one capability and collect its result.

            Synchronous on purpose: MCP tool handlers are called from the SDK's
            own loop, and a capability that streams is drained here into its
            final value.
            """
            import asyncio

            async def collect():
                value, error = None, None
                async for ev in registry.invoke(cap_id, arguments,
                                                InvokeContext()):
                    if ev.type == "result":
                        value = ev.data.get("value")
                    elif ev.type == "error":
                        error = ev.data
                return value, error

            try:
                value, error = asyncio.run(collect())
            except RuntimeError:
                # Already inside a loop (the SDK runs one): use a private one.
                loop = asyncio.new_event_loop()
                try:
                    value, error = loop.run_until_complete(collect())
                finally:
                    loop.close()
            if error:
                return {"error": error.get("message"), "code": error.get("code")}
            return value

        run.__name__ = cap_id.replace(".", "_")
        run.__doc__ = f"xcore capability `{cap_id}`."
        # The SDK builds each tool's input schema by introspecting this
        # signature. `def run(**arguments)` reads as one required parameter
        # named `arguments`, so all 38 tools used to be listed with a schema no
        # client could satisfy, and every call failed validation with
        # "arguments: Field required". The capability's real JSON Schema was
        # already computed and then discarded; this is what stops it being
        # discarded.
        run.__signature__ = _signature_from_schema(params)
        return run

    for cap_id, schema in pairs:
        tool = _make(cap_id, schema.get("parameters") or {})
        try:
            mcp.tool(name=schema["name"])(tool)
        except TypeError:
            # Older SDKs take no name= override; the function name carries it.
            mcp.tool()(tool)

    mcp.run(transport="stdio")


if __name__ == "__main__":
    start_server()
