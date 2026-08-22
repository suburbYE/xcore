"""
MCP Server Skeleton — wraps xcore_bridge tools as MCP resources.

Currently provides the Tool Schema definitions and handler stubs.
When the ``mcp`` SDK is installed, uncomment the integration points
and remove the ``NotImplementedError`` guards.

Usage (future)::

    from xchat.tools.mcp_server import start_server
    start_server()
"""

from __future__ import annotations

from typing import Any

from .xcore_bridge import (
    run_native_scan,
    run_web_pipeline,
    run_apk_pipeline,
    generate_frida_probe,
    classify_shell,
)

# ─── Tool Schemas ─────────────────────────────────────────────────────────────
# These describe the JSON Schema for each tool that will be exposed via MCP.

TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "run_native_scan",
        "description": (
            "Scan a native shared library (.so/.dll) with xcore Phase 4b "
            "target scanner. Returns algorithm detection layers, string "
            "cross-references, constant fingerprints, and CFG pattern matches."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "so_path": {
                    "type": "string",
                    "description": "Absolute path to the .so or .dll file to scan.",
                },
            },
            "required": ["so_path"],
        },
    },
    {
        "name": "run_web_pipeline",
        "description": (
            "Execute the xcore web deobfuscation pipeline against a JS bundle "
            "URL.  NOTE: This endpoint is not yet integrated (Phase 3e)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL or JS bundle URL.",
                },
                "entry": {
                    "type": "string",
                    "description": "Optional entry function name.",
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "run_apk_pipeline",
        "description": (
            "Run the full Phase 4c native pipeline against an APK: "
            "shell classification → .so extraction → target scanning → "
            "Frida probe generation. Returns summary.json contents."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {
                    "type": "string",
                    "description": "Absolute path to the .apk file.",
                },
                "output_dir": {
                    "type": "string",
                    "description": "Optional output directory for results.",
                },
            },
            "required": ["apk_path"],
        },
    },
    {
        "name": "generate_frida_probe",
        "description": (
            "Generate a Frida probe script from a Phase 4b target_scanner "
            "JSON output. The generated script contains RegisterNatives hooks, "
            "RVA hex-dump probes, and crypto function logging."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "scan_json_path": {
                    "type": "string",
                    "description": "Path to target_scanner output JSON.",
                },
                "output_dir": {
                    "type": "string",
                    "description": "Optional output directory for the .js script.",
                },
            },
            "required": ["scan_json_path"],
        },
    },
    {
        "name": "classify_shell",
        "description": (
            "Classify an APK's packer/protector shell (Tencent Legu, 360, "
            "Bangcle, etc.) using passive static analysis. Returns shell name, "
            "confidence, evidence chain, and recommended next steps."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {
                    "type": "string",
                    "description": "Absolute path to the .apk file.",
                },
            },
            "required": ["apk_path"],
        },
    },
]

# Map tool name → handler function
_HANDLERS: dict[str, Any] = {
    "run_native_scan": run_native_scan,
    "run_web_pipeline": run_web_pipeline,
    "run_apk_pipeline": run_apk_pipeline,
    "generate_frida_probe": generate_frida_probe,
    "classify_shell": classify_shell,
}


# ─── MCP Server Class (skeleton) ──────────────────────────────────────────────

class MCPServer:
    """MCP Server for xcore toolchain.

    Currently a skeleton.  Once the ``mcp`` SDK is integrated, this class
    will be registered as an MCP server with the tool list above.

    Integration roadmap::

        # 1. Install mcp SDK (see requirements.txt)
        # 2. Replace the NotImplementedError below with:
        #
        #    from mcp.server import Server
        #    from mcp.types import Tool, TextContent
        #
        #    self._server = Server("xcore-tools")
        #
        #    @self._server.list_tools()
        #    async def list_tools() -> list[Tool]:
        #        return [Tool(**s) for s in TOOL_SCHEMAS]
        #
        #    @self._server.call_tool()
        #    async def call_tool(name: str, arguments: dict) -> list[TextContent]:
        #        result = await self._dispatch(name, arguments)
        #        return [TextContent(type="text", text=json.dumps(result))]
        #
        # 3. Use stdio_server() or SSE transport in start_server().
    """

    def __init__(self) -> None:
        self._tools = TOOL_SCHEMAS
        self._handlers = _HANDLERS
        # TODO: self._server = Server("xcore-tools")  # mcp SDK integration

    def list_tools(self) -> list[dict[str, Any]]:
        """Return the list of registered MCP tool schemas."""
        return self._tools

    def dispatch(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Invoke the handler for *tool_name* and return the result.

        Args:
            tool_name: One of the keys in ``_HANDLERS``.
            arguments: Keyword arguments passed to the bridge function.

        Returns:
            dict result from the corresponding xcore_bridge function.

        Raises:
            ValueError: If *tool_name* is unknown.
        """
        handler = self._handlers.get(tool_name)
        if handler is None:
            raise ValueError(
                f"Unknown tool '{tool_name}'. "
                f"Available: {list(self._handlers.keys())}"
            )
        return handler(**arguments)


# ─── Entry point ──────────────────────────────────────────────────────────────


def start_server() -> None:
    """Start the MCP server (skeleton — mcp SDK not yet wired).

    Raises:
        NotImplementedError: Until the mcp SDK is integrated.
    """
    # TODO: Replace this with actual mcp SDK transport wiring.
    # Example:
    #
    #   import asyncio
    #   from mcp.server.stdio import stdio_server
    #
    #   async def main():
    #       server = MCPServer()
    #       async with stdio_server() as (reader, writer):
    #           await server._server.run(reader, writer)
    #   asyncio.run(main())
    #
    raise NotImplementedError(
        "MCP server transport not yet wired. "
        "Install 'mcp' SDK and uncomment the integration points in "
        "xchat/tools/mcp_server.py."
    )
