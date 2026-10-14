"""What does the MCP tool surface actually look like to an AI?

Two things a length check cannot see, and both would break a real harness:

  * the *parameter names* in each tool's schema. If the server's wrapper is
    `def run(**arguments)`, a schema generator can conclude the tool takes one
    parameter literally called `arguments` -- so the AI sends {"arguments": {}}
    and the server rejects it. The tool "works" and is still uncallable.
  * what a tool actually returns on a successful call, as opposed to an error
    string that merely has a nonzero length.

Run:  python scripts/probe_mcp_schema.py
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def unwrap(e: BaseException, depth: int = 0) -> list[str]:
    pad = "    " * depth
    out = [f"{pad}{type(e).__name__}: {e}"]
    for sub in getattr(e, "exceptions", []) or []:
        out.extend(unwrap(sub, depth + 1))
    return out


async def main() -> int:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "xchat.tools.mcp_server"],
        cwd=str(ROOT),
        env={**os.environ, "PYTHONPATH": str(ROOT), "PYTHONIOENCODING": "utf-8"},
    )

    report: list[str] = []
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await asyncio.wait_for(session.initialize(), timeout=60)
            tools = (await asyncio.wait_for(session.list_tools(), timeout=60)).tools

            report.append(f"tools: {len(tools)}\n")

            def schema_of(t):
                return getattr(t, "inputSchema", None) or getattr(t, "input_schema", None) or {}

            # The tell: a schema whose only property is named "arguments".
            bogus = [t.name for t in tools if set(schema_of(t).get("properties") or {}) == {"arguments"}]
            report.append(f"tools whose ONLY parameter is `arguments`: {len(bogus)}")
            if bogus:
                report.append(f"  {bogus[:8]}")
            report.append("")

            for t in tools[:4]:
                s = schema_of(t)
                props = list((s.get("properties") or {}).keys())
                report.append(f"  {t.name}")
                report.append(f"    params: {props}")
                report.append(f"    required: {s.get('required')}")

            # Call a cheap one and show the payload, not its size.
            probe = next((t.name for t in tools if "stats" in t.name), None)
            if probe:
                report.append(f"\n--- call {probe!r} with {{}} ---")
                res = await asyncio.wait_for(session.call_tool(probe, {}), timeout=120)
                is_err = getattr(res, "isError", None)
                if is_err is None:
                    is_err = getattr(res, "is_error", None)
                report.append(f"  is_error: {is_err}")
                for c in (res.content or []):
                    txt = getattr(c, "text", None)
                    if txt is not None:
                        report.append("  content:")
                        report.extend("    " + ln for ln in txt.splitlines()[:25])

    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    print("\n".join(report))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except BaseException as e:
        for line in unwrap(e):
            print(line)
        sys.exit(1)
