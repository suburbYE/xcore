"""Can an AI actually drive xcore over MCP?

The CLI is for the AI, not for a human, so "the module imports" is not the
question. The question is whether a real MCP client can spawn the server, list
the tools, and call one -- over the same stdio JSON-RPC a harness like Claude
Code or Codex uses. Everything else is a proxy for this.

It is also the only way to catch the failure mode this file exists for: a
server that *starts* but whose stdout carries a stray print or banner. That
corrupts the JSON-RPC stream, so the client hangs or errors while the process
looks perfectly healthy from the outside.

Run:  python scripts/verify_mcp.py
"""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

checks: list[tuple[str, bool, str]] = []
skips: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    checks.append((name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""))


def skip(name: str, why: str) -> None:
    skips.append(name)
    print(f"  [SKIP] {name} -- {why}")


def unwrap(e: BaseException, depth: int = 0) -> list[str]:
    """Flatten an ExceptionGroup into readable lines.

    The MCP client runs the session in a TaskGroup, so any failure arrives as
    an ExceptionGroup whose message is just "unhandled errors in a TaskGroup".
    Printing only that would hide the cause entirely -- which is the same
    silent-failure shape this whole script exists to catch.
    """
    pad = "    " * depth
    lines = [f"{pad}{type(e).__name__}: {e}"]
    for sub in getattr(e, "exceptions", []) or []:
        lines.extend(unwrap(sub, depth + 1))
    return lines


async def main() -> int:
    try:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
    except ImportError as e:
        print(f"mcp client SDK unavailable: {e}")
        return 2

    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "xchat.tools.mcp_server"],
        cwd=str(ROOT),
        env={**os.environ, "PYTHONPATH": str(ROOT), "PYTHONIOENCODING": "utf-8"},
    )

    print("connecting to `python -m xchat.tools.mcp_server` over stdio")
    try:
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await asyncio.wait_for(session.initialize(), timeout=60)
                check("initialize handshake completes", True)

                listed = await asyncio.wait_for(session.list_tools(), timeout=60)
                tools = listed.tools
                names = [t.name for t in tools]
                check("tools/list returns tools", bool(tools), f"n={len(tools)}")

                # The registry-derived surface is ~38. A handful means the
                # hand-written TOOL_SCHEMAS list is still what is being served.
                check("tool surface is registry-derived, not the legacy 5",
                      len(tools) > 10, f"n={len(tools)}")
                check("tool names look like capabilities",
                      all("." in n or "_" in n for n in names),
                      f"sample={names[:4]}")

                # Every tool must carry a schema an AI can build arguments from.
                # Field naming moved from inputSchema to input_schema between
                # SDK generations, so probe for both rather than pinning one.
                def schema_of(t):
                    return getattr(t, "inputSchema", None) or getattr(t, "input_schema", None) or {}

                # Cross-check the advertised surface against the registry.
                #
                # "Every tool has a non-empty schema" would be the wrong rule:
                # job.list and knowledge.stats genuinely take no parameters, so
                # an empty `properties` is correct for them. The real invariant
                # is that the two surfaces AGREE -- which is what
                # `_registry_tools` claims and what the `arguments` bug broke
                # (the registry said `limit`, the wire said `arguments`).
                from xchat.kernel import bootstrap
                from xchat.tools.mcp_server import MCP_DENY

                expected: dict[str, set[str]] = {}
                for spec in bootstrap().specs():
                    if spec["id"] in MCP_DENY or spec.get("kind") == "agent":
                        continue
                    wire = spec["id"].replace(".", "_").replace("-", "_")
                    expected[wire] = set((spec.get("params") or {}).get("properties") or {})

                advertised = {t.name: set(schema_of(t).get("properties") or {})
                              for t in tools}
                missing = sorted(set(expected) - set(advertised))
                extra = sorted(set(advertised) - set(expected))
                drifted = sorted(n for n in set(expected) & set(advertised)
                                 if expected[n] != advertised[n])

                check("MCP surface matches the registry exactly",
                      not missing and not extra and not drifted,
                      f"missing={missing[:3]} extra={extra[:3]} "
                      f"param-drift={[(n, sorted(expected[n]), sorted(advertised[n])) for n in drifted[:2]]}"
                      if (missing or extra or drifted)
                      else f"{len(advertised)} tools, params identical")

                no_schema = [t.name for t in tools if not schema_of(t).get("type")]
                check("every tool has an object input schema", not no_schema,
                      f"missing on {no_schema[:4]}" if no_schema else "all present")

                # The bug this script was written to find: the handler was
                # `def run(**arguments)`, so the SDK read the signature as one
                # required parameter literally called `arguments`. All 38 tools
                # listed fine and every single call failed validation. A tool
                # surface that is 100% uncallable while looking healthy is worse
                # than an empty one, because nobody goes looking.
                bogus = [t.name for t in tools
                         if set(schema_of(t).get("properties") or {}) == {"arguments"}]
                check("no tool exposes a bogus `arguments` parameter", not bogus,
                      f"{len(bogus)} tools affected: {bogus[:4]}" if bogus
                      else "parameters are the real capability params")

                # A tool's real params must reach the capability. Calling with
                # `{}` cannot show that, so invoke one that takes an argument.
                pair = next(((t, list((schema_of(t).get("properties") or {})))
                             for t in tools
                             if "history" in t.name
                             and "limit" in (schema_of(t).get("properties") or {})),
                            None)
                if pair is None:
                    skip("tools/call forwards a real argument",
                         "no cheap tool with a known parameter found")
                else:
                    t, first = pair
                    res = await asyncio.wait_for(
                        session.call_tool(t.name, {"limit": 1}), timeout=120)
                    is_err = getattr(res, "isError", None)
                    if is_err is None:
                        is_err = getattr(res, "is_error", None)
                    text = "".join(getattr(c, "text", "") for c in (res.content or []))
                    check(f"tools/call {t.name!r}(limit=1) succeeds", is_err is False,
                          f"is_error={is_err}")
                    # Length is not evidence: an error message has length too,
                    # and the first version of this check passed on one.
                    check(f"tools/call {t.name!r} returned output, not an error",
                          bool(text.strip()) and "validation error" not in text
                          and "Field required" not in text,
                          f"{len(text)} chars: {text[:70]!r}")

                # Something read-only and cheap: proves the zero-arg call path.
                probe = next((n for n in names if "stats" in n), None)
                if probe is None:
                    skip("tools/call with no arguments", "no cheap tool found")
                else:
                    res = await asyncio.wait_for(
                        session.call_tool(probe, {}), timeout=120)
                    is_err = getattr(res, "isError", None)
                    if is_err is None:
                        is_err = getattr(res, "is_error", None)
                    text = "".join(getattr(c, "text", "") for c in (res.content or []))
                    check(f"tools/call {probe!r}() succeeds", is_err is False,
                          f"is_error={is_err}")
                    check(f"tools/call {probe!r}() returned output",
                          bool(text.strip()), f"{len(text)} chars")

                # A tool the agent must not be able to call into itself.
                check("agent.* is not exposed",
                      not any(n.startswith("agent") for n in names),
                      "no recursive self-invocation surface")

    except asyncio.TimeoutError:
        check("MCP session completes", False,
              "TIMED OUT -- a stray print on stdout corrupts the JSON-RPC stream")
    except BaseException as e:
        for line in unwrap(e):
            print(line)
        check("MCP session completes", False, f"{type(e).__name__}: {e}")

    failed = [n for n, ok, _ in checks if not ok]
    summary = (f"\n{len(checks) - len(failed)}/{len(checks)} PASS"
               + (f", FAILED: {failed}" if failed else ""))
    if skips:
        summary += f", {len(skips)} SKIPPED: {skips}"
    print(summary)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
