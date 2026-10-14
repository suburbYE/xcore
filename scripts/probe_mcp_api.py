"""What does the installed mcp SDK let us tell it about a tool's parameters?

The server already computes a correct JSON Schema per capability and then
discards it, because the handler is `def run(**arguments)` and the SDK
introspects that signature -- producing a single required parameter literally
named `arguments` on all 38 tools. Any call then fails validation.

Which repair is right depends on the installed SDK: it may accept an explicit
schema, and if it does not, attaching `__signature__` to the handler is the
portable answer (inspect.signature honours it). This prints what is available
instead of guessing.

Run:  python scripts/probe_mcp_api.py
"""
import inspect
import sys

from mcp.server.mcpserver import MCPServer

print("MCPServer.tool signature:")
sig = inspect.signature(MCPServer.tool)
for name, p in sig.parameters.items():
    print(f"  {name}: {p.kind.name} default={p.default!r} annotation={p.annotation!r}")

print("\nMCPServer methods:")
print("  " + ", ".join(sorted(m for m in dir(MCPServer) if not m.startswith("_"))))

# Does adding a tool with an explicit schema get through?
print("\nprobe: can we register a function with __signature__ attached?")
from inspect import Parameter, Signature


def run(**arguments):
    return arguments


run.__signature__ = Signature(parameters=[
    Parameter("x", Parameter.KEYWORD_ONLY, default="", annotation=str),
])
print("  run.__signature__ ->", inspect.signature(run))
print("  honours __signature__:",
      list(inspect.signature(run).parameters) == ["x"])

try:
    m = MCPServer("probe")
    m.tool(name="probe_tool")(run)
    print("  tool() accepted the named form")
except Exception as e:
    print(f"  tool(name=...) failed: {type(e).__name__}: {e}")

print("\nMCPServer.add_tool signature:")
for name, p in inspect.signature(MCPServer.add_tool).parameters.items():
    print(f"  {name}: {p.kind.name} default={p.default!r} annotation={p.annotation!r}")

print("\nmcp.types.Tool fields:")
try:
    import mcp.types as T
    for f, info in T.Tool.model_fields.items():
        print(f"  {f}: required={info.is_required()} annotation={info.annotation}")
except Exception as e:
    print(f"  could not introspect: {e}")

sys.exit(0)
