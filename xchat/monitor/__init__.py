"""
Phase 5d: Auto-Healing Monitor package.

Exports:
    run_frida_session  — Launch Frida + inject probe + capture output
    check_frida_installed — Verify frida CLI on PATH
    list_processes    — Enumerate device processes
    parse_frida_error — Classify Frida stderr errors
    extract_hook_context — Extract probe code around an error RVA
    auto_heal         — Full auto-healing loop (inject → detect → fix → retry)
"""

from .frida_runner import run_frida_session, check_frida_installed, list_processes
from .error_parser import parse_frida_error, extract_hook_context
from .patch_loop import auto_heal

__all__ = [
    "run_frida_session",
    "check_frida_installed",
    "list_processes",
    "parse_frida_error",
    "extract_hook_context",
    "auto_heal",
]
