"""
Phase 5d: Frida error classification and context extraction.

Parses Frida's stderr output to classify error types, extract
addresses / line numbers, and retrieve the surrounding Hook code
for LLM-based auto-healing.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any


# ─── Error pattern definitions ────────────────────────────────────────────────

# Ordered list of (regex, error_type, severity).
# Patterns are checked in order; first match wins.
_ERROR_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    # TypeError: cannot read property 'readXxx' of null
    (
        re.compile(
            r"TypeError:\s*cannot\s+read\s+property\s+'read\w*'\s+of\s+null",
            re.IGNORECASE,
        ),
        "TypeError",
        "recoverable",
    ),
    # TypeError: not a function
    (
        re.compile(r"TypeError:\s*not\s+a\s+function", re.IGNORECASE),
        "TypeError",
        "recoverable",
    ),
    # ReferenceError: xxx is not defined
    (
        re.compile(r"ReferenceError:\s*\S+\s+is\s+not\s+defined", re.IGNORECASE),
        "ReferenceError",
        "recoverable",
    ),
    # Failed to attach: process not found
    (
        re.compile(r"Failed\s+to\s+attach", re.IGNORECASE),
        "ProcessNotFound",
        "fatal",
    ),
    # Failed to enumerate processes
    (
        re.compile(r"Failed\s+to\s+enumerate\s+processes", re.IGNORECASE),
        "ConnectionError",
        "fatal",
    ),
    # timed out / timeout
    (
        re.compile(r"timed?\s*out|timeout", re.IGNORECASE),
        "TimeoutError",
        "fatal",
    ),
    # NativePointer / access violation
    (
        re.compile(
            r"access\s+violation\s+accessing\s+(0x[0-9a-fA-F]+)|Error:\s*access\s+violation",
            re.IGNORECASE,
        ),
        "NativePointer",
        "recoverable",
    ),
    # Generic TypeError catch-all (placed after specific TypeError patterns)
    (
        re.compile(r"TypeError:", re.IGNORECASE),
        "TypeError",
        "recoverable",
    ),
    # Generic ReferenceError catch-all
    (
        re.compile(r"ReferenceError:", re.IGNORECASE),
        "ReferenceError",
        "recoverable",
    ),
]

# Regex to extract hex addresses from error messages
_RE_HEX_ADDR = re.compile(r"0x[0-9a-fA-F]{4,}")

# Regex to extract JS line numbers like "<eval> line 42" or "frida_probe.js:42"
_RE_LINE_NUM = re.compile(
    r"(?:line\s+|\.js:|:)(\d+)",
    re.IGNORECASE,
)

# ─── Context window size ──────────────────────────────────────────────────────

# Number of lines to include before and after the matched RVA in the probe
_CONTEXT_LINES = 10


# ─── Public API ───────────────────────────────────────────────────────────────


def parse_frida_error(stderr: str) -> dict[str, Any]:
    """Parse a Frida stderr string and classify the error.

    Matches the error message against a priority-ordered list of regex
    patterns to determine ``error_type`` and ``severity``.  Also extracts
    any hex address (RVA) and JS line number found in the text.

    Args:
        stderr: Raw stderr output from a Frida session.

    Returns:
        dict with keys:
            - **error_type** (str) — One of ``TypeError``, ``ReferenceError``,
              ``NativePointer``, ``ProcessNotFound``, ``ConnectionError``,
              ``TimeoutError``, ``ScriptRuntimeError``, or ``UnknownError``.
            - **severity** (str) — ``"fatal"`` or ``"recoverable"``.
            - **rva** (str | None) — Extracted hex address (e.g. ``"0x1A4F0"``).
            - **line_number** (int | None) — JS script line number.
            - **context** (str) — Key sentences surrounding the error.
            - **raw_message** (str) — The full stderr text.
            - **suggestion** (str) — Human-readable recovery hint.
    """
    # Default fallback
    error_type = "UnknownError"
    severity = "fatal"

    if not stderr or not stderr.strip():
        return {
            "error_type": "UnknownError",
            "severity": "fatal",
            "rva": None,
            "line_number": None,
            "context": "",
            "raw_message": stderr,
            "suggestion": "No error output captured; check Frida CLI and device connection.",
        }

    # Classify: first pattern match wins
    for pattern, etype, sev in _ERROR_PATTERNS:
        if pattern.search(stderr):
            error_type = etype
            severity = sev
            break

    # Extract RVA (hex address)
    rva = _extract_rva(stderr)

    # Extract line number
    line_number = _extract_line_number(stderr)

    # Build contextual snippet: last ~300 chars trimmed to sentence boundaries
    context = _build_context(stderr)

    # Generate suggestion based on error type
    suggestion = _generate_suggestion(error_type, rva)

    return {
        "error_type": error_type,
        "severity": severity,
        "rva": rva,
        "line_number": line_number,
        "context": context,
        "raw_message": stderr,
        "suggestion": suggestion,
    }


def extract_hook_context(probe_code: str, error_rva: str) -> str:
    """Search ``probe_code`` for ``error_rva`` and return surrounding lines.

    Scans the probe source code for lines containing the given RVA
    string.  For each match, returns the matched line ± ``_CONTEXT_LINES``
    of surrounding code, joined into a single string.

    Args:
        probe_code: Full source code of the Frida probe script.
        error_rva: Hex address string to search for (e.g. ``"0x1A4F0"``).

    Returns:
        Context snippet as a string, or ``""`` if the RVA is not found.
    """
    if not error_rva or not probe_code:
        return ""

    lines = probe_code.splitlines()
    matched_blocks: list[str] = []

    for i, line in enumerate(lines):
        if error_rva in line:
            start = max(0, i - _CONTEXT_LINES)
            end = min(len(lines), i + _CONTEXT_LINES + 1)
            block = "\n".join(
                f"{j + 1:>4}: {lines[j]}" for j in range(start, end)
            )
            matched_blocks.append(block)

    if matched_blocks:
        return "\n\n---\n\n".join(matched_blocks)

    # Fallback: return last 30 lines if RVA not literally in source
    tail = lines[-30:] if len(lines) > 30 else lines
    return "\n".join(f"{i + 1:>4}: {line}" for i, line in enumerate(tail))


# ─── Internal helpers ─────────────────────────────────────────────────────────


def _extract_rva(stderr: str) -> str | None:
    """Extract the first hex address (0x...) from the error text."""
    m = _RE_HEX_ADDR.search(stderr)
    return m.group(0) if m else None


def _extract_line_number(stderr: str) -> int | None:
    """Extract a JS script line number from Frida error output."""
    m = _RE_LINE_NUM.search(stderr)
    return int(m.group(1)) if m else None


def _build_context(stderr: str, max_chars: int = 300) -> str:
    """Build a short contextual snippet from the tail of stderr.

    Trims to ``max_chars``, starting from the last newline boundary
    for readability.
    """
    text = stderr.strip()
    if len(text) <= max_chars:
        return text
    # Take the last max_chars characters
    snippet = text[-max_chars:]
    # Align to the first newline within the snippet so we start on a clean line
    nl = snippet.find("\n")
    if nl > 0 and nl < max_chars // 2:
        snippet = snippet[nl + 1:]
    return snippet


def _generate_suggestion(error_type: str, rva: str | None) -> str:
    """Produce a human-readable suggestion based on error classification."""
    suggestions: dict[str, str] = {
        "TypeError": (
            "Hook target returned null — the offset may be incorrect. "
            "Try adjusting the RVA by ±0x4 or adding a null-pointer guard."
        ),
        "ReferenceError": (
            "A referenced symbol or variable is undefined. "
            "Check that the symbol name is correct and exported by the target module."
        ),
        "NativePointer": (
            "Invalid memory access at the given address. "
            "The RVA likely points to non-executable or unmapped memory. "
            "Verify the base address and offset calculation."
        ),
        "ProcessNotFound": (
            "The target process was not found on the device. "
            "Ensure the app is running and the package name / PID is correct."
        ),
        "ConnectionError": (
            "Cannot connect to the Frida server. "
            "Check that frida-server is running on the device and USB debugging is enabled."
        ),
        "TimeoutError": (
            "The Frida session timed out. "
            "Increase the timeout or check for infinite loops in the Hook script."
        ),
        "ScriptRuntimeError": (
            "A runtime error occurred in the probe script. "
            "Review the error message and check for logic errors in the Hook code."
        ),
        "UnknownError": (
            "Unrecognized error. Review the raw message for details."
        ),
    }

    base = suggestions.get(error_type, suggestions["UnknownError"])
    if rva and error_type in ("TypeError", "NativePointer"):
        base += f" (RVA: {rva})"
    return base
