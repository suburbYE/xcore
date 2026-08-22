"""
Phase 5c: Multi-source input parser and router.

Parses terminal input — detects file-drops (drag-and-drop) vs natural
language commands — and routes each request to the correct handler.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any

# Supported file extensions for auto-detect
_FILE_EXTENSIONS = frozenset({
    ".apk", ".so", ".dll", ".json",
    ".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp",
    ".txt", ".log",
})

_SCAN_EXTENSIONS = frozenset({".apk", ".so", ".dll"})
_JSON_EXTENSIONS = frozenset({".json"})
_IMAGE_EXTENSIONS = frozenset({".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp"})


# ─── Dataclasses ──────────────────────────────────────────────────────────────

@dataclass
class ParsedInput:
    """Result of parsing a raw terminal input line."""
    input_type: str                          # "file" | "text"
    file_paths: list[str] = field(default_factory=list)
    text: str = ""


@dataclass
class CommandResult:
    """Result of routing a parsed input to a handler."""
    result_type: str                         # "scan" | "shell_classify" | "probe" | "text" | "error"
    data: dict[str, Any] | str | None = None


# ─── Path extraction helpers ──────────────────────────────────────────────────

_QUOTED_PATH_RE = re.compile(
    r"""(['"])(.*?)\1""",                   # single- or double-quoted
)

_EXT_RE = re.compile(
    r'[A-Za-z0-9_\-\\/\s]\.(apk|so|dll|json|png|jpg|jpeg|bmp|gif|webp|txt|log)',
    re.IGNORECASE,
)


def _deduplicate_paths(paths: list[str]) -> list[str]:
    """Remove duplicate paths, keeping the first occurrence order."""
    seen: set[str] = set()
    out: list[str] = []
    for p in paths:
        norm = os.path.normpath(p)
        if norm not in seen:
            seen.add(norm)
            out.append(norm)
    return out


def _extract_quoted_parts(raw: str) -> list[str]:
    """Extract quoted substrings and treat them as potential file paths."""
    paths: list[str] = []
    for m in _QUOTED_PATH_RE.finditer(raw):
        inner = m.group(2)
        if os.path.exists(inner):
            paths.append(inner)
    return paths


def _extract_unquoted_paths(raw: str) -> list[str]:
    """Extract bare (unquoted) paths that look like real file references."""
    # Remove already-handled quoted sections first
    cleaned = _QUOTED_PATH_RE.sub(" ", raw)
    # Split on whitespace
    candidates = cleaned.split()
    paths: list[str] = []
    for cand in candidates:
        cand = cand.strip()
        if not cand:
            continue
        # Quick filter: must contain a recognized extension
        if _EXT_RE.search(cand):
            if os.path.exists(cand):
                paths.append(cand)
    return paths


# ─── Public API ───────────────────────────────────────────────────────────────


def parse_input(raw: str) -> ParsedInput:
    """Parse a raw terminal input line into a ``ParsedInput``.

    Detects file paths introduced via drag-and-drop (which may be quoted
    by the shell) and separates them from the remaining natural-language
    text.

    Args:
        raw: The raw input string from the terminal.

    Returns:
        A ``ParsedInput`` with ``input_type="file"`` if any file paths
        were detected; otherwise ``"text"`` with the whole input as text.
    """
    raw = raw.strip()
    if not raw:
        return ParsedInput(input_type="text", text=raw)

    # 1. Extract quoted paths (shell-quoted by drag-and-drop)
    file_paths = _extract_quoted_parts(raw)

    # 2. Extract unquoted paths
    file_paths += _extract_unquoted_paths(raw)

    file_paths = _deduplicate_paths(file_paths)

    if not file_paths:
        return ParsedInput(input_type="text", text=raw)

    # Remove the path substrings from raw to get remaining text
    text = raw
    for fp in file_paths:
        text = text.replace(f'"{fp}"', " ")
        text = text.replace(f"'{fp}'", " ")
        text = text.replace(fp, " ")
    text = " ".join(text.split()).strip()

    return ParsedInput(input_type="file", file_paths=file_paths, text=text)


async def route_input(
    parsed: ParsedInput,
    session: Any = None,
) -> CommandResult:
    """Route a parsed input to the correct handler.

    Routing rules:

    * ``.apk`` → classify_shell() then run_apk_pipeline()
    * ``.so`` / ``.dll`` → run_native_scan()
    * ``.json`` (scan result) → generate_frida_probe()
    * image files → unsupported (Vision Phase)
    * pure text → LLM router (if session available) or text echo

    Args:
        parsed: The parsed input from ``parse_input()``.
        session: Optional ``XChatSession`` instance for LLM routing.

    Returns:
        A ``CommandResult`` with ``result_type`` and ``data``.
    """
    from xchat.tools.xcore_bridge import (
        classify_shell,
        generate_frida_probe,
        run_apk_pipeline,
        run_native_scan,
    )

    if parsed.input_type != "file":
        # Pure text → route to LLM if session is provided
        if session is not None and hasattr(session, "ask"):
            try:
                answer = await session.router.ask_3b(parsed.text)
                return CommandResult(result_type="text", data=answer)
            except Exception as e:
                return CommandResult(
                    result_type="error",
                    data=f"LLM routing failed: {e}",
                )
        return CommandResult(result_type="text", data=parsed.text)

    results: list[dict[str, Any]] = []
    has_error = False
    error_msgs: list[str] = []

    for fp in parsed.file_paths:
        if not os.path.isfile(fp):
            error_msgs.append(f"File not found: {fp}")
            has_error = True
            continue

        ext = os.path.splitext(fp)[1].lower()

        # ── .apk ────────────────────────────────────────────────────────
        if ext == ".apk":
            try:
                shell = classify_shell(fp)
            except Exception as e:
                error_msgs.append(f"Shell classify failed for {fp}: {e}")
                has_error = True
                continue

            try:
                pipeline = run_apk_pipeline(fp)
            except Exception as e:
                error_msgs.append(f"APK pipeline failed for {fp}: {e}")
                has_error = True
                continue

            results.append({
                "file": fp,
                "type": "apk",
                "shell": shell,
                "pipeline": pipeline,
            })

        # ── .so / .dll ───────────────────────────────────────────────────
        elif ext in (".so", ".dll"):
            try:
                scan = run_native_scan(fp)
            except Exception as e:
                error_msgs.append(f"Native scan failed for {fp}: {e}")
                has_error = True
                continue

            results.append({
                "file": fp,
                "type": "native",
                "scan": scan,
            })

        # ── .json ────────────────────────────────────────────────────────
        elif ext == ".json":
            try:
                probe_path = generate_frida_probe(fp)
            except Exception as e:
                error_msgs.append(f"Frida probe generation failed for {fp}: {e}")
                has_error = True
                continue

            results.append({
                "file": fp,
                "type": "probe",
                "probe_path": probe_path,
            })

        # ── Image ────────────────────────────────────────────────────────
        elif ext in _IMAGE_EXTENSIONS:
            error_msgs.append(
                f"Vision analysis is not supported yet. "
                f"(Phase 5a will implement image/Vision support.)"
            )
            has_error = True

        # ── Unknown ──────────────────────────────────────────────────────
        else:
            supported = ", ".join(sorted(_SCAN_EXTENSIONS | _JSON_EXTENSIONS))
            error_msgs.append(
                f"Unsupported file type '{ext}'. "
                f"Supported: {supported}"
            )
            has_error = True

    if not results and has_error:
        return CommandResult(
            result_type="error",
            data="\n".join(error_msgs),
        )

    # Build composite result
    data: dict[str, Any] = {"results": results}
    if error_msgs:
        data["warnings"] = error_msgs

    # Determine primary result_type
    types = {r["type"] for r in results}
    if "apk" in types or "native" in types:
        return CommandResult(result_type="scan", data=data)
    if "probe" in types:
        return CommandResult(result_type="probe", data=data)

    return CommandResult(result_type="scan", data=data)
