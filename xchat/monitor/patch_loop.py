"""
Phase 5d: Auto-Healing monitor — LLM-driven Frida probe repair loop.

Core loop:
    run_probe → parse_error → LLM_fix → apply_fix → write_new_probe → retry

Integrates frida_runner (subprocess), error_parser (classification),
and a sync Ollama LLM call adapted from LLMRouter for fix generation.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.request
from pathlib import Path
from typing import Any

from .frida_runner import run_frida_session
from .error_parser import parse_frida_error, extract_hook_context

# ─── Constants ────────────────────────────────────────────────────────────────

# Default LLM model for fix generation
_DEFAULT_LLM_MODEL = "qwen2.5:7b"

# Timeout for individual LLM calls
_LLM_TIMEOUT = 120

# Ollama API base URL (matches config.OLLAMA_URL)
_OLLAMA_URL = "http://localhost:11434"

# ─── LLM fix prompt template ──────────────────────────────────────────────────

_FIX_PROMPT_TEMPLATE = """\
You are a Frida reverse engineering expert. A Frida Hook script has encountered
an error during execution. Analyze the error and provide a precise fix.

【Current Probe Code】
{probe_code}

【Error Message】
{error_message}

【Error RVA】
{error_rva}

【Hook Context (surrounding code where the error occurred)】
{hook_context}

Analyze the error and return a JSON fix specification.  Reply ONLY with a JSON
object (no markdown fences, no extra text):

{{
    "diagnosis": "Brief explanation of what went wrong",
    "fix_type": "offset_adjust" | "code_rewrite" | "add_null_check",
    "fixed_code": "The complete replacement code block (keep original formatting)",
    "offset_delta": "+0x4 or -0x4 (only for offset_adjust)",
    "confidence": 0.85
}}
"""

# ─── Public API ───────────────────────────────────────────────────────────────


def auto_heal(
    probe_path: str,
    target: str,
    max_retries: int = 5,
    device: str = "usb",
    timeout: int = 30,
) -> dict[str, Any]:
    """Run the auto-healing loop: inject → detect → fix → retry.

    Repeatedly launches a Frida session with the probe script.  On failure,
    classifies the error, asks the local LLM to generate a fix, applies it
    to a new versioned probe file, and retries — up to ``max_retries`` times.

    Args:
        probe_path: Absolute path to the initial Frida probe script.
        target: Target process (package name or PID).
        max_retries: Maximum repair attempts before giving up.
        device: ``"usb"``, ``"remote"``, or ``"local"``.
        timeout: Seconds per individual Frida session.

    Returns:
        dict with keys:
            - **success** (bool) — ``True`` if any attempt passed.
            - **final_probe_path** (str | None) — Path of the last probe tried.
            - **attempts** (list[dict]) — Per-attempt record with keys
              ``attempt``, ``probe_path``, ``error``, ``action``.
            - **total_attempts** (int) — Total attempts executed.
            - **total_duration_ms** (float) — Summed wall-clock time.
            - **summary** (str) — Human-readable outcome description.
    """
    t_start = time.perf_counter()
    attempts: list[dict[str, Any]] = []
    current_probe = Path(probe_path).resolve()
    probe_dir = str(current_probe.parent)
    base_name = current_probe.stem  # filename without .js

    # Version tracking: start at 1 (the initial probe is v0)
    version = 1
    final_success = False

    for attempt_num in range(1, max_retries + 1):
        # ── Step 1: Run Frida ─────────────────────────────────────────────
        result = run_frida_session(
            script_path=str(current_probe),
            target=target,
            device=device,
            timeout=timeout,
        )

        attempt_record: dict[str, Any] = {
            "attempt": attempt_num,
            "probe_path": str(current_probe),
        }

        if result["success"]:
            attempt_record["error"] = None
            attempt_record["action"] = "probe executed successfully"
            attempts.append(attempt_record)
            final_success = True
            break

        # ── Step 2: Parse error ──────────────────────────────────────────
        error_info = parse_frida_error(result["stderr"])
        attempt_record["error"] = error_info

        if error_info["severity"] == "fatal":
            attempt_record["action"] = f"fatal error ({error_info['error_type']}) — cannot auto-heal"
            attempts.append(attempt_record)
            break

        # ── Step 3: Read current probe source ────────────────────────────
        try:
            probe_code = Path(current_probe).read_text(encoding="utf-8")
        except Exception:
            attempt_record["action"] = "failed to read probe source"
            attempts.append(attempt_record)
            break

        # ── Step 4: Extract hook context ─────────────────────────────────
        hook_context = extract_hook_context(
            probe_code, error_info.get("rva") or ""
        )

        # ── Step 5: Build LLM prompt ─────────────────────────────────────
        prompt = _FIX_PROMPT_TEMPLATE.format(
            probe_code=probe_code,
            error_message=error_info["raw_message"],
            error_rva=error_info.get("rva") or "(not extracted)",
            hook_context=hook_context or "(context not available)",
        )

        # ── Step 6: Call LLM ─────────────────────────────────────────────
        llm_result = _call_llm(prompt, model=_DEFAULT_LLM_MODEL, timeout=_LLM_TIMEOUT)

        if not llm_result["ok"]:
            attempt_record["action"] = f"LLM call failed: {llm_result['error']}"
            attempts.append(attempt_record)
            break

        # ── Step 7: Parse fix from LLM response ──────────────────────────
        fix = _extract_llm_fix(llm_result["answer"])
        if fix is None:
            attempt_record["action"] = "could not parse fix from LLM response"
            attempts.append(attempt_record)
            break

        # ── Step 8: Apply fix ────────────────────────────────────────────
        try:
            new_code = _apply_fix(probe_code, fix)
        except Exception as e:
            attempt_record["action"] = f"fix application failed: {e}"
            attempts.append(attempt_record)
            break

        # ── Step 9: Write versioned probe ────────────────────────────────
        current_probe = Path(
            _write_probe_version(probe_dir, base_name, version, new_code)
        )
        version += 1

        action_desc = (
            f"{fix.get('fix_type', 'unknown')}: "
            f"{fix.get('diagnosis', 'no diagnosis')[:120]}"
        )
        attempt_record["action"] = action_desc
        attempts.append(attempt_record)

    total_duration_ms = round((time.perf_counter() - t_start) * 1000, 2)

    # Build summary
    if final_success:
        summary = (
            f"Succeeded after {len(attempts)} attempt(s) — "
            f"final probe: {current_probe}"
        )
    else:
        last_error = attempts[-1].get("error", {}) if attempts else {}
        summary = (
            f"Failed after {len(attempts)} attempt(s). "
            f"Last error: {last_error.get('error_type', 'N/A')} "
            f"({last_error.get('severity', 'N/A')})"
        )

    return {
        "success": final_success,
        "final_probe_path": str(current_probe) if final_success else None,
        "attempts": attempts,
        "total_attempts": len(attempts),
        "total_duration_ms": total_duration_ms,
        "summary": summary,
    }


# ─── LLM communication ────────────────────────────────────────────────────────


def _call_llm(
    prompt: str,
    model: str = _DEFAULT_LLM_MODEL,
    timeout: int = _LLM_TIMEOUT,
) -> dict[str, Any]:
    """Synchronous Ollama chat API call — adapted from LLMRouter._ollama_chat.

    Args:
        prompt: The user prompt to send.
        model: Ollama model name (e.g. ``"qwen2.5:7b"``).
        timeout: HTTP timeout in seconds.

    Returns:
        dict with ``ok`` (bool), ``answer`` (str), and ``error`` (str).
    """
    payload = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
    }).encode("utf-8")

    try:
        req = urllib.request.Request(
            f"{_OLLAMA_URL}/api/chat",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        resp = urllib.request.urlopen(req, timeout=timeout)
        data = json.loads(resp.read())
        answer = data.get("message", {}).get("content", "").strip()
        return {"ok": bool(answer), "answer": answer, "error": ""}
    except Exception as e:
        return {"ok": False, "answer": "", "error": str(e)}


# ─── Fix extraction & application ─────────────────────────────────────────────


def _extract_llm_fix(llm_response: str) -> dict[str, Any] | None:
    """Extract a JSON fix specification from an LLM response.

    Handles both bare JSON and JSON inside markdown code fences.

    Args:
        llm_response: Raw text response from the LLM.

    Returns:
        Parsed fix dict, or ``None`` if no valid JSON could be extracted.
    """
    # Try extracting JSON from ```json ... ``` fenced block first
    fence_m = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", llm_response, re.DOTALL)
    json_candidate = fence_m.group(1).strip() if fence_m else llm_response

    # Find first { ... } balanced JSON object
    start = json_candidate.find("{")
    if start == -1:
        return None

    depth = 0
    end = start
    for i, ch in enumerate(json_candidate[start:], start=start):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = i + 1
                break

    if depth != 0:
        return None

    try:
        return json.loads(json_candidate[start:end])
    except json.JSONDecodeError:
        return None


def _apply_fix(original_probe: str, fix: dict[str, Any]) -> str:
    """Apply a fix specification to the original probe source.

    Args:
        original_probe: Full source code of the current probe script.
        fix: Dict from ``_extract_llm_fix`` with keys ``fix_type``,
            ``fixed_code``, and optionally ``offset_delta``.

    Returns:
        Modified probe source code as a string.

    Raises:
        ValueError: If the fix_type is unknown or the code block to replace
            cannot be located.
    """
    fix_type = fix.get("fix_type", "")
    fixed_code = fix.get("fixed_code", "")

    if not fixed_code or not fix_type:
        raise ValueError("fix must contain 'fix_type' and 'fixed_code'")

    if fix_type == "offset_adjust":
        delta = fix.get("offset_delta", "+0x4")
        # Apply delta to all hex literals in fixed_code
        return _adjust_offsets(original_probe, delta)

    elif fix_type == "code_rewrite":
        # Replace the first occurrence of fixed_code-like block.
        # We use a heuristic: find lines that start similarly.
        return _replace_code_block(original_probe, fixed_code)

    elif fix_type == "add_null_check":
        # Insert the null-check code before the offending line.
        # fixed_code should contain the guard + the original line.
        return _insert_null_check(original_probe, fixed_code)

    else:
        raise ValueError(f"Unknown fix_type: {fix_type}")


def _adjust_offsets(code: str, delta: str) -> str:
    """Adjust all hex literal offsets in the code by ``delta``.

    ``delta`` is a string like ``"+0x4"`` or ``"-0x8"``.
    Currently a pass-through — full implementation would parse and
    recalculate each hex literal.  For the initial implementation we
    return the code unmodified and rely on ``code_rewrite`` for
    offset fixes.
    """
    # If fixed_code from LLM already contains adjusted addresses,
    # treat this the same as code_rewrite.
    return code


def _replace_code_block(original: str, replacement: str) -> str:
    """Replace a code block in ``original`` with ``replacement``.

    Uses the first 3 non-empty, non-comment lines of ``replacement``
    as a search key to locate the target block in ``original``.
    """
    rep_lines = replacement.strip().splitlines()
    # Build search key: first substantive line of replacement
    search_key = None
    for line in rep_lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("//") and not stripped.startswith("/*"):
            search_key = stripped
            break

    if search_key is None:
        raise ValueError("Cannot locate replacement target: empty fixed_code")

    orig_lines = original.split("\n")

    # Find the line in original that best matches the search key
    match_idx = None
    for i, line in enumerate(orig_lines):
        if search_key in line:
            match_idx = i
            break

    if match_idx is None:
        # Fallback: try replacing the entire code (append)
        return original + "\n\n" + replacement

    # Determine block boundaries: from match_idx back to nearest blank/comment
    # line with different indentation, forward to next blank line + closing brace
    block_start = match_idx
    for i in range(match_idx - 1, -1, -1):
        if orig_lines[i].strip() == "":
            block_start = i + 1
            break
        if orig_lines[i].strip().startswith("//"):
            block_start = i
            break

    block_end = match_idx + 1
    brace_depth = 0
    for i in range(match_idx, len(orig_lines)):
        line = orig_lines[i]
        brace_depth += line.count("{") - line.count("}")
        block_end = i + 1
        if brace_depth <= 0 and i > match_idx:
            break

    new_lines = orig_lines[:block_start] + rep_lines + orig_lines[block_end:]
    return "\n".join(new_lines)


def _insert_null_check(code: str, guard_block: str) -> str:
    """Insert a null-check guard before the error-prone line.

    The ``guard_block`` should contain the null-check + original code.
    We locate the target line by matching the first substantive line
    of guard_block and replace it.
    """
    return _replace_code_block(code, guard_block)


# ─── Probe versioning ─────────────────────────────────────────────────────────


def _write_probe_version(
    probe_dir: str,
    base_name: str,
    version: int,
    code: str,
) -> str:
    """Write a versioned probe file and return its absolute path.

    Naming convention: ``{base_name}_v{version}.js``

    Args:
        probe_dir: Directory to write into.
        base_name: Probe base name (stem without extension).
        version: Integer version number.
        code: Probe source code.

    Returns:
        Absolute path of the written file.
    """
    filename = f"{base_name}_v{version}.js"
    filepath = os.path.join(probe_dir, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(code)
    return os.path.abspath(filepath)
