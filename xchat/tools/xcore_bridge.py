"""
XCore Bridge: wraps xcore CLI as Python-callable functions.

Provides a clean Python API over the xcore C++/Node.js toolchain,
intended for use by llm_router.py and mcp_server.py.

All functions use subprocess with timeout, automatic JSON parsing,
and clear exception reporting on failure.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

# ─── Path resolution ─────────────────────────────────────────────────────────

_TOOLS_DIR = Path(__file__).resolve().parent            # xchat/tools/
_XCHAT_DIR = _TOOLS_DIR.parent                          # xchat/
_XCORE_ROOT = _XCHAT_DIR.parent                         # xcore/ (project root)
_NODE_CMD = "node"                                      # assumes node on PATH


def _find_node() -> str:
    """Return the best-available node executable path."""
    try:
        result = subprocess.run(
            ["where", "node"],
            capture_output=True, text=True, timeout=5,
            shell=True,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip().splitlines()[0]
    except Exception:
        pass
    return _NODE_CMD


def _run_node(
    script_rel: str,
    args: list[str],
    *,
    timeout: int = 120,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a Node.js script from xcore root with unified error handling."""
    node = _find_node()
    script_path = _XCORE_ROOT / script_rel
    cmd = [node, str(script_path)] + args
    cwd_str = str(cwd or _XCORE_ROOT)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd_str,
            encoding="utf-8",
            errors="ignore",
        )
        return proc
    except subprocess.TimeoutExpired:
        raise RuntimeError(
            f"Node script '{script_rel}' timed out after {timeout}s"
        )
    except FileNotFoundError:
        raise RuntimeError(
            f"Node.js not found. Ensure 'node' is on PATH."
        )


def _extract_json(text: str) -> dict[str, Any]:
    """Extract the first balanced JSON object from mixed stdout/stderr output."""
    # Strip \r and find first '{'
    cleaned = text.replace("\r", "")
    start = cleaned.find("{")
    if start == -1:
        raise RuntimeError(f"No JSON object found in output:\n{cleaned[:500]}")

    depth = 0
    i = start
    for ch in cleaned[start:]:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                break
        i += 1

    if depth != 0:
        raise RuntimeError(
            f"Unbalanced JSON braces in output:\n{cleaned[start:][:500]}"
        )

    json_str = cleaned[start:i + 1]
    try:
        return json.loads(json_str)
    except json.JSONDecodeError as e:
        raise RuntimeError(
            f"Failed to parse JSON: {e}\nOutput:\n{json_str[:500]}"
        )


def _extract_json_file(path: Path) -> dict[str, Any]:
    """Read and parse a JSON file."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# ─── Public API ───────────────────────────────────────────────────────────────


def run_native_scan(so_path: str) -> dict[str, Any]:
    """Execute xcore native --so scan on a shared library.

    Delegates to ``modules/native/target_scanner.js`` internally and
    returns the parsed scan-result JSON.

    Args:
        so_path: Absolute path to the .so / .dll file to scan.

    Returns:
        dict with keys: target, arch, final_score, verdict, layers, xrefs, ...

    Raises:
        RuntimeError: On subprocess failure or JSON parse error.
    """
    if not os.path.isfile(so_path):
        raise FileNotFoundError(f"SO file not found: {so_path}")

    proc = _run_node(
        "modules/native/target_scanner.js",
        ["--so", os.path.abspath(so_path), "--json"],
    )

    combined = proc.stdout + proc.stderr
    result = _extract_json(combined)
    return result


def run_web_pipeline(url: str, entry: str | None = None) -> dict[str, Any]:
    """Execute the Node.js deobfuscation pipeline against a web target.

    Note:
        The web pipeline (xcore pipeline) is not yet fully integrated
        at the C++ level (see main.cpp Phase 3e stub).  This function
        provides the scaffolding and will be wired once the pipeline is
        exposed as a standalone Node entry point.

    Args:
        url: Target URL or JS bundle URL.
        entry: Optional entry function name (e.g. ``"window.ParamsSign.sign"``).

    Returns:
        dict with pipeline result (TBD).

    Raises:
        NotImplementedError: Pipeline endpoint is not yet available.
    """
    raise NotImplementedError(
        "Web pipeline (xcore pipeline) is not yet integrated. "
        "See main.cpp Phase 3e stub for status."
    )


def run_apk_pipeline(
    apk_path: str,
    output_dir: str | None = None,
) -> dict[str, Any]:
    """Run the full Phase 4c native pipeline against an APK.

    Executes ``node modules/native/pipeline_native.js --apk <apk_path>``
    and returns the contents of the generated ``summary.json``.

    Pipeline stages:  Shell classification → .so extraction →
    target scanning → Frida probe generation.

    Args:
        apk_path: Absolute path to the .apk file.
        output_dir: Optional output directory.  Defaults to
            ``<apk_dir>/xcore_pipeline_output/``.

    Returns:
        dict with keys: pipeline, timestamp, shell, targets_scanned,
        probes_generated, so_targets, probes.

    Raises:
        FileNotFoundError: If ``apk_path`` does not exist.
        RuntimeError: On subprocess failure or JSON parse error.
    """
    if not os.path.isfile(apk_path):
        raise FileNotFoundError(f"APK file not found: {apk_path}")

    args = ["--apk", os.path.abspath(apk_path)]
    if output_dir:
        args.extend(["--output-dir", os.path.abspath(output_dir)])

    proc = _run_node("modules/native/pipeline_native.js", args)

    # pipeline_native.js writes summary.json to output_dir and prints a
    # final JSON status object to stdout.  Parse that to locate summary.
    combined = proc.stdout + proc.stderr

    # Try to find the final status JSON first
    try:
        status = _extract_json(combined)
    except RuntimeError:
        status = {}

    summary_file = status.get("summary_file")
    if summary_file and os.path.isfile(summary_file):
        return _extract_json_file(Path(summary_file))

    # Fallback: search for summary.json in output dir
    out_dir = output_dir or os.path.join(
        os.path.dirname(os.path.abspath(apk_path)),
        "xcore_pipeline_output",
    )
    summary_path = Path(out_dir) / "summary.json"
    if summary_path.is_file():
        return _extract_json_file(summary_path)

    # Last resort: return parsed status
    if status:
        return status

    raise RuntimeError(
        f"Pipeline completed but no summary.json found.\n"
        f"stdout:\n{proc.stdout[:500]}"
    )


def generate_frida_probe(
    scan_json_path: str,
    output_dir: str | None = None,
) -> str:
    """Generate a Frida probe script from a Phase 4b scan result.

    Calls ``node modules/native/probe_generator.js --scan-result <scan.json>``
    and returns the absolute path of the generated ``.js`` script.

    Args:
        scan_json_path: Path to the target_scanner JSON output.
        output_dir: Optional output directory for the generated script.
            Defaults to the same directory as ``scan_json_path``.

    Returns:
        Absolute path to the generated ``.js`` Frida probe script.

    Raises:
        FileNotFoundError: If ``scan_json_path`` does not exist.
        RuntimeError: On subprocess failure.
    """
    if not os.path.isfile(scan_json_path):
        raise FileNotFoundError(f"Scan JSON not found: {scan_json_path}")

    scan_abs = os.path.abspath(scan_json_path)
    args = ["--scan-result", scan_abs]

    if output_dir:
        out_abs = os.path.abspath(output_dir)
        os.makedirs(out_abs, exist_ok=True)
        out_script = os.path.join(out_abs, "frida_probe.js")
    else:
        out_script = os.path.join(
            os.path.dirname(scan_abs), "frida_probe.js"
        )

    args.extend(["--out", out_script])

    proc = _run_node("modules/native/probe_generator.js", args)

    # probe_generator.js writes the script to --out and prints stats to stderr
    if not os.path.isfile(out_script):
        raise RuntimeError(
            f"probe_generator.js completed but output not found at "
            f"{out_script}\nStderr:\n{proc.stderr[:500]}"
        )

    return out_script


def classify_shell(apk_path: str) -> dict[str, Any]:
    """Quick shell classification for an APK (passive mode).

    Calls ``node modules/native/shell_classifier.js --apk <apk_path>
    --mode passive --json`` and returns the parsed result.

    Args:
        apk_path: Absolute path to the .apk file.

    Returns:
        dict with keys: apk, package_name, shell (name/confidence/evidence),
        recommendation, next_step.

    Raises:
        FileNotFoundError: If ``apk_path`` does not exist.
        RuntimeError: On subprocess failure or JSON parse error.
    """
    if not os.path.isfile(apk_path):
        raise FileNotFoundError(f"APK file not found: {apk_path}")

    proc = _run_node(
        "modules/native/shell_classifier.js",
        ["--apk", os.path.abspath(apk_path), "--mode", "passive", "--json"],
    )

    # shell_classifier exits non-zero for heavy_shell but still prints JSON
    combined = proc.stdout + proc.stderr
    if not combined.strip():
        raise RuntimeError(
            f"shell_classifier.js produced no output for {apk_path}"
        )

    result = _extract_json(combined)
    return result
