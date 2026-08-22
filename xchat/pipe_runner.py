"""
XCore pipe runner: calls xcore.exe pipe/native and parses output.

Async wrapper around subprocess for both JS pipeline and Native Scanner.
"""

import asyncio
import json as _json
import os
import re as _re
import subprocess

from .config import XCORE_BIN, RULES_PATH, FINGERPRINTS_DIR, BASE_DIR


async def run_xcore_native(file_path: str, mode: str = "so") -> dict:
    """Run xcore native scan on a SO/DLL/APK file.

    Calls ``xcore native --so <path> --json`` (or ``--apk``) and
    returns structured result compatible with xchat's scan_context.
    """
    if not XCORE_BIN.exists():
        return {"error": f"xcore.exe not found at {XCORE_BIN}", "hits": []}

    flag = "--so" if mode == "so" else "--apk"

    try:
        loop = asyncio.get_running_loop()

        def _run():
            env = os.environ.copy()
            tools_path = r"C:\tools"
            env["PATH"] = tools_path + os.pathsep + env.get("PATH", "")
            proc = subprocess.run(
                [str(XCORE_BIN), "native", flag, file_path, "--json"],
                capture_output=True,
                timeout=120,
                cwd=str(BASE_DIR),
                env=env,
            )
            return proc.stdout.decode("utf-8", errors="ignore"), proc.stderr.decode("utf-8", errors="ignore")

        stdout, stderr = await loop.run_in_executor(None, _run)
        result = _parse_native_output(stdout, stderr)
        result["file_path"] = file_path
        result["type"] = "native"
        return result

    except subprocess.TimeoutExpired:
        return {"error": "xcore native timed out (120s)", "hits": []}
    except Exception as e:
        return {"error": str(e), "hits": []}


def _parse_native_output(stdout: str, stderr: str) -> dict:
    """Parse xcore native --so/--apk text output into structured dict.

    Detects output format automatically: SO target-scan (Phase 4b/c) or
    APK shell-classifier (Phase 4a).
    """
    is_shell_classifier = "Shell" in stdout and "Class" in stdout

    if is_shell_classifier:
        return _parse_shell_classifier(stdout, stderr)

    result: dict = {
        "file_path": "",
        "target": "",
        "arch": "",
        "final_score": 0.0,
        "verdict": "clean",
        "algorithm": "unknown",
        "layers": {},
        "xrefs": [],
        "hits": [],
        "stderr": stderr.strip(),
    }

    # Top-level fields: "Key : Value"
    for line in stdout.split("\n"):
        line = line.strip()
        m = _re.match(r"^(Target|Arch|Final score|Verdict|Algorithm)\s*:\s*(.+)$", line)
        if m:
            key = m.group(1).lower().replace(" ", "_")
            val = m.group(2).strip()
            if key == "target":
                result["target"] = val
                result["hits"].append({"target": val})
            elif key == "arch":
                result["arch"] = val
            elif key == "final_score":
                try:
                    result["final_score"] = float(val)
                except ValueError:
                    pass
            elif key == "verdict":
                result["verdict"] = val
            elif key == "algorithm":
                result["algorithm"] = val

    # Layer scores
    layer_section = False
    for line in stdout.split("\n"):
        line = line.strip()
        if "Layer scores:" in line:
            layer_section = True
            continue
        if layer_section and not line:
            break
        if layer_section:
            m = _re.match(
                r"^(L\d_[a-z_]+)\s*:\s*score=([\d.]+)\s+hits=(\d+)\s*\[(.*)\]$",
                line,
            )
            if m:
                name = m.group(1)
                score = float(m.group(2))
                hits_count = int(m.group(3))
                hits_str = m.group(4).strip()
                hits_list = [h.strip() for h in hits_str.split(",") if h.strip()]
                result["layers"][name] = {
                    "score": score,
                    "hits": hits_list,
                    "hits_count": hits_count,
                }

    # Xrefs
    for line in stdout.split("\n"):
        line = line.strip()
        if "String Xrefs:" in line:
            continue
        m = _re.match(r"^(\S+)\s+@\s+(\S+)\s+in\s+(\S+)$", line)
        if m:
            result["xrefs"].append({
                "symbol": m.group(1),
                "offset": m.group(2),
                "section": m.group(3),
            })

    # If layers had any meaningful hits, create a hit entry for LLM context
    if result["layers"]:
        algo_hints = []
        for layer_name, layer_data in result["layers"].items():
            if layer_data.get("hits"):
                algo_hints.extend(layer_data["hits"])
        if algo_hints:
            result["hits"].append({
                "id": "native-scan",
                "algos": algo_hints[:10],
                "sim": result["final_score"],
                "status": "soft",
            })

    return result


def _parse_shell_classifier(stdout: str, stderr: str) -> dict:
    """Parse Phase 4a shell classifier output (APK mode)."""
    result: dict = {
        "file_path": "",
        "package": "",
        "shell": "",
        "confidence": "",
        "shell_class": "",
        "next_step": "",
        "frida_script": "",
        "spawn_cmd": "",
        "attach_cmd": "",
        "evidence": [],
        "hits": [],
        "stderr": stderr.strip(),
    }

    field_map = {
        "APK": "apk_path",
        "Package": "package",
        "Shell": "shell",
        "Confidence": "confidence",
        "Class": "shell_class",
        "Next step": "next_step",
        "Frida script": "frida_script",
        "Spawn cmd": "spawn_cmd",
        "Attach cmd": "attach_cmd",
    }

    evidence_section = False
    for line in stdout.split("\n"):
        line_stripped = line.strip()
        if evidence_section:
            if line_stripped.startswith("[") and "]" in line_stripped:
                m = _re.match(r"^\[(\w+)\]\s+(.+)$", line_stripped)
                if m:
                    result["evidence"].append({
                        "type": m.group(1),
                        "value": m.group(2),
                    })
            continue
        if "Evidence:" in line_stripped:
            evidence_section = True
            continue
        for field_name, key in field_map.items():
            if line_stripped.startswith(field_name):
                val = line_stripped.split(":", 1)[1].strip() if ":" in line_stripped else ""
                result[key] = val
                break

    # Build hits for LLM context
    result["hits"].append({
        "id": "shell-classify",
        "shell": result["shell"],
        "confidence": result["confidence"],
        "shell_class": result["shell_class"],
        "next_step": result["next_step"],
        "evidence_count": len(result["evidence"]),
    })

    return result


async def run_xcore_pipe(file_path: str) -> dict:
    """Run xcore pipe on a file, return structured scan result."""
    if not XCORE_BIN.exists():
        return {"error": f"xcore.exe not found at {XCORE_BIN}", "hits": []}
    if not RULES_PATH.exists():
        return {"error": f"rules.json not found at {RULES_PATH}", "hits": []}

    try:
        loop = asyncio.get_running_loop()

        def _run():
            with open(file_path, "rb") as f:
                data = f.read(262144)  # first 256KB (was 64KB)
            proc = subprocess.run(
                [str(XCORE_BIN), "pipe", str(RULES_PATH),
                 "--fingerprints-dir", str(FINGERPRINTS_DIR),
                 "--model", "qwen2.5:3b"],
                input=data,
                capture_output=True,
                timeout=120,
                cwd=str(BASE_DIR),
            )
            return proc.stdout.decode("utf-8", errors="ignore"), proc.stderr.decode("utf-8", errors="ignore")

        stdout, stderr = await loop.run_in_executor(None, _run)
        result = _parse_xcore_output(stdout, stderr)
        result["file_path"] = file_path
        return result

    except subprocess.TimeoutExpired:
        return {"error": "xcore pipe timed out (120s)", "hits": []}
    except Exception as e:
        return {"error": str(e), "hits": []}


def _parse_xcore_output(stdout: str, stderr: str) -> dict:
    """Parse xcore pipe text output into structured dict."""
    hits = []
    lines = stdout.strip().split("\n")
    for line in lines:
        line = line.strip()
        if not line:
            continue
        # Skip summary lines (arrow + Case # indicates duplicate)
        if "->" in line:
            continue
        hit = {}
        # Extract case id: match #NNN or [#NNN
        m = _re.search(r'#(\d+)', line)
        if m:
            hit["id"] = m.group(1)
        # Extract sim value
        m = _re.search(r'sim=([\d.]+)', line)
        if m:
            hit["sim"] = float(m.group(1))
        # Extract algo list: match ["...", "..."] as JSON array
        m = _re.search(r'\["[^"]*"(?:,"[^"]*")*\]', line)
        if m:
            try:
                hit["algos"] = _json.loads(m.group(0))
            except Exception:
                pass
        # Status
        if "Hard-lock" in line or "w5=LOCK" in line:
            hit["status"] = "hard-lock"
        elif "FAILED" in line:
            hit["status"] = "failed"
        elif "TIMEOUT" in line:
            hit["status"] = "timeout"

        if hit:
            hits.append(hit)

    return {
        "file_path": "",
        "hits": hits,
        "stderr": stderr.strip(),
    }
