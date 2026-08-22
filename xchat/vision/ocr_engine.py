"""
Phase 5a: Network capture OCR — extract structured data from proxy tool
screenshots (Charles / Wireshark / Postman / Burp Suite).

Capabilities:
    - HTTP header / body parameter extraction (focus on signing fields)
    - Base64 / hex string detection
    - Shannon entropy annotation for high-entropy fields
    - Slider / click CAPTCHA coordinate extraction

Design note: llm_router currently does not support vision natively;
this module uses _vision_client as a standalone vision call path.
Once llm_router integrates vision providers, the call path can be
refactored to route through it.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter

from ._vision_client import call_vision


# ─── Shannon Entropy ──────────────────────────────────────────────────────────


def calculate_shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy for a given string.

    Shannon entropy measures the randomness / information density of a
    byte sequence.  High entropy (> 5.5) often indicates encrypted or
    compressed data — a strong signal for crypto-related fields.

    Args:
        data: The string to analyze (e.g. a header value, base64 blob).

    Returns:
        Float in [0.0, 8.0] (bits per byte).
    """
    if not data:
        return 0.0

    freq = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def _annotate_entropy(items: list[dict], key_field: str = "value") -> list[dict]:
    """Annotate a list of dicts with entropy and high_entropy flags."""
    for item in items:
        val = item.get(key_field, "") or ""
        ent = calculate_shannon_entropy(val)
        item["entropy"] = round(ent, 1)
        item["high_entropy"] = ent > 5.5
    return items


# ─── Network Capture Extraction ───────────────────────────────────────────────


def extract_network_capture(image_path: str, provider: str = "auto") -> dict:
    """Extract structured HTTP request data from a proxy tool screenshot.

    Accepts screenshots from Charles / Wireshark / Postman / Burp Suite
    and uses a cloud VLM to extract headers, body params, and encoded
    strings.  Each header / param value is annotated with Shannon entropy.

    Args:
        image_path: Absolute path to the screenshot (.png / .jpg).
        provider: VLM provider — ``"auto"`` (try Gemini → OpenAI),
            ``"gemini"``, ``"openai"``, or ``"deepseek"``.

    Returns:
        dict with keys:
            - ``headers``: list of {name, value, entropy, high_entropy}
            - ``method``: HTTP method (GET/POST/...)
            - ``url``: request URL
            - ``body_type``: "form" | "json" | "raw" | null
            - ``body_params``: list of {key, value}
            - ``base64_strings``: detected base64-encoded blobs
            - ``hex_strings``: detected hex strings
            - ``raw_text``: full OCR text from the screenshot

    Raises:
        RuntimeError: If the VLM call fails or no credentials are configured.
        FileNotFoundError: If ``image_path`` does not exist.
    """
    prompt = (
        "You are analyzing a screenshot from a network proxy tool (Charles / "
        "Wireshark / Postman / Burp Suite).  Extract EVERYTHING into a single "
        "JSON object.  Follow these rules strictly:\n\n"
        "1. Focus on HTTP request headers — especially custom signing headers "
        "like X-Sign, X-S, X-Token, X-Auth, sign, signature, token, nonce, "
        "timestamp, Authorization.  Capture the EXACT header value character by "
        "character.\n"
        "2. Identify the HTTP method (GET / POST / PUT / DELETE) and the full URL.\n"
        "3. For the request body: classify as 'form', 'json', 'raw', or null if "
        "no body is visible.  Extract every parameter key-value pair.\n"
        "4. Scan ALL visible text for base64-encoded strings.  A base64 string "
        "typically ends with '=' padding and contains [A-Za-z0-9+/].  List them.\n"
        "5. Scan ALL visible text for hex strings (even-length, [0-9a-fA-F]+).  "
        "List strings 8+ characters long.\n"
        "6. Provide the FULL raw text OCR of the entire screenshot as 'raw_text'.\n"
        "7. Return ONLY valid JSON — no markdown fences, no explanations.\n"
        "8. If a field has no value, use an empty array [] or null.\n\n"
        "Output schema:\n"
        "{\n"
        '  "headers": [{"name": "...", "value": "..."}],\n'
        '  "method": "POST",\n'
        '  "url": "https://...",\n'
        '  "body_type": "json",\n'
        '  "body_params": [{"key": "...", "value": "..."}],\n'
        '  "base64_strings": ["..."],\n'
        '  "hex_strings": ["..."],\n'
        '  "raw_text": "..."\n'
        "}"
    )

    raw = call_vision(prompt, image_path, provider)

    # Parse JSON — VLM may wrap in ```json fences
    raw = raw.strip()
    if raw.startswith("```"):
        # Remove opening fence line
        raw = re.sub(r"^```[a-zA-Z]*\s*", "", raw)
        # Remove closing fence
        raw = re.sub(r"\s*```$", "", raw)

    result = json.loads(raw)

    # Annotate header values with entropy
    if "headers" in result:
        result["headers"] = _annotate_entropy(result["headers"], key_field="value")

    # Annotate base64 strings
    if "base64_strings" in result:
        result["base64_strings"] = _annotate_entropy(
            [{"value": s} for s in result["base64_strings"]], key_field="value"
        )
        # Flatten back to annotated list with entropy
        annotated = result["base64_strings"]
        result["base64_strings"] = annotated

    # Ensure all expected keys exist
    defaults = {
        "headers": [],
        "method": None,
        "url": None,
        "body_type": None,
        "body_params": [],
        "base64_strings": [],
        "hex_strings": [],
        "raw_text": "",
    }
    for k, v in defaults.items():
        result.setdefault(k, v)

    return result


# ─── CAPTCHA Coordinate Extraction ────────────────────────────────────────────


def extract_captcha_coordinates(image_path: str, provider: str = "auto") -> dict:
    """Extract slider / click CAPTCHA coordinates from a screenshot.

    Designed for mobile-app-style slider verification (滑块验证码) and
    click-based CAPTCHAs.  Returns normalized coordinates and a trajectory
    hint suitable for automated slider solving.

    Args:
        image_path: Absolute path to the CAPTCHA screenshot (.png / .jpg).
        provider: VLM provider — ``"auto"`` (try Gemini → OpenAI),
            ``"gemini"``, ``"openai"``, or ``"deepseek"``.

    Returns:
        dict with keys:
            - ``type``: "slider" or "click"
            - ``slider_x``: normalized X coordinate of the gap (integer)
            - ``slider_y``: normalized Y coordinate of the gap (integer)
            - ``trajectory_hint``: human-readable trajectory suggestion
            - ``confidence``: float [0.0, 1.0]

    Raises:
        RuntimeError: If the VLM call fails or no credentials are configured.
        FileNotFoundError: If ``image_path`` does not exist.
    """
    prompt = (
        "You are analyzing a slider verification CAPTCHA (滑块验证码) screenshot "
        "from a mobile app reverse-engineering session.  Your task: identify the "
        "slider gap position and provide coordinates for automated solving.\n\n"
        "Instructions:\n"
        "1. Determine if this is a 'slider' (drag-to-fill-gap) or 'click' "
        "(tap-the-target) CAPTCHA.\n"
        "2. For 'slider': locate the gap (缺口) — the missing puzzle piece area "
        "in the background image.  Report the CENTER X coordinate of the gap "
        "(in pixels) as 'slider_x'.  Also report the Y coordinate.\n"
        "3. For 'click': locate the target area and report its center coordinates.\n"
        "4. Provide a 'trajectory_hint' describing how a human would slide: "
        "e.g. 'accelerate quickly then decelerate, pause ~10px before the gap, "
        "final slow nudge'.\n"
        "5. Give a confidence score 0.0–1.0 reflecting how certain you are.\n"
        "6. Return ONLY valid JSON — no markdown fences, no explanations.\n\n"
        "Output schema:\n"
        "{\n"
        '  "type": "slider",\n'
        '  "slider_x": 320,\n'
        '  "slider_y": 160,\n'
        '  "trajectory_hint": "accelerate quickly then decelerate, pause ~10px before gap",\n'
        '  "confidence": 0.92\n'
        "}"
    )

    raw = call_vision(prompt, image_path, provider)

    # Parse JSON — VLM may wrap in ```json fences
    raw = raw.strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```[a-zA-Z]*\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)

    result = json.loads(raw)

    # Type normalization
    if result.get("type", "").lower() not in ("slider", "click"):
        result["type"] = "slider"  # default

    # Ensure numeric fields
    for key in ("slider_x", "slider_y"):
        if key in result and result[key] is not None:
            result[key] = int(result[key])
        else:
            result[key] = 0

    if "confidence" in result and result["confidence"] is not None:
        result["confidence"] = float(result["confidence"])
    else:
        result["confidence"] = 0.0

    return result
