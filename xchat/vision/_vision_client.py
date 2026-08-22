"""
Internal vision client: base64 encoding + multi-provider VLM HTTP calls.

Used by ocr_engine.py and cfg_parser.py to send images to cloud VLM
providers (OpenAI / Gemini / DeepSeek).  This module is NOT part of the
public API — external callers should use the domain-specific wrappers.

NOTE: llm_router.py does NOT yet support vision natively.  This module
provides standalone vision capabilities that can later be merged into
llm_router.py once it gains multimodal support.

All functions are synchronous (blocking HTTP) and raise RuntimeError
on unrecoverable failures.
"""

from __future__ import annotations

import base64
import json
import math
from io import BytesIO

import httpx
from PIL import Image

from ..api_key import APIKeyManager

# ─── Constants ────────────────────────────────────────────────────────────────

# Max image dimension before downscale (to avoid token explosion).
# Gemini 2.0 Flash has 1M token context; GPT-4o ~128K.  1024px is a safe default.
MAX_DIM = 1024

# VLM timeout in seconds.  Vision calls are slower than text-only.
VLM_TIMEOUT = 60

# Provider → (endpoint, model) mapping.
_PROVIDER_SPEC: dict[str, tuple[str, str]] = {
    "openai": (
        "https://api.openai.com/v1/chat/completions",
        "gpt-4o-mini",
    ),
    "gemini": (
        "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
        "gemini-1.5-flash",   # gemini-1.5-flash has solid vision
    ),
    "deepseek": (
        "https://api.deepseek.com/v1/chat/completions",
        "deepseek-chat",     # NOTE: deepseek-chat does NOT support vision (text-only).
    ),
}

# Priority order for provider="auto".
_AUTO_ORDER = ["gemini", "openai"]


# ─── Image Helpers ────────────────────────────────────────────────────────────


def encode_image(image_path: str) -> str:
    """Load an image, downscale if needed, and return a base64 data-URI string.

    Returns a string suitable for the ``image_url.url`` field in an
    OpenAI-compatible vision API payload, e.g.
    ``"data:image/png;base64,iVBORw0..."``.
    """
    img = Image.open(image_path)
    fmt = img.format or "PNG"

    # Downscale to avoid token explosion
    w, h = img.size
    if w > MAX_DIM or h > MAX_DIM:
        ratio = MAX_DIM / max(w, h)
        new_size = (math.floor(w * ratio), math.floor(h * ratio))
        img = img.resize(new_size, Image.LANCZOS)

    # Convert to RGB for JPEG-safe encoding (avoids RGBA base64 bloat)
    if img.mode in ("RGBA", "P", "LA"):
        img = img.convert("RGB")

    buf = BytesIO()
    img.save(buf, format="JPEG" if fmt.upper() in ("JPEG", "JPG") else "PNG")
    b64 = base64.b64encode(buf.getvalue()).decode("ascii")

    mime = "image/jpeg" if fmt.upper() in ("JPEG", "JPG") else "image/png"
    return f"data:{mime};base64,{b64}"


# ─── Vision API ───────────────────────────────────────────────────────────────


def _build_vision_payload(prompt: str, image_data_uri: str, model: str) -> dict:
    """Build an OpenAI-compatible chat completions payload with inline image."""
    return {
        "model": model,
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": prompt},
                    {"type": "image_url", "image_url": {"url": image_data_uri, "detail": "high"}},
                ],
            }
        ],
        "max_tokens": 2048,
        "temperature": 0.1,  # low temp for structured extraction
    }


def _call_single_provider(
    prompt: str,
    image_data_uri: str,
    provider: str,
    api_key: str,
) -> str | None:
    """Attempt a vision call to a single provider.  Returns text or None."""
    if provider not in _PROVIDER_SPEC:
        raise ValueError(f"Unknown vision provider: {provider}")

    url, model = _PROVIDER_SPEC[provider]
    payload = _build_vision_payload(prompt, image_data_uri, model)

    try:
        with httpx.Client(timeout=VLM_TIMEOUT) as client:
            resp = client.post(
                url,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                content=json.dumps(payload),
            )
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"].strip()
    except httpx.HTTPStatusError as e:
        # 4xx / 5xx — provider likely doesn't support vision or auth issue
        raise RuntimeError(
            f"Vision call to {provider} failed with HTTP {e.response.status_code}: "
            f"{e.response.text[:300]}"
        ) from e
    except httpx.TimeoutException as e:
        raise RuntimeError(f"Vision call to {provider} timed out ({VLM_TIMEOUT}s)") from e
    except Exception as e:
        raise RuntimeError(f"Vision call to {provider} failed: {e}") from e


def call_vision(
    prompt: str,
    image_path: str,
    provider: str = "auto",
) -> str:
    """Encode an image and send it to a VLM provider.  Returns raw response text.

    Args:
        prompt: The text prompt describing what to extract from the image.
        image_path: Absolute path to the screenshot (.png / .jpg).
        provider: One of ``"auto"``, ``"openai"``, ``"gemini"``, ``"deepseek"``.
            ``"auto"`` tries Gemini first, then OpenAI.

    Returns:
        Raw text response from the VLM.

    Raises:
        RuntimeError: If no provider succeeds or no credentials are configured.
    """
    # Load credentials
    cfg = APIKeyManager.load()
    if not cfg:
        raise RuntimeError(
            "No cloud API key configured. Run 'cloud' command in xchat to set one."
        )

    # Encode image once for all retries
    data_uri = encode_image(image_path)

    # Determine providers to try
    if provider == "auto":
        candidates = _AUTO_ORDER
    else:
        candidates = [provider]

    # If user's configured provider is not in candidates, prepend it
    configured_provider = cfg.get("provider", "")
    api_key = cfg.get("key", "")
    if configured_provider and configured_provider not in candidates:
        candidates = [configured_provider] + candidates

    # Try each candidate
    last_error = ""
    for prov in candidates:
        try:
            result = _call_single_provider(prompt, data_uri, prov, api_key)
            if result:
                return result
        except RuntimeError as e:
            last_error = str(e)
            continue

    raise RuntimeError(
        f"All vision providers failed. Last error: {last_error}"
    )
