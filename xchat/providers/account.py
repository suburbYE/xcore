"""
Account probes: balance / quota and live model discovery.

Only DeepSeek exposes an API-key-accessible balance endpoint. Gemini and OpenAI
do not, and the client must surface that honestly instead of rendering a
placeholder figure — a fake balance is worse than "unsupported".

All network entries return a normalised dataclass and never raise: the GUI
calls these on a timer and a transient network error must not kill the panel.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from ..api_key import APIKeyManager
from . import registry

_TIMEOUT = 20
_MODEL_CACHE_TTL = 300  # seconds
_model_cache: dict[str, tuple[float, list[dict]]] = {}


@dataclass
class BalanceResult:
    provider: str
    supported: bool
    ok: bool = False
    currency: str = ""
    total: float | None = None
    granted: float | None = None
    topped_up: float | None = None
    is_available: bool | None = None
    error: str = ""
    reason: str = ""       # why unsupported
    raw: dict = field(default_factory=dict)


@dataclass
class ModelInfo:
    id: str
    provider: str
    context_window: int = 0
    max_output: int = 0
    display_name: str = ""
    source: str = "live"   # live | catalog


def _keys() -> dict[str, str]:
    cfg = APIKeyManager.load() or {}
    return cfg.get("providers", {}) or {}


def _request(spec: registry.ProviderSpec, path: str, api_key: str):
    req = urllib.request.Request(spec.url_for(path))
    if spec.auth_style == "x-goog-api-key":
        req.add_header("x-goog-api-key", api_key)
    else:
        req.add_header("Authorization", f"Bearer {api_key}")
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
            return json.loads(r.read().decode("utf-8", "replace")), None
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")[:200]
        return None, f"HTTP {e.code}: {body}"
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


# ── 余额 ────────────────────────────────────────────────────────────────────

def balance(provider: str) -> BalanceResult:
    """Query one provider's balance. Never raises."""
    spec = registry.get(provider)
    if spec is None:
        return BalanceResult(provider=provider, supported=False,
                             reason=f"unknown provider '{provider}'")
    if not spec.balance_path:
        return BalanceResult(
            provider=provider, supported=False,
            reason=f"{spec.label} exposes no API-key-accessible balance endpoint",
        )

    key = _keys().get(provider)
    if not key:
        return BalanceResult(provider=provider, supported=True,
                             reason="no API key configured")

    data, err = _request(spec, spec.balance_path, key)
    if err:
        return BalanceResult(provider=provider, supported=True, error=err)

    if spec.balance_style == "deepseek":
        infos = data.get("balance_infos") or []
        info = infos[0] if infos else {}
        def _f(v):
            try:
                return float(v)
            except (TypeError, ValueError):
                return None
        return BalanceResult(
            provider=provider, supported=True, ok=True,
            currency=info.get("currency", ""),
            total=_f(info.get("total_balance")),
            granted=_f(info.get("granted_balance")),
            topped_up=_f(info.get("topped_up_balance")),
            is_available=data.get("is_available"),
            raw=data,
        )

    return BalanceResult(provider=provider, supported=True, ok=True, raw=data)


def balances() -> dict[str, BalanceResult]:
    """Balance for every configured provider. Used by the GUI status bar."""
    return {p: balance(p) for p in _keys()}


# ── 模型发现 ────────────────────────────────────────────────────────────────

def list_models(provider: str, use_cache: bool = True) -> tuple[list[ModelInfo], str]:
    """Return (models, error). Falls back to the registry catalog on failure.

    Live discovery is authoritative: vendors add and retire models constantly,
    so a hardcoded name is a latent breakage.
    """
    spec = registry.get(provider)
    if spec is None:
        return [], f"unknown provider '{provider}'"

    now = time.time()
    if use_cache:
        hit = _model_cache.get(provider)
        if hit and now - hit[0] < _MODEL_CACHE_TTL:
            return hit[1], ""

    out: list[ModelInfo] = []
    err = ""
    key = _keys().get(provider)

    if key and spec.models_path:
        data, rerr = _request(spec, spec.models_path, key)
        if rerr:
            err = rerr
        elif data is not None:
            if spec.models_style == "gemini":
                for m in data.get("models", []):
                    mid = (m.get("name") or "").replace("models/", "")
                    if not mid:
                        continue
                    out.append(ModelInfo(
                        id=mid, provider=provider,
                        context_window=m.get("inputTokenLimit", 0) or 0,
                        max_output=m.get("outputTokenLimit", 0) or 0,
                        display_name=m.get("displayName", ""),
                    ))
            elif spec.models_style == "openai":
                for m in data.get("data", []):
                    mid = m.get("id")
                    if mid:
                        out.append(ModelInfo(id=mid, provider=provider))

    if not out:
        # offline / no key / discovery failed -> show what the registry knows,
        # clearly labelled so the UI never passes a catalog entry off as live
        out = [ModelInfo(id=m.id, provider=provider,
                         context_window=m.context_window,
                         max_output=m.max_output, source="catalog")
               for m in spec.catalog]

    out.sort(key=lambda m: m.id)
    _model_cache[provider] = (now, out)
    return out, err


def clear_model_cache(provider: str | None = None):
    if provider:
        _model_cache.pop(provider, None)
    else:
        _model_cache.clear()


def model_exists(provider: str, model_id: str) -> bool:
    """Validate a configured model against the live list (catalog as fallback)."""
    models, _ = list_models(provider)
    return any(m.id == model_id for m in models)
