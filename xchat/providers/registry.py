"""
Provider registry: declarative metadata for every cloud backend.

Design notes
------------
Model names are NOT hardcoded as truth. Gemini exposes ~58 models through its
list endpoint and rotates them constantly, so the registry keeps only a
*fallback* default per provider and treats live discovery (see ``account.py``)
as authoritative. Anything the GUI shows should come from discovery, not here.

Pricing is configuration, not fact — vendors change it without notice. The
numbers below are defaults; ``state/models.json`` overrides them so the client
can be corrected without a code change.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from ..config import MODELS_OVERRIDE


@dataclass(frozen=True)
class ModelSpec:
    """One selectable model on one provider."""

    id: str
    provider: str
    context_window: int = 0
    max_output: int = 0
    # USD per 1M tokens
    price_in: float = 0.0
    price_out: float = 0.0
    # Coarse tiers the scheduler uses for routing. "fast" answers quick
    # lookups, "deep" is for real analysis, "code" for code/pseudocode work.
    speed: str = "medium"        # fast | medium | slow
    capability: str = "general"  # general | code | deep
    notes: str = ""

    def cost_usd(self, prompt_tokens: int, completion_tokens: int) -> float:
        return (prompt_tokens * self.price_in + completion_tokens * self.price_out) / 1_000_000


@dataclass(frozen=True)
class ProviderSpec:
    """How to talk to one provider, and what it can tell us about itself."""

    name: str
    label: str
    base_url: str
    # Root for NON-chat endpoints (balance, model list). Cannot be derived from
    # base_url: Gemini's OpenAI-compatible chat base is /v1beta/openai while its
    # model list lives at /v1beta/models.
    api_root: str = ""
    chat_path: str = "/chat/completions"
    # Balance/quota endpoint. None => the vendor exposes no API-key-accessible
    # balance, and the client must say so rather than showing a fake number.
    balance_path: str | None = None
    balance_style: str | None = None   # "deepseek" | None
    models_path: str | None = None
    models_style: str | None = None    # "openai" | "gemini" | None
    # Auth differs per endpoint family, which is easy to get wrong:
    # Gemini's OpenAI-compatible CHAT endpoint wants `Authorization: Bearer`,
    # while its NATIVE endpoints (model list) want `x-goog-api-key`. A single
    # auth_style field cannot express both.
    auth_style: str = "bearer"         # for balance / model-list endpoints
    auth_chat: str = "bearer"          # for the chat endpoint
    default_model: str = ""
    is_openai_compatible: bool = True
    docs_url: str = ""
    catalog: tuple[ModelSpec, ...] = field(default_factory=tuple)

    @property
    def chat_url(self) -> str:
        return self.base_url.rstrip("/") + self.chat_path

    def url_for(self, path: str) -> str:
        root = (self.api_root or self.base_url).rstrip("/")
        return root + path

    def auth_headers(self, api_key: str, *, chat: bool = False) -> dict:
        style = self.auth_chat if chat else self.auth_style
        if style == "x-goog-api-key":
            return {"x-goog-api-key": api_key, "Content-Type": "application/json"}
        return {"Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"}


# ── 默认价目（USD / 1M tokens）。仅作兜底，可被 state/models.json 覆盖 ──
_GEMINI_CATALOG = (
    ModelSpec("gemini-3.8-flash", "gemini", price_in=0.30, price_out=2.50,
              speed="fast", capability="general", notes="newest flash tier"),
    ModelSpec("gemini-3.6-flash", "gemini", price_in=0.30, price_out=2.50,
              speed="fast", capability="general"),
    ModelSpec("gemini-3.1-pro-preview", "gemini", price_in=1.25, price_out=10.00,
              speed="slow", capability="deep"),
)

_DEEPSEEK_CATALOG = (
    # Live list (verified 2026-09): deepseek-flash, deepseek-v4-pro.
    # `deepseek-chat` and `deepseek-reasoner` still resolve but are SILENT
    # aliases onto deepseek-flash — the API echoes back the real model, which is
    # why the usage ledger records the response's model id, not the requested one.
    ModelSpec("deepseek-flash", "deepseek", context_window=65536, max_output=8192,
              price_in=0.27, price_out=1.10, speed="fast", capability="general",
              notes="legacy alias deepseek-chat resolves here"),
    ModelSpec("deepseek-v4-pro", "deepseek", context_window=65536, max_output=8192,
              price_in=0.55, price_out=2.19, speed="slow", capability="deep"),
)

_OPENAI_CATALOG = (
    ModelSpec("gpt-4o-mini", "openai", context_window=128000, max_output=16384,
              price_in=0.15, price_out=0.60, speed="fast", capability="general"),
    ModelSpec("gpt-4o", "openai", context_window=128000, max_output=16384,
              price_in=2.50, price_out=10.00, speed="slow", capability="deep"),
)

PROVIDERS: dict[str, ProviderSpec] = {
    "gemini": ProviderSpec(
        name="gemini",
        label="Google Gemini",
        base_url="https://generativelanguage.googleapis.com/v1beta/openai",
        api_root="https://generativelanguage.googleapis.com",
        balance_path=None,
        balance_style=None,
        models_path="/v1beta/models",
        models_style="gemini",
        auth_style="x-goog-api-key",   # native endpoints
        auth_chat="bearer",            # OpenAI-compatible chat endpoint
        default_model="gemini-3.6-flash",
        docs_url="https://ai.google.dev/gemini-api/docs",
        catalog=_GEMINI_CATALOG,
    ),
    "deepseek": ProviderSpec(
        name="deepseek",
        label="DeepSeek",
        base_url="https://api.deepseek.com",
        api_root="https://api.deepseek.com",
        balance_path="/user/balance",
        balance_style="deepseek",
        models_path="/models",
        models_style="openai",
        auth_style="bearer",
        default_model="deepseek-flash",
        docs_url="https://api-docs.deepseek.com",
        catalog=_DEEPSEEK_CATALOG,
    ),
    "openai": ProviderSpec(
        name="openai",
        label="OpenAI",
        base_url="https://api.openai.com/v1",
        api_root="https://api.openai.com/v1",
        balance_path=None,   # credit_grants needs a session key, not an API key
        balance_style=None,
        models_path="/models",
        models_style="openai",
        auth_style="bearer",
        default_model="gpt-4o-mini",
        docs_url="https://platform.openai.com/docs",
        catalog=_OPENAI_CATALOG,
    ),
}


def get(name: str) -> ProviderSpec | None:
    return PROVIDERS.get(name)


def known() -> list[str]:
    return sorted(PROVIDERS)


def _load_overrides() -> dict:
    try:
        if MODELS_OVERRIDE.exists():
            return json.loads(MODELS_OVERRIDE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


def model_spec(provider: str, model_id: str) -> ModelSpec:
    """Look up pricing/metadata for a model, applying user overrides.

    Falls back to a zero-cost unknown spec rather than guessing: the GUI should
    show "pricing unknown" instead of inventing a number.
    """
    overrides = _load_overrides()
    ov = overrides.get(provider, {}).get(model_id, {})
    if ov:
        base = next((m for m in (get(provider).catalog if get(provider) else ())
                     if m.id == model_id), None)
        if base:
            return ModelSpec(
                id=base.id, provider=base.provider,
                context_window=ov.get("context_window", base.context_window),
                max_output=ov.get("max_output", base.max_output),
                price_in=ov.get("price_in", base.price_in),
                price_out=ov.get("price_out", base.price_out),
                speed=ov.get("speed", base.speed),
                capability=ov.get("capability", base.capability),
                notes=ov.get("notes", base.notes),
            )
        return ModelSpec(
            id=model_id, provider=provider,
            context_window=ov.get("context_window", 0),
            max_output=ov.get("max_output", 0),
            price_in=ov.get("price_in", 0.0),
            price_out=ov.get("price_out", 0.0),
            speed=ov.get("speed", "medium"),
            capability=ov.get("capability", "general"),
            notes=ov.get("notes", "user-defined"),
        )

    for m in (get(provider).catalog if get(provider) else ()):
        if m.id == model_id:
            return m
    return ModelSpec(id=model_id, provider=provider, notes="unknown to registry")


def pricing_known(provider: str, model_id: str) -> bool:
    """True when we have real prices (so the GUI can flag unknown-cost models)."""
    m = model_spec(provider, model_id)
    return m.price_in > 0 or m.price_out > 0
