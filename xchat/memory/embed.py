"""
Embedding providers for the semantic memory layer.

Provider-agnostic on purpose: P4 runs against a cloud model because llama.cpp
is not set up yet (P5), and switching to a local model later must be a config
change, not a rewrite of the memory layer.

Two things this module is careful about:

* **Live model names.** `text-embedding-004` — the name in most tutorials — now
  returns 404. Only `gemini-embedding-*` is served. Names are verified against
  the live model list rather than trusted from documentation.
* **Reduced dimensionality.** Gemini defaults to 3072 floats per vector; the
  index only needs 768 to rank well, which cuts the on-disk index 4x.

Everything leaving for a cloud embedder is sanitised first: the memory layer
holds case summaries that may embed real target paths.
"""

from __future__ import annotations

import json
import math
import re
import urllib.error
import urllib.request
from dataclasses import dataclass

from ..api_key import APIKeyManager

# Cosine similarity from Gemini embeddings has a high baseline (~0.48 even for
# unrelated text), so absolute thresholds are meaningless. Retrieval ranks
# relatively and reports the score rather than filtering on a magic number.
BASELINE_SIMILARITY = 0.5


class EmbedError(Exception):
    pass


@dataclass
class EmbedderInfo:
    name: str
    model: str
    dim: int
    local: bool


class Embedder:
    """Interface every embedder implements."""

    name = "base"
    model = ""
    dim = 768
    local = False

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        raise NotImplementedError

    def embed(self, text: str) -> list[float]:
        out = self.embed_batch([text])
        if not out:
            raise EmbedError("embedder returned no vectors")
        return out[0]

    def info(self) -> EmbedderInfo:
        return EmbedderInfo(self.name, self.model, self.dim, self.local)


class GeminiEmbedder(Embedder):
    """Cloud embeddings via Gemini's native batch endpoint.

    Retries on 429/5xx with exponential backoff. The free tier rate-limits
    aggressively — the first indexing run embedded 96 entries and then hit a 429
    that cost it all 22 cases — so a quota error must be survivable rather than
    fatal to the whole run.
    """

    name = "gemini"
    BASE = "https://generativelanguage.googleapis.com/v1beta/models"
    RETRY_STATUSES = {429, 500, 502, 503, 504}

    def __init__(self, model: str = "gemini-embedding-001", dim: int = 768,
                 timeout: int = 60, sanitize: bool = True,
                 max_retries: int = 5, base_delay: float = 2.0,
                 min_interval: float = 0.0):
        self.model = model
        self.dim = dim
        self.timeout = timeout
        self.sanitize = sanitize
        self.max_retries = max_retries
        self.base_delay = base_delay
        # Minimum spacing between calls, to stay under a per-minute quota
        # instead of discovering it by being rejected.
        self.min_interval = min_interval
        self._last_call = 0.0
        self._key: str | None = None

    def _api_key(self) -> str:
        if self._key is None:
            keys = (APIKeyManager.load() or {}).get("providers", {}) or {}
            self._key = keys.get("gemini", "")
        if not self._key:
            raise EmbedError("no gemini API key configured")
        return self._key

    def _prepare(self, texts: list[str]) -> list[str]:
        if not self.sanitize:
            return texts
        from ..sanitizer import Sanitizer
        return [Sanitizer.text(t) for t in texts]

    def _throttle(self) -> None:
        if self.min_interval <= 0:
            return
        import time
        wait = self.min_interval - (time.monotonic() - self._last_call)
        if wait > 0:
            time.sleep(wait)

    def _post(self, url: str, payload: dict) -> dict:
        import time

        last_detail = ""
        for attempt in range(self.max_retries + 1):
            self._throttle()
            req = urllib.request.Request(
                url, data=json.dumps(payload).encode(), method="POST")
            req.add_header("x-goog-api-key", self._api_key())
            req.add_header("Content-Type", "application/json")
            try:
                self._last_call = time.monotonic()
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    return json.loads(r.read())
            except urllib.error.HTTPError as e:
                detail = e.read().decode("utf-8", "replace")
                last_detail = f"HTTP {e.code}: {detail[:200]}"
                if e.code not in self.RETRY_STATUSES or attempt == self.max_retries:
                    raise EmbedError(f"embedding {last_detail}") from None
                # Honour the server's own hint when it gives one.
                delay = self.base_delay * (2 ** attempt)
                m = re.search(r'"retryDelay"\s*:\s*"(\d+(?:\.\d+)?)s"', detail)
                if m:
                    delay = max(delay, float(m.group(1)))
                time.sleep(min(delay, 60.0))
            except Exception as e:
                last_detail = f"{type(e).__name__}: {e}"
                if attempt == self.max_retries:
                    raise EmbedError(f"embedding failed: {last_detail}") from None
                time.sleep(self.base_delay * (2 ** attempt))
        raise EmbedError(f"embedding failed after retries: {last_detail}")

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []
        prepared = self._prepare(texts)
        url = f"{self.BASE}/{self.model}:batchEmbedContents"
        payload = {
            "requests": [
                {"model": f"models/{self.model}",
                 "content": {"parts": [{"text": t}]},
                 "outputDimensionality": self.dim}
                for t in prepared
            ]
        }
        body = self._post(url, payload)
        embs = body.get("embeddings") or []
        if len(embs) != len(texts):
            raise EmbedError(f"expected {len(texts)} vectors, got {len(embs)}")
        return [e.get("values", []) for e in embs]

    def embed(self, text: str) -> list[float]:
        """Single-text embed via embedContent (batch of one wastes quota)."""
        url = f"{self.BASE}/{self.model}:embedContent"
        body = self._post(url, {
            "content": {"parts": [{"text": self._prepare([text])[0]}]},
            "outputDimensionality": self.dim,
        })
        return (body.get("embedding") or {}).get("values", [])


class LocalEmbedder(Embedder):
    """Placeholder for P5.

    Kept as a real class rather than a comment so the seam is visible: when
    llama.cpp lands, only `_embed` needs implementing and the memory layer
    becomes fully local with no other change.
    """

    name = "local"
    local = True

    def __init__(self, model: str = "bge-small-en-v1.5", dim: int = 384):
        self.model = model
        self.dim = dim

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        raise EmbedError(
            "local embeddings require the llama.cpp backend (P5). "
            "Set embedding.provider=gemini meanwhile.")


def get_embedder(provider: str = "gemini", **kw) -> Embedder:
    if provider == "gemini":
        return GeminiEmbedder(**kw)
    if provider == "local":
        return LocalEmbedder(**kw)
    raise EmbedError(f"unknown embedding provider '{provider}'")


# ── vector helpers ──────────────────────────────────────────────────────────

def cosine(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


def pack(vec: list[float]) -> bytes:
    """float32 blob — half the size of JSON and trivially unpacked."""
    import array
    return array.array("f", vec).tobytes()


def unpack(blob: bytes) -> list[float]:
    import array
    a = array.array("f")
    a.frombytes(blob)
    return list(a)
