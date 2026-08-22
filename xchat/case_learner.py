"""
Case Learner: deep algorithm identification + knowledge DB.

Pipeline: 3B → 7B analysis → structured result → persistent storage in knowledge/.
"""

import json
from datetime import datetime

from .config import KNOWLEDGE_DIR
from .llm_router import LLMRouter


ANALYSIS_PROMPT = """You are a cryptographic reverse engineering expert. Identify the SPECIFIC algorithm implementation, not just the type.

For each algorithm found, provide:
1. Algorithm name with version/variant (e.g. "AES-128-CBC with OpenSSL 1.1.1 S-box", not just "AES")
2. Implementation source if identifiable (OpenSSL, BoringSSL, Crypto++, custom, etc.)
3. Key constants found (S-box values, IV patterns, round constants)
4. Parameters (key size, block size, rounds, padding scheme)
5. Evidence: which byte patterns led to this conclusion
6. Confidence: 0.0-1.0

Output as JSON:
{
  "algorithms": [
    {
      "name": "specific algorithm name",
      "library": "OpenSSL 1.1.1 / BoringSSL / custom / unknown",
      "constants": ["constant1", "constant2"],
      "parameters": {"key_size": 256, "block_size": 128, "rounds": 14, "padding": "PKCS7"},
      "evidence": "specific byte patterns observed",
      "confidence": 0.95
    }
  ],
  "summary": "one-line summary"
}

Be precise. If unsure, state what you CAN determine and mark uncertain parts."""


class CaseLearner:
    """Deep algorithm analysis → structured knowledge → persistent storage."""

    def __init__(self, router: LLMRouter):
        self.router = router
        KNOWLEDGE_DIR.mkdir(exist_ok=True)

    async def analyze(self, name: str, data: bytes, pipe_hits: dict) -> dict | None:
        """Run deep analysis on a single asset. Returns structured result or None."""
        hits = pipe_hits.get("hits", [])
        if not hits:
            return None

        # Build context: pipe hits + hex snippet
        hits_str = "\n".join(
            f"  Rule match: {', '.join(h.get('algos', []))} (sim={h.get('sim', 'N/A')})"
            for h in hits
        )

        # Extract first 512 bytes as hex evidence
        hex_snippet = data[:512].hex()
        hex_lines = [hex_snippet[i:i+64] for i in range(0, min(len(hex_snippet), 1024), 64)]
        hex_str = "\n".join(hex_lines)

        prompt = (
            f"{ANALYSIS_PROMPT}\n\n"
            f"Asset: {name}\n"
            f"Size: {len(data)} bytes\n\n"
            f"--- Rule Engine Hits ---\n{hits_str}\n\n"
            f"--- Binary Header (first 512 bytes hex) ---\n{hex_str}\n\n"
            f"Identify the specific algorithm implementation used in this binary."
        )

        context = {"hits": hits, "file_name": name, "file_size": len(data)}
        answer = await self.router.ask_3b(prompt, context, cloud_ok=False)

        if not answer:
            return None

        # Try to parse JSON from answer
        try:
            start = answer.find("{")
            end = answer.rfind("}") + 1
            if start >= 0 and end > start:
                parsed = json.loads(answer[start:end])
                parsed["_asset"] = name
                parsed["_model"] = "qwen2.5:3b+7b"
                parsed["_timestamp"] = datetime.now().isoformat()
                return parsed
        except json.JSONDecodeError:
            pass

        # Fallback: wrap raw answer
        return {
            "algorithms": [],
            "summary": answer,
            "_asset": name,
            "_model": "qwen2.5:3b+7b",
            "_raw": True,
            "_timestamp": datetime.now().isoformat(),
        }

    def save(self, sha256_hash: str, analysis: dict):
        """Persist analysis to knowledge DB."""
        fname = KNOWLEDGE_DIR / f"{sha256_hash[:16]}.json"
        existing = {}
        if fname.exists():
            try:
                existing = json.loads(fname.read_text(encoding="utf-8"))
            except Exception:
                pass

        # Merge: keep history, append new analysis
        history = existing.get("_history", [])
        history.append(analysis)
        record = {"sha256": sha256_hash, "_history": history}
        fname.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")

    MIN_LEARN_SIZE = 256  # skip tiny/empty files to prevent LLM hallucination

    async def learn(self, name: str, data: bytes, sha256_hash: str, pipe_hits: dict) -> dict | None:
        """Full pipeline: analyze → save → return."""
        if len(data) < self.MIN_LEARN_SIZE:
            print(f"  [learn] {name} ({len(data)} bytes) SKIP < {self.MIN_LEARN_SIZE}", flush=True)
            return None
        print(f"  [learn] {name} ({len(data)} bytes)", flush=True)
        analysis = await self.analyze(name, data, pipe_hits)
        if analysis:
            self.save(sha256_hash, analysis)
            return analysis
        return None

    def query_knowledge(self, sha256_hash: str) -> dict | None:
        """Look up previously learned analysis."""
        fname = KNOWLEDGE_DIR / f"{sha256_hash[:16]}.json"
        if fname.exists():
            try:
                return json.loads(fname.read_text(encoding="utf-8"))
            except Exception:
                pass
        return None

    def stats(self) -> dict:
        """Knowledge DB statistics."""
        if not KNOWLEDGE_DIR.exists():
            return {"total": 0, "algorithms": {}}
        files = list(KNOWLEDGE_DIR.glob("*.json"))
        algos = {}
        for f in files:
            try:
                record = json.loads(f.read_text(encoding="utf-8"))
                for entry in record.get("_history", []):
                    for algo in entry.get("algorithms", []):
                        name = algo.get("name", "unknown")
                        algos[name] = algos.get(name, 0) + 1
            except Exception:
                pass
        return {"total": len(files), "algorithms": algos}
