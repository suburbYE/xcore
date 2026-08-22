"""
LLM Router: 3b ↔ 7b ↔ cloud orchestration.

Single dialog layer: 3B handles all user interaction and decides
when to delegate to 7B or Cloud for deeper analysis.
"""

import asyncio
import json

from .config import OLLAMA_URL, TIMEOUT_3B, TIMEOUT_7B, TIMEOUT_14B, TIMEOUT_CLOUD, MAX_CLOUD_TOKENS, LOCAL_MODELS, MODEL_VRAM, VRAM_RESERVE, VRAM_FALLBACK_TOTAL
from .sanitizer import Sanitizer
from .api_key import APIKeyManager


XC_SYS_PROMPT = """You are X-Chat, a crypto reverse engineering assistant built into a CLI tool.
You answer questions about scanned binary files. You have access to:

1. SCAN CONTEXT: algorithm detection hits from the xcore engine
2. 7B ANALYZER: local model for deep algorithm analysis
3. CLOUD ANALYZER: expert cloud model (GPT-4o-mini/DeepSeek) for tasks beyond 7B's capability

RULES:
- Answer directly from SCAN CONTEXT for simple questions about detected algorithms.
- For deeper analysis (library origin, encryption parameters, implementation details), respond with EXACTLY:
  NEED_7B: <your specific question for the 7B analyzer>
- For expert-level analysis that needs more than 7B can provide:
  NEED_CLOUD: <your specific question for the cloud analyzer>
- When you receive results prefixed with "7B_RESULT:" or "CLOUD_RESULT:", synthesize a concise final answer.
- Be concise. Skip beginner-level explanations. The user is a reverse engineer.
- If asked something unrelated to binary analysis, answer briefly."""

NEED_7B_MARKER = "NEED_7B:"
NEED_CLOUD_MARKER = "NEED_CLOUD:"


class LLMRouter:
    def __init__(self):
        self.models_available = self._probe_ollama()

    @staticmethod
    def _get_vram_free_gb() -> float:
        """Detect free VRAM in GB. Returns -1 on failure."""
        try:
            import subprocess
            # Try WMI first (Intel Arc reports correctly via AdapterRAM)
            raw = subprocess.check_output(
                ['wmic', 'path', 'Win32_VideoController', 'get', 'AdapterRAM'],
                timeout=5, text=True
            )
            for line in raw.splitlines():
                line = line.strip()
                if line.isdigit():
                    total_gb = int(line) / (1024 ** 3)
                    break
            else:
                return -1

            # Try perf counter for current GPU usage
            try:
                import re
                raw2 = subprocess.check_output(
                    ['powershell', '-NoProfile', '-Command',
                     '(Get-Counter "\\GPU Local Usage(*)\\local usage" -ErrorAction Stop).CounterSamples '
                     '| Where-Object {$_.InstanceName -notmatch "_eng"} '
                     '| ForEach-Object {$_.CookedValue}'],
                    timeout=5, text=True
                )
                pcts = [float(x.strip()) for x in raw2.splitlines() if x.strip()]
                if pcts:
                    # Take the highest engine usage (most accurate for Arc)
                    max_pct = max(pcts) / 100.0
                    used_gb = total_gb * max_pct
                    return total_gb - used_gb
            except Exception:
                pass

            # Fallback: check ollama loaded models
            try:
                r = subprocess.check_output(
                    ['ollama', 'ps'], timeout=5, text=True
                )
                loaded = 0.0
                for name, gb in MODEL_VRAM.items():
                    if name in r:
                        loaded += gb
                return total_gb - loaded
            except Exception:
                pass

            return total_gb  # can't measure used → assume all free
        except Exception:
            return -1

    def _probe_ollama(self) -> list[str]:
        """Check which local models are installed AND can fit in VRAM."""
        try:
            import urllib.request
            r = urllib.request.urlopen(f"{OLLAMA_URL}/api/tags", timeout=5)
            data = json.loads(r.read())
            names = [m["name"] for m in data.get("models", [])]
            installed = [n for n in names if n in LOCAL_MODELS]
        except Exception:
            return []

        # VRAM budget check: only enable models that fit
        free_gb = self._get_vram_free_gb()
        if free_gb < 0:
            # Detection failed — trust all installed models
            print(f"  [vram] Detection failed, enabling all installed: {installed}")
            return installed

        available = []
        skipped = []
        budget = free_gb - VRAM_RESERVE
        # Always enable 3B (essential for routing), then largest-first greedy
        must_have = "qwen2.5:3b"
        for name in sorted(installed, key=lambda n: MODEL_VRAM.get(n, 0), reverse=True):
            if name == must_have:
                continue
            cost = MODEL_VRAM.get(name, 5.0)
            if budget >= cost:
                budget -= cost
                available.append(name)
            else:
                skipped.append(name)

        # 3B always last (lowest priority in greedy, but always included)
        if must_have in installed:
            cost_3b = MODEL_VRAM.get(must_have, 2.2)
            if budget >= cost_3b or not available:
                available.append(must_have)
            else:
                skipped.append(must_have)

        if skipped:
            print(f"  [vram] Free: {free_gb:.1f}G → enabled: {available}  skipped (OOM): {skipped}")
        else:
            print(f"  [vram] Free: {free_gb:.1f}G → all models fit: {available}")
        return available

    def has_model(self, name: str) -> bool:
        return name in self.models_available

    async def _ollama_chat(self, model: str, prompt: str, timeout: int) -> dict:
        """Call Ollama chat API. Returns {ok, answer, error}."""
        import urllib.request
        payload = json.dumps({
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
        }).encode()

        try:
            loop = asyncio.get_running_loop()

            def _req():
                req = urllib.request.Request(
                    f"{OLLAMA_URL}/api/chat",
                    data=payload,
                    headers={"Content-Type": "application/json"},
                )
                return urllib.request.urlopen(req, timeout=timeout).read()

            resp = await asyncio.wait_for(
                loop.run_in_executor(None, _req),
                timeout=timeout,
            )
            data = json.loads(resp)
            answer = data.get("message", {}).get("content", "").strip()
            return {"ok": bool(answer), "answer": answer, "error": ""}

        except asyncio.TimeoutError:
            return {"ok": False, "answer": "", "error": f"timeout ({timeout}s)"}
        except Exception as e:
            return {"ok": False, "answer": "", "error": str(e)}

    async def ask_3b(self, question: str, context: dict | None = None, cloud_ok: bool = False) -> str:
        """Single dialog layer: 3B → 7B/Cloud → 3B → user.
        Cloud only talks to 3B, never to user directly."""
        has_7b = self.has_model("qwen2.5:7b")
        has_3b = self.has_model("qwen2.5:3b")

        if not has_3b:
            if has_7b:
                r = await self._ollama_chat("qwen2.5:7b", question, TIMEOUT_7B)
                return r.get("answer", "[!] No response") if r.get("ok") else "[!] Model error"
            return "[!] No local models available"

        # Build context string
        ctx_str = ""
        if context:
            hits = context.get("hits", [])
            if hits:
                ctx_str = "SCAN CONTEXT:\n" + "\n".join(
                    f"  #{h.get('id','?')}: {','.join(h.get('algos',[]))} (sim={h.get('sim','N/A')}, status={h.get('status','?')})"
                    for h in hits
                ) + f"\n  Total hits: {len(hits)}"

        # Step 1: Ask 3B
        has_14b = self.has_model("qwen2.5:14b")
        prompt_3b = (
            f"{XC_SYS_PROMPT}\n\n"
            f"{ctx_str}\n\n"
            f"User: {question}\n"
        )
        r1 = await self._ollama_chat("qwen2.5:3b", prompt_3b, TIMEOUT_3B)
        if not r1["ok"]:
            return f"[!] 3B error: {r1.get('error', 'unknown')}"

        ans1 = r1["answer"]

        # Helper: synthesize with 3B after external result
        async def _synthesize(source_label: str, result_text: str) -> str:
            prompt_synth = (
                f"{XC_SYS_PROMPT}\n\n"
                f"{ctx_str}\n\n"
                f"User: {question}\n\n"
                f"{source_label}: {result_text}\n\n"
                f"Synthesize a concise final answer for the user. Do NOT output NEED_7B or NEED_CLOUD markers."
            )
            r3 = await self._ollama_chat("qwen2.5:3b", prompt_synth, TIMEOUT_3B)
            if r3["ok"]:
                ans = r3["answer"]
                # Strip any leaked routing markers from synthesis output
                for marker in (NEED_7B_MARKER, NEED_CLOUD_MARKER):
                    if marker in ans:
                        idx = ans.find(marker)
                        ans = ans[:idx].strip()
                return ans if ans else f"[{source_label}] {result_text}"
            return f"[{source_label}] {result_text}"

        # 2a: NEED_CLOUD — 3B explicitly requests cloud
        if NEED_CLOUD_MARKER in ans1:
            idx = ans1.find(NEED_CLOUD_MARKER)
            q_cloud = ans1[idx + len(NEED_CLOUD_MARKER):].strip()
            if cloud_ok:
                print("  [3B → Cloud]", flush=True)
                cloud_ans = await self._cloud_query(q_cloud, context)
                if cloud_ans:
                    return await _synthesize("CLOUD_RESULT", cloud_ans)
                print("  [!] Cloud failed, falling back to local models...", flush=True)
            # Remove NEED_CLOUD marker, fall through to NEED_7B/14B below
            ans1 = ans1[:idx] + ans1[idx + len(NEED_CLOUD_MARKER) + len(q_cloud):].strip()

        # 2b: NEED_7B — 3B requests local deep analysis
        # Try 14B (best domain knowledge) → 7B → Cloud
        if NEED_7B_MARKER in ans1:
            idx = ans1.find(NEED_7B_MARKER)
            q7b = ans1[idx + len(NEED_7B_MARKER):].strip()
            # Forward context to downstream models so they see scan results
            full_prompt = f"{ctx_str}\n\nQuestion: {q7b}" if ctx_str else q7b

            # Prefer 14B for superior domain knowledge (mobile signing, crypto params)
            if has_14b:
                print("  [3B → 14B]", flush=True)
                r2 = await self._ollama_chat("qwen2.5:14b", full_prompt, TIMEOUT_14B)
                if r2["ok"]:
                    return await _synthesize("14B_RESULT", r2["answer"])
                print(f"  [!] 14B failed ({r2.get('error', '?')}), trying 7B...", flush=True)

            if has_7b:
                print("  [3B → 7B]", flush=True)
                r2 = await self._ollama_chat("qwen2.5:7b", full_prompt, TIMEOUT_7B)
                if r2["ok"]:
                    return await _synthesize("7B_RESULT", r2["answer"])

            # 7B/14B both failed or unavailable → try cloud
            if cloud_ok:
                print("  [Local models failed → Cloud]", flush=True)
                cloud_ans = await self._cloud_query(full_prompt, context)
                if cloud_ans:
                    return await _synthesize("CLOUD_RESULT", cloud_ans)

            # No cloud either
            return ans1.replace(NEED_7B_MARKER, "").strip()

        return ans1

    async def _cloud_query(self, prompt: str, context: dict | None = None) -> str:
        """Send a pre-sanitized prompt to cloud. Returns raw answer or '' on failure."""
        cfg = APIKeyManager.load()
        if not cfg:
            print("  [!] No cloud API key configured. Type 'cloud' to set one.")
            return ""

        provider = cfg["provider"]
        api_key = cfg["key"]
        safe_prompt = Sanitizer.prompt(prompt, context or {})

        import urllib.request
        if provider == "openai":
            url = "https://api.openai.com/v1/chat/completions"
            headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
            model = "gpt-4o-mini"
        elif provider == "gemini":
            url = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
            headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
            model = "gemini-3.5-flash"
        else:
            url = "https://api.deepseek.com/v1/chat/completions"
            headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
            model = "deepseek-chat"

        payload = json.dumps({
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": MAX_CLOUD_TOKENS,
        }).encode()

        try:
            loop = asyncio.get_running_loop()

            def _req():
                req = urllib.request.Request(url, data=payload, headers=headers)
                return urllib.request.urlopen(req, timeout=TIMEOUT_CLOUD).read()

            resp = await loop.run_in_executor(None, _req)
            data = json.loads(resp)
            answer = data["choices"][0]["message"]["content"].strip()
            return answer
        except Exception as e:
            error_msg = str(e)
            if "401" in error_msg or "403" in error_msg or "auth" in error_msg.lower():
                print("  [!] Cloud auth failed — check API key with 'cloud' command")
            elif "timeout" in error_msg.lower():
                print(f"  [!] Cloud timeout: {e}")
            else:
                print(f"  [!] Cloud error: {e}")
            return ""
