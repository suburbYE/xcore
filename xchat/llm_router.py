"""
LLM Router: 3b ↔ 7b ↔ cloud orchestration.

Single dialog layer: 3B handles all user interaction and decides
when to delegate to 7B or Cloud for deeper analysis.
"""

import asyncio
import json

from .config import OLLAMA_URL, TIMEOUT_3B, TIMEOUT_7B, TIMEOUT_14B, TIMEOUT_CLOUD, MAX_CLOUD_TOKENS, LOCAL_MODELS, MODEL_VRAM, VRAM_RESERVE, VRAM_FALLBACK_TOTAL, DIALOG_MODEL, DIALOG_TIMEOUT
from .sanitizer import Sanitizer
from .api_key import APIKeyManager
from .tools.mcp_server import invoke_capability


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


def _downstream_prompt(ctx_str: str, question: str, sub_question: str) -> str:
    """Assemble the prompt handed to the 7B / cloud tier.

    Must carry the user's ORIGINAL request, not just the local model's refined
    sub-question: users routinely paste pseudocode or disassembly straight into
    the question, and forwarding only the sub-question leaves the downstream
    model analysing evidence it cannot see.
    """
    parts = []
    if ctx_str:
        parts.append(ctx_str)
    parts.append(f"Original request:\n{question}")
    sub = (sub_question or "").strip()
    # 与原始请求重复时不必再发一遍（本地模型常把问题原样回显）
    if sub and sub != question.strip():
        parts.append(f"Focused sub-question: {sub}")
    return "\n\n".join(parts)


class LLMRouter:
    def __init__(self):
        self.models_available = self._probe_ollama()

    @staticmethod
    def _query_total_vram_gb() -> float:
        """Query total dedicated VRAM in GB. Returns -1 on failure.

        Prefers the display-class registry value ``HardwareInformation.qwMemorySize``
        (a REG_QWORD). ``Win32_VideoController.AdapterRAM`` is a uint32 and silently
        truncates at 4 GB on larger cards, so it is only a fallback.

        Note: the old implementation shelled out to ``wmic``, which Microsoft
        deprecated and which is absent on current Windows 11 builds — there it
        always failed and every installed model was enabled regardless of VRAM.
        """
        ps = (
            "$s = @();"
            "try { $s += Get-ItemProperty -Path "
            "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Class\\"
            "{4d36e968-e325-11ce-bfc1-08002be10318}\\0*' "
            "-Name 'HardwareInformation.qwMemorySize' -ErrorAction SilentlyContinue |"
            " ForEach-Object { $_.'HardwareInformation.qwMemorySize' } } catch {};"
            "if (-not $s) { try { $s += (Get-CimInstance Win32_VideoController "
            "-ErrorAction SilentlyContinue | ForEach-Object { $_.AdapterRAM }) } catch {} };"
            "($s | Where-Object { $_ -gt 0 } | Measure-Object -Maximum).Maximum"
        )
        try:
            import subprocess
            raw = subprocess.check_output(
                ['powershell', '-NoProfile', '-NonInteractive', '-Command', ps],
                timeout=15, text=True
            ).strip()
            if not raw.isdigit():
                return -1
            total_gb = int(raw) / (1024 ** 3)
            return total_gb if total_gb > 0 else -1
        except Exception:
            return -1

    @staticmethod
    def _get_vram_free_gb() -> float:
        """Detect free VRAM in GB. Returns -1 on failure."""
        try:
            import subprocess
            total_gb = LLMRouter._query_total_vram_gb()
            if total_gb <= 0:
                return -1

            # Try perf counter for current GPU usage
            try:
                raw2 = subprocess.check_output(
                    ['powershell', '-NoProfile', '-Command',
                     '(Get-Counter "\\GPU Local Usage(*)\\local usage" -ErrorAction Stop).CounterSamples '
                     '| Where-Object {$_.InstanceName -notmatch "_eng"} '
                     '| ForEach-Object {$_.CookedValue}'],
                    timeout=5, text=True, stderr=subprocess.DEVNULL
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
                    ['ollama', 'ps'], timeout=5, text=True, stderr=subprocess.DEVNULL
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

        # DIALOG_MODEL 是路由链的必经入口（对话 + 判定上云 + 复述云端结果），
        # 必须在预算里预留给它，否则大模型贪心会把它挤掉。
        must_have = DIALOG_MODEL
        if must_have in installed:
            budget -= MODEL_VRAM.get(must_have, 9.5)

        # 其余模型按大到小贪心填满剩余预算
        for name in sorted(installed, key=lambda n: MODEL_VRAM.get(n, 0), reverse=True):
            if name == must_have:
                continue
            cost = MODEL_VRAM.get(name, 5.0)
            if budget >= cost:
                budget -= cost
                available.append(name)
            else:
                skipped.append(name)

        # 3B 始终可用（它的席位已在上方预留）
        if must_have in installed:
            available.append(must_have)

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

    async def _ollama_chat_tools(self, model: str, messages: list[dict], tools: list[dict], timeout: int) -> dict:
        """Call Ollama chat API with native tools field. Returns {ok, answer, tool_calls, error}."""
        import urllib.request
        payload = json.dumps({
            "model": model,
            "messages": messages,
            "tools": tools,
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
            msg = data.get("message", {})
            answer = msg.get("content", "").strip()
            tool_calls = msg.get("tool_calls", [])
            return {"ok": bool(answer) or bool(tool_calls), "answer": answer, "tool_calls": tool_calls, "error": ""}

        except asyncio.TimeoutError:
            return {"ok": False, "answer": "", "tool_calls": [], "error": f"timeout ({timeout}s)"}
        except Exception as e:
            return {"ok": False, "answer": "", "tool_calls": [], "error": str(e)}

    async def ask_with_tools(self, question: str, context: dict | None = None, cloud_ok: bool = False) -> str:
        """Tool-augmented dialog: model decides whether to call xcore tools,
        executes them in a loop until a final answer is produced.
        Fallback: if no tools available or model errors, delegates to ask_3b.

        The tool list comes from the capability registry by way of the agent's
        own intent-based selection, not from a hand-written list. The old list
        had drifted: it advertised `so_path` where the registry — and therefore
        every MCP client — said `so`, so the local model was being told to call
        a parameter that the rest of the system does not use.
        """
        from .kernel import bootstrap
        from .kernel.providers import agent as agent_provider

        registry = bootstrap()
        tools_ollama, reverse, _stats = agent_provider.select_tools(registry, question)
        if not tools_ollama:
            return await self.ask_3b(question, context, cloud_ok=cloud_ok)
        known = set(reverse)

        model = DIALOG_MODEL
        if not self.has_model(model):
            return f"[!] No local model available ({model}). Run: ollama pull {model}"

        ctx_str = ""
        if context:
            hits = context.get("hits", [])
            if hits:
                ctx_str = "SCAN CONTEXT:\n" + "\n".join(
                    f"  #{h.get('id','?')}: {','.join(h.get('algos',[]))} (sim={h.get('sim','N/A')}, status={h.get('status','?')})"
                    for h in hits
                ) + f"\n  Total hits: {len(hits)}"
            f = context.get("file")
            if f:
                ctx_str += f"\n  Current file: {f}"

        def _fn(t):
            return t.get("function", t)

        sys_prompt = (
            f"{XC_SYS_PROMPT}\n\n"
            "You have access to these tools. Call a tool when the user asks you to "
            "scan/classify/analyze a file or generate a probe; otherwise answer directly.\n"
            "Tool list:\n"
            + "\n".join(
                f"- {_fn(t)['name']}: {_fn(t).get('description', '')} "
                f"args={list((_fn(t).get('parameters') or {}).get('properties', {}).keys())}"
                for t in tools_ollama
            )
            + "\n\nCRITICAL RULES:\n"
            "- Use the EXACT argument names listed above.\n"
            "- When a tool returns an error or empty result, report it honestly to the user. NEVER invent scan results, hits, or analysis that the tool did not return.\n"
            "- Tool results are the ground truth; summarize them, do not fabricate details.\n"
        )

        messages = [
            {"role": "system", "content": sys_prompt},
            {"role": "user", "content": f"{ctx_str}\n\nUser: {question}"},
        ]

        # 14B 级模型用 30s 会频繁超时；跟随 DIALOG_MODEL 的超时预算
        timeout = (DIALOG_TIMEOUT if model == DIALOG_MODEL
                   else (TIMEOUT_7B if "7b" in model else TIMEOUT_3B))

        for _round in range(5):  # max 5 tool rounds
            resp = await self._ollama_chat_tools(model, messages, tools_ollama, timeout)
            if not resp["ok"]:
                return f"[!] Model error: {resp.get('error', 'unknown')}"
            tool_calls = resp.get("tool_calls") or []
            if not tool_calls:
                return resp["answer"] or "[!] No response"

            messages.append({
                "role": "assistant",
                "content": resp["answer"] or "",
                "tool_calls": tool_calls,
            })
            for tc in tool_calls:
                fn = tc.get("function", {})
                name = fn.get("name", "")
                args = fn.get("arguments", {})
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except Exception:
                        args = {"raw": args}
                if not name or name not in known:
                    err = f"Unknown tool name '{name}'"
                    print(f"  [tool] !! {err}", flush=True)
                    messages.append({"role": "tool", "content": f"TOOL ERROR: {err}"})
                    continue
                print(f"  [tool] {name}({json.dumps(args, ensure_ascii=False)})", flush=True)
                try:
                    # Same selection, same ids: the name the model was shown maps
                    # straight back to the capability, so there is no second
                    # name table to keep in step.
                    result = await asyncio.to_thread(
                        invoke_capability, reverse[name], args or {})
                    result_text = json.dumps(result, ensure_ascii=False, default=str)[:4000]
                except Exception as e:
                    result_text = f"TOOL ERROR: {type(e).__name__}: {e}"
                messages.append({"role": "tool", "content": result_text})

        return "[!] Tool call loop exceeded limit"

    async def ask_3b(self, question: str, context: dict | None = None, cloud_ok: bool = False) -> str:
        """Single dialog layer: DIALOG_MODEL → (7B) → Cloud → DIALOG_MODEL → user.
        Cloud only talks to the dialog model, never to user directly.

        本地只保留 DIALOG_MODEL 时，NEED_7B 与 NEED_CLOUD 都汇入云端——
        这正是「本地轻量、重活上云」想要的行为。
        """
        has_7b = self.has_model("qwen2.5:7b")
        has_local = self.has_model(DIALOG_MODEL)

        if not has_local:
            if has_7b:
                r = await self._ollama_chat("qwen2.5:7b", question, TIMEOUT_7B)
                return r.get("answer", "[!] No response") if r.get("ok") else "[!] Model error"
            return f"[!] No local model available ({DIALOG_MODEL}). Run: ollama pull {DIALOG_MODEL}"

        # Build context string
        ctx_str = ""
        if context:
            hits = context.get("hits", [])
            if hits:
                ctx_str = "SCAN CONTEXT:\n" + "\n".join(
                    f"  #{h.get('id','?')}: {','.join(h.get('algos',[]))} (sim={h.get('sim','N/A')}, status={h.get('status','?')})"
                    for h in hits
                ) + f"\n  Total hits: {len(hits)}"

        # Step 1: Ask the local dialog model
        has_14b = self.has_model("qwen2.5:14b")
        prompt_3b = (
            f"{XC_SYS_PROMPT}\n\n"
            f"{ctx_str}\n\n"
            f"User: {question}\n"
        )
        r1 = await self._ollama_chat(DIALOG_MODEL, prompt_3b, DIALOG_TIMEOUT)
        if not r1["ok"]:
            return f"[!] {DIALOG_MODEL} error: {r1.get('error', 'unknown')}"

        ans1 = r1["answer"]

        # Helper: synthesize with the local model after an external result
        async def _synthesize(source_label: str, result_text: str) -> str:
            prompt_synth = (
                f"{XC_SYS_PROMPT}\n\n"
                f"{ctx_str}\n\n"
                f"User: {question}\n\n"
                f"{source_label}: {result_text}\n\n"
                f"Synthesize a concise final answer for the user. Do NOT output NEED_7B or NEED_CLOUD markers."
            )
            r3 = await self._ollama_chat(DIALOG_MODEL, prompt_synth, DIALOG_TIMEOUT)
            if r3["ok"]:
                ans = r3["answer"]
                # Strip any leaked routing markers from synthesis output
                for marker in (NEED_7B_MARKER, NEED_CLOUD_MARKER):
                    if marker in ans:
                        idx = ans.find(marker)
                        ans = ans[:idx].strip()
                return ans if ans else f"[{source_label}] {result_text}"
            return f"[{source_label}] {result_text}"

        # 2a: NEED_CLOUD — local model explicitly requests cloud
        if NEED_CLOUD_MARKER in ans1:
            idx = ans1.find(NEED_CLOUD_MARKER)
            q_cloud = ans1[idx + len(NEED_CLOUD_MARKER):].strip()
            if cloud_ok:
                print("  [local → Cloud]", flush=True)
                cloud_ans = await self._cloud_query(
                    _downstream_prompt(ctx_str, question, q_cloud), context)
                if cloud_ans:
                    return await _synthesize("CLOUD_RESULT", cloud_ans)
                print("  [!] Cloud failed, falling back to local models...", flush=True)
            # Remove NEED_CLOUD marker, fall through to NEED_7B/14B below
            ans1 = ans1[:idx] + ans1[idx + len(NEED_CLOUD_MARKER) + len(q_cloud):].strip()

        # 2b: NEED_7B — local model requests deeper analysis
        if NEED_7B_MARKER in ans1:
            idx = ans1.find(NEED_7B_MARKER)
            q7b = ans1[idx + len(NEED_7B_MARKER):].strip()
            # 下游模型必须看到原始请求本体，见 _downstream_prompt 的说明
            full_prompt = _downstream_prompt(ctx_str, question, q7b)

            # Local fast pass first: 7B is the "rough scan" tier (fast, always resident)
            if has_7b:
                print("  [local → 7B]", flush=True)
                r2 = await self._ollama_chat("qwen2.5:7b", full_prompt, TIMEOUT_7B)
                if r2["ok"]:
                    return await _synthesize("7B_RESULT", r2["answer"])
                print(f"  [!] 7B failed ({r2.get('error', '?')}), moving on...", flush=True)

            # Heavy lift goes to cloud (sanitized) before 14B — 14B cold-load is too slow for one-shot flows
            if cloud_ok:
                print("  [7B failed → Cloud]", flush=True)
                cloud_ans = await self._cloud_query(full_prompt, context)
                if cloud_ans:
                    return await _synthesize("CLOUD_RESULT", cloud_ans)
                print("  [!] Cloud failed, trying 14B as last resort...", flush=True)

            # 14B only as last local resort (no cloud configured)
            if has_14b:
                print("  [local → 14B]", flush=True)
                r2 = await self._ollama_chat("qwen2.5:14b", full_prompt, TIMEOUT_14B)
                if r2["ok"]:
                    return await _synthesize("14B_RESULT", r2["answer"])

            # No cloud either
            return ans1.replace(NEED_7B_MARKER, "").strip()

        return ans1

    # Cloud provider registry: name -> (endpoint, default model)
    CLOUD_PROVIDERS = {
        "openai":   ("https://api.openai.com/v1/chat/completions", "gpt-4o-mini"),
        "gemini":   ("https://generativelanguage.googleapis.com/v1beta/openai/chat/completions", "gemini-3.6-flash"),
        "deepseek": ("https://api.deepseek.com/v1/chat/completions", "deepseek-chat"),
    }

    async def _cloud_query(self, prompt: str, context: dict | None = None, provider: str | None = None) -> str:
        """Send a pre-sanitized prompt to cloud. Returns raw answer or '' on failure.

        Tries the requested provider first (default: primary), then falls back
        to every other configured provider until one answers.
        """
        cfg = APIKeyManager.load()
        if not cfg:
            print("  [!] No cloud API key configured. Type 'cloud' to set one.")
            return ""

        providers = cfg.get("providers", {})
        if not providers:
            print("  [!] No cloud API key configured. Type 'cloud' to set one.")
            return ""

        # Build the provider attempt order: requested → primary → rest
        primary = cfg.get("primary")
        order: list[str] = []
        if provider and provider in providers:
            order.append(provider)
        if primary and primary in providers and primary not in order:
            order.append(primary)
        for p in providers:
            if p not in order:
                order.append(p)

        # 脱敏必须作用在真正发出去的文本上：原实现算了 safe_prompt 却把裸 prompt
        # 塞进 payload，等于完全没脱敏（路径/哈希原样出境）。
        safe_prompt = Sanitizer.prompt(prompt, context or {})
        import urllib.request
        last_err = ""
        for p in order:
            api_key = providers[p]
            spec = self.CLOUD_PROVIDERS.get(p)
            if not spec:
                print(f"  [cloud:{p}] unknown provider spec")
                continue
            url, model = spec
            headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
            payload = json.dumps({
                "model": model,
                "messages": [{"role": "user", "content": safe_prompt}],
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
                if answer:
                    if p != order[0]:
                        print(f"  [cloud] primary failed, {p} answered")
                    return answer
                last_err = "empty answer"
            except Exception as e:
                error_msg = str(e)
                if "401" in error_msg or "403" in error_msg or "auth" in error_msg.lower():
                    print(f"  [cloud:{p}] auth failed — check API key with 'cloud' command")
                elif "timeout" in error_msg.lower():
                    print(f"  [cloud:{p}] timeout: {e}")
                else:
                    print(f"  [cloud:{p}] error: {e}")
                last_err = error_msg
        print(f"  [!] All cloud providers failed: {last_err}")
        return ""
