"""
Interactive session: the main X-Chat interrogation loop.

Handles scan / ask / learn / kb / cloud / report / NL-intent commands,
session persistence, and the interactive terminal UI.
"""

import asyncio
import gzip
import hashlib
import json
import os
import re
import glob
import sys
import urllib.request
import urllib.error
from pathlib import Path

from .config import (
    BASE_DIR, SESSION_FILE, MAX_HISTORY, REPORTS_DIR, DIALOG_MODEL,
)
from .intent import INTENT_PROMPT, INTENT_DIR_ALIASES, INTENT_TIMEOUT
from .llm_router import LLMRouter
from .api_key import APIKeyManager
from .pipe_runner import run_xcore_pipe, run_xcore_native
from .case_learner import CaseLearner


class XChatSession:
    WEB_EXTS = (".html", ".htm", ".js", ".mjs", ".wasm")

    def __init__(self, cloud_ok: bool = True):
        self.router = LLMRouter()
        self.cloud_ok = cloud_ok
        self.scan_context = None
        self.scanned_file = None
        self.learner = CaseLearner(self.router)
        self.session_history: list[dict] = []

    async def fetch(self, url: str):
        """Download file from URL, auto-name from Content-Disposition or URL path,
        save to temp/, then scan.
        """
        temp_dir = BASE_DIR / "temp"
        temp_dir.mkdir(parents=True, exist_ok=True)

        # Normalize bare hostnames → https://
        if url and not re.match(r'^https?://', url, re.I):
            url = "https://" + url
            print(f"  (normalized → {url})", flush=True)

        print(f"Fetching: {url}", flush=True)
        try:
            loop = asyncio.get_running_loop()

            def _download():
                req = urllib.request.Request(url, headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                })
                resp = urllib.request.urlopen(req, timeout=30)
                # Extract filename
                cd = resp.headers.get("Content-Disposition", "")
                fname_match = re.search(r'filename[^;=\n]*=["\']?([^"\';\n]+)', cd)
                if fname_match:
                    fname = fname_match.group(1).strip()
                else:
                    fname = url.rstrip("/").rsplit("/", 1)[-1].split("?")[0]
                if not fname or fname == url.rstrip("/"):
                    fname = "downloaded_file"
                data = resp.read()
                # Auto-decompress gzip content encoding
                if resp.headers.get("Content-Encoding") == "gzip" or data[:2] == b'\x1f\x8b':
                    data = gzip.decompress(data)
                return fname, data

            fname, data = await asyncio.wait_for(
                loop.run_in_executor(None, _download),
                timeout=30,
            )
        except urllib.error.HTTPError as e:
            print(f"[!] HTTP {e.code}: {e.reason}")
            return
        except asyncio.TimeoutError:
            print("[!] Download timed out (30s)")
            return
        except Exception as e:
            print(f"[!] Download failed: {e}")
            return

        out_path = temp_dir / fname
        out_path.write_bytes(data)
        # Phase 5w: extension-less payloads that look like HTML are saved as .html
        # so they route to the web pipeline instead of falling into native/pipe.
        if out_path.suffix.lower() not in self.WEB_EXTS:
            head = data[:64].lstrip().lower()
            if head.startswith(b"<!doctype") or head.startswith(b"<html"):
                out_path = out_path.with_suffix(".html")
                out_path.write_bytes(data)
        print(f"Saved: {out_path} ({len(data)} bytes)", flush=True)
        await self._run_scan(str(out_path))

    async def scan(self, file_path: str, native: bool = False):
        """Run xcore scan and store context. Check knowledge DB first.

        Auto-detects .so/.dll/.apk files and routes to Native Scanner.
        Pass ``native=True`` to force native mode for other binaries.
        """
        ext = os.path.splitext(file_path)[1].lower()
        is_native = native or ext in (".so", ".dll", ".apk")
        native_mode = "apk" if ext == ".apk" else "so"
        print(f"Scanning: {file_path}  [{'native' if is_native else 'pipe'}]", flush=True)

        await self._run_scan(file_path, native=native)

    async def _run_scan(self, file_path: str, native: bool = False):
        """Internal scan dispatcher. ELF magic bytes override .exe routing."""
        ext = os.path.splitext(file_path)[1].lower()
        # Detect ELF disguised as .exe (e.g., Quarkslab dataset)
        if not native and ext == ".exe":
            try:
                with open(file_path, "rb") as f:
                    if f.read(4) == b"\x7fELF":
                        native = True
            except Exception:
                pass
        is_native = native or ext in (".so", ".dll", ".apk")
        native_mode = "apk" if ext == ".apk" else "so"

        if is_native:
            await self._scan_native(file_path, mode=native_mode)
        elif ext in self.WEB_EXTS:
            await self._scan_web(file_path)
        else:
            await self._scan_pipe(file_path)

    async def _scan_web(self, file_path: str):
        """Web pipeline path (Phase 5w): xcore modules/web
        (web_fetcher + api_probe + wasm_analyzer via pipeline_web.js)."""
        web_dir = BASE_DIR / "modules" / "web"
        out_dir = BASE_DIR / "temp" / "web_out"
        out_dir.mkdir(parents=True, exist_ok=True)

        proc = await asyncio.create_subprocess_exec(
            "node", str(web_dir / "pipeline_web.js"),
            "--html", file_path, "--out", str(out_dir), "--json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            print(f"[!] Web scan failed: {stderr.decode(errors='replace')[:300]}")
            return

        try:
            report = json.loads(stdout.decode("utf-8", errors="replace"))
        except json.JSONDecodeError as e:
            print(f"[!] Web scan report parse error: {e}")
            return

        self.scanned_file = file_path
        self.scan_context = report
        self._print_web_report(report)

    def _print_web_report(self, report: dict):
        """Pretty-print a web pipeline report."""
        stages = report.get("stages", {})
        probe = stages.get("probe") or {}
        hits = probe.get("hits") or []
        wasm = stages.get("wasm") or []
        fetch = stages.get("fetch") or {}
        endpoints = fetch.get("endpoints") or []

        print(f"\n  Web source  : {report.get('source', '?')}")
        print(f"  Stages      : {', '.join(stages.keys()) or '-'}")
        if endpoints:
            print(f"  Endpoints   : {len(endpoints)}")
            for ep in endpoints[:10]:
                print(f"    - {ep}")
        if hits:
            print(f"  Probe hits  : {len(hits)}")
            for h in hits[:8]:
                kinds = ",".join(h.get("kinds", []))
                print(f"    [{kinds}] {h.get('file', '?')}:{h.get('line', '?')}  {h.get('code', '?')[:70]}")
        if wasm:
            for w in wasm:
                sections = [s.get("name", "?") for s in (w.get("sections") or [])]
                print(f"  WASM        : {w.get('url', '?')}  sections=[{','.join(sections)}] exports={len(w.get('exports') or [])}")
        artifacts = report.get("artifacts") or []
        if artifacts:
            print(f"  Artifacts   : {len(artifacts)} files")

    async def _scan_native(self, file_path: str, mode: str = "so"):
        """Native scanner path: xcore native --so/--apk."""
        result = await run_xcore_native(file_path, mode=mode)
        self.scanned_file = file_path

        if result.get("error"):
            print(f"[!] Scan error: {result['error']}")
            return

        self.scan_context = result

        # Shell classifier output (Phase 4a)
        if result.get("shell_class"):
            shell = result.get("shell", "?")
            confidence = result.get("confidence", "?")
            sc = result.get("shell_class", "?")
            next_step = result.get("next_step", "?")
            package = result.get("package", "?")
            evidence = result.get("evidence", [])

            print(f"\n  APK         : {os.path.basename(file_path)}")
            print(f"  Package     : {package}")
            print(f"  Shell       : {shell}")
            print(f"  Class       : {sc}")
            print(f"  Confidence  : {confidence}")
            print(f"  Next step   : {next_step}")
            if evidence:
                print(f"\n  Evidence ({len(evidence)} items):")
                for e in evidence[:12]:
                    print(f"    [{e.get('type', '?')}] {e.get('value', '?')[:80]}")
            print()
            return

        layers = result.get("layers", {})
        final_score = result.get("final_score", 0)
        verdict = result.get("verdict", "clean")
        algorithm = result.get("algorithm", "unknown")
        target = result.get("target", os.path.basename(file_path))
        arch = result.get("arch", "?")
        xrefs = result.get("xrefs", [])

        print(f"\n  Target      : {target}")
        print(f"  Arch        : {arch}")
        print(f"  Final score : {final_score}")
        print(f"  Verdict     : {verdict}")
        print(f"  Algorithm   : {algorithm}")
        if layers:
            print(f"\n  Layer scores:")
            for name, ld in layers.items():
                hits = ld.get("hits", [])
                hits_str = ", ".join(hits[:4]) if hits else "-"
                print(f"    {name}:  score={ld.get('score', 0):.2f}  [{hits_str}]")
        if xrefs:
            print(f"\n  String Xrefs: {len(xrefs)} entries")
            for x in xrefs[:5]:
                print(f"    {x.get('symbol', '?')} @ {x.get('offset', '?')} in {x.get('section', '?')}")
        print()

    async def _scan_pipe(self, file_path: str):
        """JS pipeline path: xcore pipe (deobfuscator engine)."""
        result = await run_xcore_pipe(file_path)
        self.scanned_file = file_path

        if result.get("error"):
            print(f"[!] Scan error: {result['error']}")
            return

        self.scan_context = result
        hits = result.get("hits", [])

        # Check knowledge DB for this file
        try:
            with open(file_path, "rb") as f:
                sha = hashlib.sha256(f.read(65536)).hexdigest()
            kb = self.learner.query_knowledge(sha)
            if kb:
                history = kb.get("_history", [])
                if history:
                    latest = history[-1]
                    algos = latest.get("algorithms", [])
                    print(f"\n  [kb] Knowledge DB hit: {len(history)} previous analyses")
                    for a in algos[:3]:
                        name = a.get("name", "?")
                        lib = a.get("library", "?")
                        conf = a.get("confidence", "?")
                        params = a.get("parameters", {})
                        print(f"       {name}  [{lib}]  conf={conf}  {params}")
        except Exception:
            pass

        if not hits:
            print("No crypto patterns detected.")
            return

        hardlocks = [h for h in hits if h.get("status") == "hard-lock"]
        soft = [h for h in hits if h.get("status") != "hard-lock"]

        print(f"\n┌─── Scan Results ─────────────────────────────┐")
        for h in hits:
            sid = h.get("id", "?")
            algos = ", ".join(h.get("algos", []))
            sim = h.get("sim", "?")
            status = h.get("status", "?")
            icon = "✓" if status == "hard-lock" else "?"
            print(f"│  {icon} Case #{sid}  [{algos}]  sim={sim}  ({status})")
        print(f"└──────────────────────────────────────────────┘")
        print(f"  Hard-locks: {len(hardlocks)}  Soft: {len(soft)}")
        print(f"  Local models available: {self.router.models_available}")
        print()

    async def ask(self, question: str):
        """All questions go through 3B as single dialog layer.
        3B handles general Q&A and scan analysis, requesting 7B for deep work.
        If question contains "丢桌面"/"保存到"/"写到 <path>", saves answer to file."""
        # Detect save-to-file instruction
        save_match = re.search(r'(?:丢|保存到|写到|存到)\s*(?:桌面|(.+))', question)
        save_path = None
        if save_match:
            loc = save_match.group(1) or "桌面"
            if loc.strip() == "桌面":
                save_path = str(Path.home() / "Desktop" / "xchat_answer.txt")
            else:
                save_path = loc.strip()
            question = re.sub(r'(?:丢|保存到|写到|存到)\s*(?:桌面|.+?)(?:\s*$|，|。)', '', question).strip()

        # Route to tool-augmented dialog when question mentions analysis targets
        tool_hint = re.search(r'(apk|\.so|\.dll|壳|脱壳|classify|扫描|scan|frida|probe|分析|native)', question, re.IGNORECASE)
        if tool_hint:
            answer = await self.router.ask_with_tools(question, self.scan_context, cloud_ok=self.cloud_ok)
        else:
            answer = await self.router.ask_3b(question, self.scan_context, cloud_ok=self.cloud_ok)

        self.session_history.append({"q": question, "a": answer})
        print(f"\n{answer}\n")

        if save_path:
            try:
                Path(save_path).parent.mkdir(parents=True, exist_ok=True)
                Path(save_path).write_text(answer, encoding="utf-8")
                print(f"[save] Answer written to {save_path}")
            except Exception as e:
                print(f"[!] Failed to save: {e}")

    async def analyze(self, url: str):
        """One-click pipeline: fetch → scan → learn → auto-ask → report.
        Downloads a file from URL, scans it, runs deep analysis, asks key questions,
        and saves a comprehensive report to Desktop.
        """
        print("=" * 60)
        print("X-Chat Analyze — One-click pipeline")
        print("=" * 60)
        print()

        # Step 1: Fetch
        print("[1/5] Downloading...")
        await self.fetch(url)
        if not self.scanned_file or not self.scan_context:
            print("[!] Abort: fetch failed or produced no scan context.")
            return
        print()

        # Step 2: Learn
        print("[2/5] Deep analysis...")
        hathits = bool(self.scan_context.get("hits", []))
        if hathits:
            await self.cmd_learn()
        else:
            print("  No hits to analyze — skipping learn.")
        print()

        # Step 3: Auto-ask — generate questions from scan context via 3B
        print("[3/5] Auto-interrogation...")
        if hathits:
            hits = self.scan_context.get("hits", [])
            hits_brief = "\n".join(
                f"  #{h.get('id', '?')}: {','.join(h.get('algos', []))} (status={h.get('status', '?')})"
                for h in hits
            )
            qgen_prompt = (
                f"Generate 3 specific, concise reverse-engineering questions about these crypto detection hits. "
                f"Focus on algorithm details, parameters, library origins, and implementation weaknesses. "
                f"Output ONLY one question per line, no numbering, no preamble:\n\n{hits_brief}"
            )
            r = await self.router._ollama_chat(DIALOG_MODEL, qgen_prompt, INTENT_TIMEOUT)
            if r["ok"]:
                questions = [q.strip().lstrip("1234567890.-) ").strip() for q in r["answer"].split("\n") if q.strip()]
                questions = questions[:5]
            else:
                # Fallback: generate questions from hit info
                algos_flat = []
                for h in hits:
                    algos_flat.extend(h.get("algos", []))
                questions = [
                    f"What algorithm is {a} and what library implements it?"
                    for a in set(algos_flat)[:3]
                ]
        else:
            questions = [
                f"What type of file is this? ({os.path.basename(self.scanned_file)})",
                "Is there any obfuscation or packing visible in this file?",
            ]

        for q in questions:
            print(f"\n  Q: {q}")
            answer = await self.router.ask_3b(q, self.scan_context, cloud_ok=self.cloud_ok)
            self.session_history.append({"q": q, "a": answer})
            # Brief preview
            preview = answer[:200].replace("\n", " ")
            print(f"  A: {preview}{'...' if len(answer) > 200 else ''}")

        print()

        # Step 4: Report
        print("[4/5] Saving report...")
        self.save_report()

        print()
        print(f"[5/5] Done. Report saved to {REPORTS_DIR}.")
        print("=" * 60)

    async def interactive(
        self,
        file_path: str | None = None,
        native: bool = False,
        non_interactive: bool = False,
    ):
        """Start interactive interrogation loop with session persistence.

        Args:
            file_path: If provided, scan this file before entering the loop.
            native: Force Native Scanner for ``file_path``.
            non_interactive: If True, skip all blocking ``input()`` prompts
                (API key config / session restore) and, when ``file_path`` is
                given, exit after scanning instead of entering the REPL.  This
                makes ``--scan`` safe for batch scripts.
        """
        if not APIKeyManager.load() and not non_interactive:
            print("Cloud fallback needs an API key (used when 3B/7B both fail).")
            # 非 TTY（管道/批处理）下不阻塞，提示后直接继续
            if sys.stdin.isatty():
                ans = input("Configure now? [Y/n] ").strip().lower()
                if ans != 'n':
                    key = input("Paste API key: ").strip()
                    if key:
                        if key.startswith("AIza"):
                            provider = "gemini"
                        elif key.startswith("sk-"):
                            # sk- prefix is shared by OpenAI and DeepSeek — ask explicitly
                            provider = "deepseek"
                            if sys.stdin.isatty():
                                ans = input("  sk- key belongs to OpenAI or DeepSeek? [openai/deepseek] ").strip().lower()
                                if ans == "openai":
                                    provider = "openai"
                        else:
                            provider = "deepseek"
                        APIKeyManager.add_provider(provider, key)
                        print(f"Cloud key saved (provider: {provider}).")
                    else:
                        print("Cloud disabled (no key provided).")
                else:
                    print("Skipped. Type 'cloud' later to configure.")
            else:
                print("Non-interactive: skipping API key prompt. Type 'cloud' later to configure.")

        prev = self._load_session()
        if prev and not file_path and not non_interactive:
            questions = len(prev.get("history", []))
            if questions > 0:
                print(f"[session] Previous session found: {questions} messages, last scan: {prev.get('scanned_file', 'none')}")
                restore = "n"
                if sys.stdin.isatty():
                    restore = input("Restore? [Y/n] ").strip().lower()
                if restore != 'n':
                    self.scanned_file = prev.get("scanned_file")
                    self.scan_context = prev.get("scan_summary")
                    self.session_history = prev.get("history", [])
                    self.cloud_ok = prev.get("cloud_ok", True)
                    if self.scan_context:
                        hits = self.scan_context.get("hits", [])
                        print(f"  Restored: {len(hits)} hits, {len(self.session_history)} messages")
                        if self.scanned_file:
                            try:
                                with open(self.scanned_file, "rb") as f:
                                    sha = hashlib.sha256(f.read(65536)).hexdigest()
                                kb = self.learner.query_knowledge(sha)
                                if kb:
                                    print(f"  [kb] Knowledge DB hit for this file")
                            except Exception:
                                pass

        if file_path:
            await self.scan(file_path, native=native)

        if non_interactive:
            # Batch mode: skip the REPL entirely — persist whatever was done and exit.
            self._save_session()
            print("[non-interactive] Done; exiting.")
            return

        print("Type 'scan <file>' to analyze, 'ask <question>' to query, 'learn' to deep-analyze, 'kb' for knowledge stats, 'exit' to quit.\n")

        while True:
            try:
                raw = input("xchat> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                self._save_session()
                break

            if not raw:
                continue

            parts = raw.split(None, 1)
            cmd = parts[0].lower()
            arg = parts[1] if len(parts) > 1 else ""

            if cmd == "exit":
                self._save_session()
                break
            elif cmd == "scan":
                if not arg:
                    print("[!] Usage: scan <file_path>")
                    continue
                await self.scan(arg)
            elif cmd == "fetch":
                if not arg:
                    print("[!] Usage: fetch <url>")
                    continue
                await self.fetch(arg)
            elif cmd == "ask":
                if not arg:
                    print("[!] Usage: ask <question>")
                    continue
                await self.ask(arg)
            elif cmd == "report":
                self.save_report()
            elif cmd == "cloud":
                self.cloud_ok = not self.cloud_ok
                print(f"Cloud fallback: {'ON' if self.cloud_ok else 'OFF'}")
                if self.cloud_ok:
                    cfg = APIKeyManager.load()
                    if cfg and cfg.get("providers"):
                        provs = cfg["providers"]
                        print(f"  Current providers: {', '.join(provs.keys())} (primary: {cfg.get('primary')})")
                        print("  Enter 'provider:key' to add/overwrite, 'primary <name>' to switch, blank to keep.")
                        inp = input("  > ").strip()
                        if not inp:
                            print("  Cloud config unchanged.")
                        elif inp.startswith("primary "):
                            name = inp.split(" ", 1)[1].strip()
                            if name in provs:
                                APIKeyManager.set_primary(name)
                                print(f"  Primary switched to {name}.")
                            else:
                                print(f"  Provider '{name}' not configured.")
                        else:
                            parts = inp.replace(":", " ").split(maxsplit=1)
                            if len(parts) == 2 and parts[0] in ("openai", "deepseek", "gemini"):
                                APIKeyManager.add_provider(parts[0], parts[1].strip())
                                print(f"  Cloud key saved ({parts[0]}).")
                            else:
                                print("  Invalid input. Use 'provider:key' (openai/deepseek/gemini).")
                    else:
                        print("  Cloud needs an API key. Enter provider+key, or leave blank to disable.")
                        provider = input("  Provider (openai/deepseek/gemini): ").strip().lower()
                        if provider in ("openai", "deepseek", "gemini"):
                            api_key = input(f"  {provider} API key: ").strip()
                            if api_key:
                                APIKeyManager.add_provider(provider, api_key)
                                print("  Cloud key saved.")
                            else:
                                self.cloud_ok = False
                                print("  Cloud disabled (no key provided).")
                        else:
                            self.cloud_ok = False
                            print("  Cloud disabled (invalid provider).")
            elif cmd == "learn":
                await self.cmd_learn()
            elif cmd == "kb":
                self.cmd_kb()
            else:
                # Natural language — parse intent via 3b
                intent = await self._parse_intent(raw)
                if not intent:
                    await self.ask(raw)
                    continue

                action = intent.get("action", "")

                if action == "find_scan":
                    d = intent.get("dir", ".")
                    p = intent.get("pattern", "*")
                    files = self._find_files(d, p)
                    if not files:
                        print(f"[!] No files matching '{p}' in {d}")
                        continue
                    print(f"[nl] Found {len(files)} file(s) in {d}:")
                    for f in files[:10]:
                        print(f"     {f}")
                    if len(files) > 10:
                        print(f"     ... and {len(files) - 10} more")
                    targets = files if len(files) <= 5 else files[:1]
                    for target in targets:
                        print(f"[nl] Auto-scanning: {target}")
                        await self.scan(target)
                        if self.scan_context and self.scan_context.get("hits"):
                            print("[nl] Auto-analyzing...")
                            await self.cmd_learn()
                    self.save_report()

                elif action == "find":
                    d = intent.get("dir", ".")
                    p = intent.get("pattern", "*")
                    files = self._find_files(d, p)
                    if not files:
                        print(f"[!] No files matching '{p}' in {d}")
                        continue
                    print(f"[nl] Found {len(files)} file(s) in {d}:")
                    for f in files:
                        print(f"     {f}")

                elif action == "scan":
                    path = intent.get("path", "")
                    if not path:
                        print("[!] No path in parsed intent")
                        continue
                    await self.scan(path)

                elif action == "ask":
                    q = intent.get("question", raw)
                    await self.ask(q)

                elif action == "learn":
                    await self.cmd_learn()

                elif action == "report":
                    self.save_report()

                elif action == "kb":
                    self.cmd_kb()

                elif action == "cloud":
                    self.cloud_ok = not self.cloud_ok
                    print(f"Cloud fallback: {'ON' if self.cloud_ok else 'OFF'}")
                    if self.cloud_ok:
                        cfg = APIKeyManager.load()
                        if cfg and cfg.get("providers"):
                            provs = cfg["providers"]
                            print(f"  Current providers: {', '.join(provs.keys())} (primary: {cfg.get('primary')})")
                            print("  Enter 'provider:key' to add/overwrite, 'primary <name>' to switch, blank to keep.")
                            inp = input("  > ").strip()
                            if not inp:
                                print("  Cloud config unchanged.")
                            elif inp.startswith("primary "):
                                name = inp.split(" ", 1)[1].strip()
                                if name in provs:
                                    APIKeyManager.set_primary(name)
                                    print(f"  Primary switched to {name}.")
                                else:
                                    print(f"  Provider '{name}' not configured.")
                            else:
                                parts = inp.replace(":", " ").split(maxsplit=1)
                                if len(parts) == 2 and parts[0] in ("openai", "deepseek", "gemini"):
                                    APIKeyManager.add_provider(parts[0], parts[1].strip())
                                    print(f"  Cloud key saved ({parts[0]}).")
                                else:
                                    print("  Invalid input. Use 'provider:key' (openai/deepseek/gemini).")
                        else:
                            print("  Cloud needs an API key. Enter provider+key, or leave blank to disable.")
                            provider = input("  Provider (openai/deepseek/gemini): ").strip().lower()
                            if provider in ("openai", "deepseek", "gemini"):
                                api_key = input(f"  {provider} API key: ").strip()
                                if api_key:
                                    APIKeyManager.add_provider(provider, api_key)
                                    print("  Cloud key saved.")
                                else:
                                    self.cloud_ok = False
                                    print("  Cloud disabled (no key provided).")
                            else:
                                self.cloud_ok = False
                                print("  Cloud disabled (invalid provider).")

                elif action == "exit":
                    self._save_session()
                    break

                else:
                    await self.ask(raw)

    def save_report(self, save_to: str | None = None):
        """Export session report."""
        if not self.session_history and not self.scan_context:
            print("[!] Nothing to report.")
            return

        report = {
            "scan_context": self.scan_context,
            "dialog": self.session_history,
        }
        if save_to:
            out_dir = Path(save_to)
        else:
            out_dir = BASE_DIR / "reports"
        out_dir.mkdir(parents=True, exist_ok=True)
        fname = out_dir / f"xchat_report_{os.getpid()}.json"
        fname.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Report saved: {fname}")

    async def cmd_learn(self):
        """Deep analysis: identify specific algorithm implementations."""
        if not self.scanned_file or not self.scan_context:
            print("[!] Nothing to learn. Run 'scan <file>' first.")
            return
        try:
            with open(self.scanned_file, "rb") as f:
                data = f.read(65536)
        except Exception as e:
            print(f"[!] Cannot read file: {e}")
            return

        sha256 = hashlib.sha256(data).hexdigest()
        print(f"Deep analysis: {self.scanned_file} ({len(data)} bytes, sha256={sha256[:16]}...)")
        analysis = await self.learner.learn(
            os.path.basename(self.scanned_file), data, sha256, self.scan_context
        )
        if analysis:
            algos = analysis.get("algorithms", [])
            if algos:
                for a in algos:
                    print(f"  {a.get('name', '?')}  [{a.get('library', '?')}]  conf={a.get('confidence', '?')}")
            else:
                print(f"  Summary: {analysis.get('summary', 'N/A')[:200]}")
        else:
            print("[!] Analysis failed.")
        print()

    def cmd_kb(self):
        """Show knowledge base stats."""
        stats = self.learner.stats()
        print(f"\nKnowledge DB: {stats['total']} entries")
        if stats["algorithms"]:
            for name, count in sorted(stats["algorithms"].items(), key=lambda x: -x[1])[:10]:
                print(f"  {name}: {count}")
        print()

    def _condense_scan_context(self) -> dict | None:
        if not self.scan_context or not self.scanned_file:
            return None
        hits = self.scan_context.get("hits", [])
        condensed_hits = []
        for h in hits:
            ch = {"id": h.get("id")}
            # Shell classifier fields
            if h.get("shell"):
                ch.update({
                    "shell": h.get("shell"),
                    "confidence": h.get("confidence"),
                    "shell_class": h.get("shell_class"),
                    "next_step": h.get("next_step"),
                    "evidence_count": h.get("evidence_count"),
                })
            # Target scan fields
            else:
                ch.update({
                    "algos": h.get("algos"),
                    "sim": h.get("sim"),
                    "status": h.get("status"),
                })
            condensed_hits.append(ch)
        return {
            "file": self.scanned_file,
            "hits": condensed_hits,
            "total": self.scan_context.get("total"),
        }

    def _save_session(self):
        if not self.session_history and not self.scan_context:
            return
        data = {
            "scanned_file": self.scanned_file,
            "scan_summary": self._condense_scan_context(),
            "history": self.session_history[-MAX_HISTORY:],
            "cloud_ok": self.cloud_ok,
        }
        try:
            SESSION_FILE.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        except Exception as e:
            print(f"[!] Session save failed: {e}")

    def _load_session(self) -> dict | None:
        if not SESSION_FILE.exists():
            return None
        try:
            return json.loads(SESSION_FILE.read_text(encoding="utf-8"))
        except Exception:
            return None

    async def _parse_intent(self, raw: str) -> dict | None:
        """Parse natural language input into structured command using the local dialog model."""
        if not self.router.has_model(DIALOG_MODEL):
            return None
        prompt = f"{INTENT_PROMPT}\n\nUser input: {raw}\n\nJSON:"
        result = await self.router._ollama_chat(DIALOG_MODEL, prompt, INTENT_TIMEOUT)
        if not result["ok"] or not result["answer"]:
            return None
        ans = result["answer"].strip()

        if ans.startswith("```"):
            m = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', ans)
            if m:
                ans = m.group(1).strip()

        start = ans.find("{")
        end = ans.rfind("}") + 1
        if start < 0 or end <= start:
            return {"action": "ask", "question": raw}

        json_str = ans[start:end]
        json_str = re.sub(r'\\(?![\\/bfnrtu"])', r'', json_str)

        try:
            intent = json.loads(json_str)
        except json.JSONDecodeError:
            return {"action": "ask", "question": raw}

        alias = intent.pop("dir_alias", None)
        if alias:
            alias_upper = alias.upper()
            if alias_upper in INTENT_DIR_ALIASES:
                intent["dir"] = INTENT_DIR_ALIASES[alias_upper]
            else:
                intent["dir"] = "."

        if intent.get("action") == "learn" and ("path" in intent or "pattern" in intent or "dir" in intent):
            intent["action"] = "find_scan"

        if raw.startswith("http://") or raw.startswith("https://") or "http://" in intent.get("pattern", "") or "https://" in intent.get("pattern", ""):
            intent = {"action": "ask", "question": raw}

        return intent

    @staticmethod
    def _find_files(directory: str, pattern: str) -> list[str]:
        """Glob search for files, return sorted absolute paths."""
        search = str(Path(directory) / pattern) if directory != "." else pattern
        results = glob.glob(search, recursive=True)
        return sorted(results)
