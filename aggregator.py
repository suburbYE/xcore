#!/usr/bin/env python3
"""
X-Core Aggregator Sidecar v0.6.1
Frontline asset capture layer: intercept wasm/js/bin from URLs or extract from APKs,
pipe through xcore engine for crypto algorithm identification.

Usage:
  python aggregator.py url <https://target.com>           # Intercept page resources
  python aggregator.py apk <game.apk>                     # Extract from APK
  python aggregator.py url <url> --profile <chrome-dir>   # Inherit Chrome session
  python aggregator.py url <url> --json                   # JSON output
  python aggregator.py url <url> --deep                   # Deep algorithm identification
"""

import asyncio
import sys
import os
import argparse
import hashlib
import zipfile
import json
from pathlib import Path
try:
    from playwright.async_api import async_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False
    async_playwright = None

# ─── xchat imports for deep analysis ───
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))
try:
    from xchat import CaseLearner, LLMRouter
    HAS_DEEP = True
except ImportError:
    HAS_DEEP = False

# ─── Feature classification keywords (supplements extension-based filtering) ───
TARGET_KEYWORDS = ['wasm', 'crypto', 'sign', 'encrypt', 'decrypt', 'auth', 'jwt', 'token']
TARGET_EXTENSIONS = ('.js', '.wasm', '.bin', '.so', '.ts', '.mjs')

# Resolve xcore binary relative to this script's directory
XCORE_BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'xcore.exe')
if not os.path.exists(XCORE_BIN):
    # Fallback: try just 'xcore.exe' in PATH
    XCORE_BIN = 'xcore.exe'



class AggregatorSidecar:
    def __init__(self, rules_path, concurrency_limit=4, timeout=120, model="qwen2.5:3b", deep=False):
        self.rules_path = rules_path
        self.model = model
        self.deep = deep and HAS_DEEP
        self.semaphore = asyncio.Semaphore(concurrency_limit)
        self.timeout = timeout
        self.scanned_hashes = set()
        self.reports = []
        self.deep_results = []
        if self.deep:
            self.learner = CaseLearner(LLMRouter())

    # ── Hash Layer ────────────────────────────────────
    def calculate_hash(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    # ── Core Pipe ─────────────────────────────────────
    async def run_xcore_pipe(self, name: str, data: bytes):
        """Spawn xcore pipe subprocess, feed data via stdin, collect result."""
        data_hash = self.calculate_hash(data)
        if data_hash in self.scanned_hashes:
            return   # Memory-level dedup: reject repeat requests from SPA/polling
        self.scanned_hashes.add(data_hash)

        print(f"  [{len(self.scanned_hashes):>3}] {name[-52:]:>52}  sha256={data_hash[:12]}...", flush=True)

        async with self.semaphore:
            try:
                process = await asyncio.create_subprocess_exec(
                    XCORE_BIN, 'pipe', self.rules_path, '--model', self.model,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

                try:
                    stdout, stderr = await asyncio.wait_for(
                        process.communicate(input=data),
                        timeout=self.timeout,
                    )
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
                    self.reports.append({
                        'asset': name, 'hash': data_hash,
                        'status': 'TIMEOUT', 'output': '',
                    })
                    print(f"    [!] TIMEOUT after {self.timeout}s", flush=True)
                    return

                output_str = stdout.decode('utf-8', errors='ignore').strip()
                stderr_str = stderr.decode('utf-8', errors='ignore').strip()

                # Real-time BORDERLINE / error highlights
                if stderr_str:
                    for line in stderr_str.split('\n'):
                        if '[!]' in line or 'error' in line.lower():
                            print(f"    {line}", file=sys.stderr, flush=True)

                status = 'SUCCESS' if process.returncode == 0 else 'FAILED'
                self.reports.append({
                    'asset': name, 'hash': data_hash,
                    'status': status, 'output': output_str,
                })

                # Deep analysis: run CaseLearner on interesting assets (max 8)
                if self.deep and status == 'SUCCESS' and 'LLM:' in output_str and len(self.deep_results) < 8:
                    try:
                        pipe_result = {'hits': self._parse_hits(output_str)}
                        analysis = await self.learner.learn(name, data, data_hash, pipe_result)
                        if analysis:
                            self.deep_results.append(analysis)
                    except Exception:
                        pass
            except Exception as e:
                self.reports.append({
                    'asset': name, 'hash': data_hash,
                    'status': 'ERROR', 'output': str(e),
                })

    # ── Output ────────────────────────────────────────
    def _parse_hits(self, output_str: str) -> list[dict]:
        """Parse xcore output into structured hits (same as xchat.py)."""
        hits = []
        for line in output_str.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            hit = {}
            if "sim=" in line:
                try:
                    hit["sim"] = float(line.split("sim=")[1].split()[0])
                except Exception:
                    pass
            if "Case #" in line:
                try:
                    hit["id"] = line.split("Case #")[1].split()[0]
                except Exception:
                    pass
            if "[" in line and "]" in line:
                try:
                    b = line[line.index("[") + 1 : line.index("]")]
                    hit["algos"] = [a.strip().strip('"') for a in b.split(",")]
                except Exception:
                    pass
            if "Hard-lock" in line:
                hit["status"] = "hard-lock"
            if hit:
                hits.append(hit)
        return hits

    def print_deep_summary(self):
        """Print structured deep analysis results."""
        if not self.deep_results:
            print("\n[!] No deep analysis results (no LLM-classified assets found).")
            return

        print(f"\n{'=' * 88}")
        print(f" Deep Analysis: {len(self.deep_results)} assets analyzed")
        print(f"{'=' * 88}")

        # Aggregate by algorithm
        algo_map: dict[str, list[dict]] = {}
        for r in self.deep_results:
            for a in r.get("algorithms", []):
                name = a.get("name", "unknown")
                if name not in algo_map:
                    algo_map[name] = []
                algo_map[name].append(a)

        for name, results in sorted(algo_map.items(), key=lambda x: -len(x[1])):
            sample = results[0]
            lib = sample.get("library", "?")
            params = sample.get("parameters", {})
            conf = sample.get("confidence", "?")
            evidence = sample.get("evidence", "")[:100]
            print(f"\n  {name}  [{lib}]  (x{len(results)} assets)")
            print(f"    Params: {json.dumps(params, ensure_ascii=False)}")
            print(f"    Evidence: {evidence}")
            print(f"    Avg confidence: {conf}")

        # Print per-asset summary
        print(f"\n  Per-asset details:")
        for r in self.deep_results:
            asset = r.get("_asset", "?")
            algos = ", ".join(a.get("name", "?") for a in r.get("algorithms", []))
            print(f"    {asset[-60:]:>60} → {algos}")

    def print_reports(self, as_json=False):
        if as_json:
            import json
            print(json.dumps(self.reports, indent=2, ensure_ascii=False))
            return

        total = len(self.reports)
        success = sum(1 for r in self.reports if r['status'] == 'SUCCESS')
        skipped = sum(1 for r in self.reports if r['status'] == 'DEDUP')
        failed = total - success - skipped

        print(f"\n{'=' * 88}")
        print(f" Scan Summary: {total} total | {success} passed | {failed} failed | {skipped} dedup")
        print(f"{'=' * 88}")

        for r in self.reports:
            if r['status'] == 'DEDUP':
                continue
            short_name = r['asset'][-55:] if len(r['asset']) > 55 else r['asset']
            tag = {
                'SUCCESS': 'OK',
                'FAILED':  'FAIL',
                'TIMEOUT': 'TIME',
                'ERROR':   'ERR',
            }.get(r['status'], r['status'][:4])

            print(f"\n  [{tag}] {short_name}")
            print(f"       sha256={r['hash'][:12]}...")
            if r['output']:
                # Extract key lines from xcore output
                for line in r['output'].split('\n'):
                    stripped = line.strip()
                    if stripped and not stripped.startswith('{'):
                        print(f"       {stripped}")

        print(f"\n{'=' * 88}")
        print(f" Done: {success}/{total} assets classified successfully.\n")

    # ── URL Mode ──────────────────────────────────────
    async def scan_url(self, url: str, profile: str = None, visible: bool = False):
        """Side-channel interception: page.on('response') for passive harvesting."""
        if not HAS_PLAYWRIGHT:
            raise RuntimeError("playwright not installed. Run: pip install playwright && playwright install chromium")
        async with async_playwright() as p:
            if profile:
                context = await p.chromium.launch_persistent_context(
                    user_data_dir=profile,
                    headless=False,
                    args=['--disable-blink-features=AutomationControlled'],
                )
            else:
                browser = await p.chromium.launch(headless=not visible)
                context = await browser.new_context()

            page = await context.new_page()
            pending_tasks = set()

            async def on_response(response):
                url_str = response.url.split('?')[0].split('#')[0]
                should_intercept = (
                    url_str.endswith(TARGET_EXTENSIONS)
                    or any(k in url_str.lower() for k in TARGET_KEYWORDS)
                )
                if not should_intercept:
                    return

                try:
                    body = await response.body()
                    if body and len(body) > 0:
                        task = asyncio.create_task(
                            self.run_xcore_pipe(f"url::{url_str}", body)
                        )
                        pending_tasks.add(task)
                        task.add_done_callback(pending_tasks.discard)
                except Exception:
                    pass  # response body may be unavailable (streaming, redirect, etc.)

            page.on('response', on_response)

            print(f"\n[*] Navigating to {url} ...\n")
            try:
                await page.goto(url, wait_until='load', timeout=30000)
            except Exception as e:
                print(f"[!] Page load error: {e}", file=sys.stderr)

            # Wait for ongoing tasks + extra settling time for deferred resources
            print("[*] Page loaded. Waiting for deferred resources (15s)...\n")
            await asyncio.sleep(15)

            # Drain remaining tasks
            if pending_tasks:
                await asyncio.gather(*pending_tasks, return_exceptions=True)

            if profile:
                await context.close()
            else:
                await browser.close()

    # ── APK Mode ──────────────────────────────────────
    async def scan_apk(self, apk_path: str):
        """In-memory APK extraction: zipfile → filter wasm/js/so → pipe each into xcore."""
        if not os.path.exists(apk_path):
            print(f"[-] APK not found: {apk_path}", file=sys.stderr)
            return

        print(f"\n[*] Extracting {apk_path} in-memory ...\n")

        with zipfile.ZipFile(apk_path, 'r') as zf:
            entries = zf.namelist()

            # Priority sort: wasm/so first (algorithm heavy), js last (noise heavy)
            def entry_priority(name):
                if name.endswith('.wasm'):
                    return 0
                if name.endswith('.so'):
                    return 1
                if name.endswith('.bin'):
                    return 2
                return 3

            candidates = [
                e for e in entries
                if any(e.endswith(ext) for ext in TARGET_EXTENSIONS)
                or any(k in e.lower() for k in TARGET_KEYWORDS)
            ]
            candidates.sort(key=entry_priority)

            print(f"[*] {len(candidates)} candidates out of {len(entries)} entries\n")

            tasks = []
            for name in candidates:
                try:
                    data = zf.read(name)
                    if data:
                        task = asyncio.create_task(
                            self.run_xcore_pipe(f"apk::{name}", data)
                        )
                        tasks.append(task)
                except Exception as e:
                    print(f"  [!] Read error: {name} - {e}", file=sys.stderr)

            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)



# ─── CLI ──────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='X-Core Aggregator Sidecar — frontline asset capture + crypto classification',
    )
    parser.add_argument(
        'mode', choices=['url', 'apk'],
        help='Capture mode: url (Playwright interception) or apk (zip extraction)',
    )
    parser.add_argument(
        'target',
        help='Target URL (for url mode) or APK path (for apk mode)',
    )
    parser.add_argument(
        '--rules', default='rules/rules.json',
        help='Path to rules.json (default: rules/rules.json)',
    )
    parser.add_argument(
        '--profile',
        help='Chrome user-data-dir for persistent login state (url mode only)',
    )
    parser.add_argument(
        '--concurrency', type=int, default=4,
        help='Max concurrent xcore pipes (default: 4)',
    )
    parser.add_argument(
        '--timeout', type=int, default=120,
        help='Per-asset timeout in seconds (default: 120)',
    )
    parser.add_argument(
        '--model', default='qwen2.5:3b',
        help='Ollama model name for LLM fallback (default: qwen2.5:3b)',
    )
    parser.add_argument(
        '--json', action='store_true',
        help='Output machine-readable JSON instead of table',
    )
    parser.add_argument(
        '--visible', action='store_true',
        help='Show browser window (default: headless)',
    )
    parser.add_argument(
        '--deep', action='store_true',
        help='Deep algorithm identification (CaseLearner) on LLM-classified assets',
    )

    args = parser.parse_args()

    if args.mode == 'url' and not args.target.startswith('http'):
        print("[-] URL must start with http:// or https://", file=sys.stderr)
        sys.exit(1)

    if args.mode == 'apk' and not os.path.exists(args.target):
        print(f"[-] APK not found: {args.target}", file=sys.stderr)
        sys.exit(1)

    # Validate rules.json
    if not os.path.exists(args.rules):
        print(f"[-] Rules file not found: {args.rules}", file=sys.stderr)
        sys.exit(1)

    agg = AggregatorSidecar(
        rules_path=args.rules,
        concurrency_limit=args.concurrency,
        timeout=args.timeout,
        model=args.model,
        deep=args.deep,
    )

    async def run():
        if args.mode == 'url':
            await agg.scan_url(args.target, profile=args.profile, visible=args.visible)
        else:
            await agg.scan_apk(args.target)
        agg.print_reports(as_json=args.json)
        if args.deep:
            agg.print_deep_summary()

    asyncio.run(run())


if __name__ == '__main__':
    main()
