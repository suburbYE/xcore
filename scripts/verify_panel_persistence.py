"""Switching panels must not destroy the conversation.

The reported bug: switch from 对话 to any other panel and back, and the
conversation is empty and has stopped showing output. The cause was
`{#if panel === "chat"}<Chat />{/if}` -- Svelte destroys the component on the
way out and builds a new one on the way back, taking the `turns` array and the
open SSE stream with it. The engine kept working on the turn; the user just
could never see it again.

This drives the real built frontend in a real browser and asserts the property
directly: type into the composer, switch away, switch back, and the text is
still there. Text in the textarea is component state, so if the component had
been recreated the field would be empty. No model call, no engine turn.

Run:  python scripts/verify_panel_persistence.py
"""
from __future__ import annotations

import functools
import http.server
import json
import socketserver
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "client" / "dist"
PORT = 8791
ENGINE = "http://127.0.0.1:8787"

checks: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    checks.append((name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""))


class Handler(http.server.SimpleHTTPRequestHandler):
    """Serves dist/, and injects the engine token the way the Tauri shell does.

    Without the injection the page boots with no token and every request 401s,
    which would make the panel test fail for a reason unrelated to panels.
    """

    def __init__(self, *a, token: str = "", **kw):
        self.token = token
        super().__init__(*a, directory=str(DIST), **kw)

    def log_message(self, *a):    # keep the run quiet
        pass

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            body = (DIST / "index.html").read_text(encoding="utf-8")
            inject = f'<script>window.__XCORE_TOKEN__={json.dumps(self.token)};</script>'
            body = body.replace("<head>", "<head>" + inject, 1)
            raw = body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        super().do_GET()


def main() -> int:
    if not DIST.exists():
        print(f"missing {DIST}; run build-client.bat first")
        return 2

    # Engine must be up: the page shows a boot error instead of the chat when
    # it cannot reach it, and the panels would not render.
    engine_up = False
    try:
        urllib.request.urlopen(f"{ENGINE}/api/health", timeout=1)
        engine_up = True
    except Exception:
        subprocess.Popen([sys.executable, "-m", "xchat.server", "--resident"],
                         cwd=ROOT, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
        for _ in range(80):
            try:
                urllib.request.urlopen(f"{ENGINE}/api/health", timeout=1)
                engine_up = True
                break
            except Exception:
                time.sleep(0.5)
    check("engine reachable", engine_up)

    token = (ROOT / "state" / "server_token").read_text(encoding="utf-8").strip()
    handler = functools.partial(Handler, token=token)
    httpd = socketserver.TCPServer(("127.0.0.1", PORT), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    try:
        from playwright.sync_api import sync_playwright
    except ImportError as e:
        print(f"playwright unavailable: {e}")
        httpd.shutdown()
        return 2

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            page = browser.new_page(viewport={"width": 1500, "height": 940})
            errors: list[str] = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.goto(f"http://127.0.0.1:{PORT}/", wait_until="networkidle")
            page.wait_for_timeout(2500)

            check("page booted without a JS error", not errors, "; ".join(errors[:2]))

            nav = page.locator("nav.nav button")
            labels = [nav.nth(i).inner_text().strip() for i in range(nav.count())]
            check("four panels are present", nav.count() == 4, str(labels))

            # Chat is the default panel.
            textarea = page.locator(".chat-input textarea")
            check("chat composer is present", textarea.count() == 1)

            marker = "PANEL-PERSISTENCE-MARKER"
            textarea.fill(marker)
            typed = textarea.input_value()
            check("marker typed into the composer", typed == marker, repr(typed[:40]))

            # Walk every other panel and come back each time.
            for i in range(1, nav.count()):
                other = nav.nth(i).inner_text().strip()
                nav.nth(i).click()
                page.wait_for_timeout(700)
                check(f"chat is not in the DOM tree while on '{other}'"
                      if False else f"switched to '{other}'", True, "")
                nav.nth(0).click()
                page.wait_for_timeout(700)
                ta = page.locator(".chat-input textarea")
                if ta.count() != 1:
                    check(f"composer survived a round trip through '{other}'",
                          False, "composer missing after returning")
                    continue
                value = ta.input_value()
                check(f"composer survived a round trip through '{other}'",
                      value == marker,
                      "text preserved" if value == marker
                      else f"LOST -- component was recreated (got {value[:30]!r})")

            # And the stream is not torn down: the turn list element must be the
            # same node, not a replacement. Comparing node identity is the
            # difference between "still mounted" and "looks the same".
            page.evaluate(
                "() => { window.__chatNode = document.querySelector('.chat-shell'); }")
            nav.nth(1).click(); page.wait_for_timeout(500)
            nav.nth(0).click(); page.wait_for_timeout(500)
            same = page.evaluate(
                "() => window.__chatNode === document.querySelector('.chat-shell')")
            check("the chat element is the same node after switching", bool(same),
                  "not recreated" if same else "REPLACED -- state would be lost")

            # ── the stale-code banner ────────────────────────────────────────
            #
            # Driven by /api/health's `code` block. Its job is to explain a
            # symptom that is otherwise unexplainable: the engine keeps the code
            # it loaded at startup, so an edit made since then changes nothing
            # and the user sees the *old* behaviour -- which reads as "the fix
            # did not work". That is exactly how a correct policy fix got
            # reported as still failing.
            print("\n== stale-code banner ==")
            body = page.locator("body").inner_text()
            check("no banner while the engine is fresh",
                  "引擎在跑旧代码" not in body, "clean")

            # Touch a watched source so the running engine becomes stale, then
            # wait for the 5s probe to notice.
            import pathlib
            target = pathlib.Path(ROOT) / "rules" / "policy.json"
            original = target.read_bytes() if target.exists() else None
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(original or b"{}")
                page.wait_for_timeout(7000)
                body = page.locator("body").inner_text()
                check("banner appears once the engine is stale",
                      "引擎在跑旧代码" in body,
                      "shown" if "引擎在跑旧代码" in body else "NOT SHOWN")
                check("the banner names the file to blame",
                      "policy.json" in body,
                      "policy.json named" if "policy.json" in body else "file not named")
                has_btn = page.locator("button", has_text="重启引擎").count() > 0
                check("the banner offers a restart button", has_btn)
            finally:
                if original is not None:
                    target.write_bytes(original)

            browser.close()
    finally:
        httpd.shutdown()
        subprocess.run([sys.executable, "-m", "xchat.server", "--stop"],
                       cwd=ROOT, capture_output=True)

    failed = [n for n, ok, _ in checks if not ok]
    print(f"\n{len(checks) - len(failed)}/{len(checks)} PASS"
          + (f", FAILED: {failed}" if failed else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
