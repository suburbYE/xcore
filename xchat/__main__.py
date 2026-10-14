"""X-Chat CLI entry point. Run with: python -m xchat"""

import argparse
import asyncio
import json
import sys

from .config import BASE_DIR
from .session import XChatSession


async def main():
    parser = argparse.ArgumentParser(description="X-Chat — Multi-model crypto analysis workbench")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--scan", metavar="FILE", help="Scan a file then enter interactive mode")
    mode.add_argument("--fetch", metavar="URL", help="Download URL to temp/, scan, then enter interactive mode")
    mode.add_argument("--analyze", metavar="URL", help="One-click: download → scan → learn → auto-ask → report to Desktop")
    mode.add_argument("--ask", metavar="QUESTION", help="One-shot question (requires prior scan from same dir)")
    parser.add_argument("--no-cloud", action="store_true", help="Disable cloud LLM fallback")
    parser.add_argument("--report", action="store_true", help="Dump session report")
    parser.add_argument("--native", action="store_true", help="Force Native Scanner for --scan (otherwise auto-detect by extension)")
    parser.add_argument("--non-interactive", action="store_true", help="Skip all input() prompts; with --scan/--fetch, scan then exit (for batch scripts)")
    args = parser.parse_args()

    session = XChatSession(cloud_ok=not args.no_cloud)

    if args.scan:
        await session.interactive(file_path=args.scan, native=args.native, non_interactive=args.non_interactive)
    elif args.fetch:
        await session.fetch(args.fetch)
        await session.interactive(non_interactive=args.non_interactive)
    elif args.analyze:
        await session.analyze(args.analyze)
    elif args.ask:
        reports_dir = BASE_DIR / "reports"
        latest = None
        if reports_dir.exists():
            reports = sorted(reports_dir.glob("xchat_report_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
            if reports:
                latest = reports[0]
        if latest:
            try:
                session.scan_context = json.loads(latest.read_text(encoding="utf-8")).get("scan_context")
            except Exception:
                pass
        if not session.scan_context:
            print("[!] No scan context found. Run 'scan' first or place a report in ./reports/.")
            return
        await session.ask(args.ask)
    elif args.report:
        session.save_report()
    else:
        await session.interactive()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, EOFError):
        print()
