"""Backward-compatible stub. Use `python -m xchat` instead."""

from xchat.__main__ import main
import asyncio

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, EOFError):
        print()
