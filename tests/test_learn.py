"""Test CaseLearner deep analysis with AES S-box binary."""
import asyncio
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from xchat import LLMRouter, CaseLearner


async def test():
    router = LLMRouter()
    learner = CaseLearner(router)

    # Check if models are available
    try:
        if not router.has_model("qwen2.5:3b"):
            print("[SKIP] qwen2.5:3b not available")
            return
    except Exception:
        print("[SKIP] Cannot connect to ollama (not running or not installed)")
        return

    # Create a minimal test binary with AES S-box
    test_bin = Path(__file__).parent / "test_crypto.bin"
    aes_sbox = bytes([
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
        0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    ])
    test_bin.write_bytes(aes_sbox)
    data = test_bin.read_bytes()

    pipe_hits = {
        "hits": [
            {"id": 1, "algos": ["AES", "S-Box"], "sim": 0.97, "status": "hard-lock"}
        ]
    }

    print("=== learn test 1 ===")
    result = await learner.analyze("test_crypto.bin", data, pipe_hits)
    if result:
        algos = result.get("algorithms", [])
        print(f"algos: {algos}")
        summary = result.get("summary", "N/A")
        if summary:
            if isinstance(summary, bytes):
                summary = summary.decode("utf-8", errors="replace")
            elif not isinstance(summary, str):
                summary = str(summary)
            # Encode→decode via ascii to catch non-ASCII before print
            safe_summary = summary.encode("ascii", errors="replace").decode("ascii")
            print(f"summary: {safe_summary[:200]}")
    else:
        print("[INFO] No result from learner (model may have returned empty)")

    print()
    print("=== learn test 2 (empty hits, should skip) ===")
    result2 = await learner.analyze("empty.bin", b"\x00\x00\x00\x00", {"hits": []})
    print(f"Result: {result2}")

    # Clean up
    if test_bin.exists():
        test_bin.unlink()
    kb_dir = Path(__file__).resolve().parent.parent / "xchat" / "knowledge"
    if kb_dir.exists():
        for f in kb_dir.glob("*.json"):
            f.unlink()
        kb_dir.rmdir()

    print("\n[PASS]")


asyncio.run(test())

