"""
Phase 5a: CFG semantic parser — analyze IDA Pro / Binary Ninja pseudocode
and control-flow graph screenshots to identify crypto primitives and
obfuscation patterns (OLLVM, control-flow flattening).

Design note: llm_router currently does not support vision natively;
this module uses _vision_client as a standalone vision call path.
"""

from __future__ import annotations

import json
import re

from ._vision_client import call_vision


# ─── CFG Analysis ─────────────────────────────────────────────────────────────


def analyze_cfg_image(image_path: str, provider: str = "auto") -> dict:
    """Analyze an IDA Pro / Binary Ninja CFG or pseudocode screenshot.

    Uses a cloud VLM with a reverse-engineering-specific prompt to identify:
    - AES / SM4 / ChaCha20 cryptographic primitives (S-Box, key expansion)
    - OLLVM control-flow flattening (large switch-case dispatchers)
    - Obfuscated loop patterns
    - Function addresses (if visible in the screenshot)

    Args:
        image_path: Absolute path to the screenshot (.png / .jpg).
        provider: VLM provider — ``"auto"`` (try Gemini → OpenAI),
            ``"gemini"``, ``"openai"``, or ``"deepseek"``.

    Returns:
        dict with keys:
            - ``functions``: list of {address, name_hint, type, algorithm_hint,
              confidence, evidence, recommendation}
            - ``ollvm_blocks``: list of {address, type, pattern, num_cases}
            - ``loops``: list of {address, type, iterations}
            - ``summary``: human-readable one-paragraph summary

    Raises:
        RuntimeError: If the VLM call fails or no credentials are configured.
        FileNotFoundError: If ``image_path`` does not exist.
    """
    prompt = (
        "You are a senior binary reverse engineer analyzing an IDA Pro / "
        "Binary Ninja screenshot.  This is a pseudocode window or control-flow "
        "graph (CFG) from a native library (ARM/ARM64/x86) that uses code "
        "obfuscation.  Extract structured intelligence.\n\n"
        "Reverse-engineering-specific patterns to identify:\n\n"
        "=== Cryptographic Primitives ===\n"
        "- AES: Look for S-Box lookups (0x63, 0x7c, 0x77, 0x7b pattern or "
        "Te0/Te1/Te2/Te3 tables), 10/12/14-round key expansion loops with "
        "RotWord/SubWord/MixColumns.  Typical evidence: XOR with round constant "
        "0x01/0x02/0x04/0x08/0x10/0x20/0x40/0x80/0x1B/0x36.\n"
        "- SM4: Look for FK constants (0xA3B1BAC6, 0x56AA3350, 0x677D9197, "
        "0xB27022DC) or CK constants (0x00070E15, 0x1C232A31, ...).  Also "
        "non-linear S-Box tau transform and linear L transform "
        "(L(B) = B ^ ROL(B,2) ^ ROL(B,10) ^ ROL(B,18) ^ ROL(B,24)).\n"
        "- ChaCha20: Quarter-round with 4x4 matrix, constant 'expand 32-byte k', "
        "ADDs and XORs with 16/12/7/8 rotation pattern.\n"
        "- RC4: 256-byte S-Box init with KSA (key-scheduling) and PRGA loop.\n"
        "- MD5 / SHA family: F/G/H/I round functions, magic constants "
        "(0x67452301 etc.), round shift amounts [7,12,17,22,...].\n"
        "- Base64 custom table: alphabet string != standard A-Za-z0-9+/.\n\n"
        "=== Obfuscation Patterns ===\n"
        "- OLLVM flattening (控制流平坦化): Large switch-case dispatcher block "
        "with state variable, many case labels, indirect jumps.\n"
        "- OLLVM bogus control flow (虚假控制流): Opaque predicates leading to "
        "dead code branches (e.g. y = x * (x+1) % 2 always 0).\n"
        "- OLLVM instruction substitution: Repeated patterns of arithmetic "
        "expansion (e.g. a+b replaced by a-(-b), a^b via (a|b)-(a&b)).\n"
        "- String encryption / stack strings: XOR loops over char arrays.\n\n"
        "=== Loop Patterns ===\n"
        "- Key expansion: Fixed-iteration loop (10/11/12/14) with rotate/shift/S-Box.\n"
        "- Memcpy-like: word/byte copy with two incrementing pointers.\n"
        "- Infinite obfuscation loop: while(true) + opaque condition.\n\n"
        "Instructions:\n"
        "1. For each identified function, provide: address (if visible), "
        "name_hint, type (crypto/obfuscation/other), algorithm_hint (e.g. "
        "'AES key expansion', 'SM4 round function'), confidence (high/medium/low), "
        "evidence (specific patterns observed), recommendation (where to hook "
        "for key capture).\n"
        "2. For OLLVM blocks: address, type (dispatcher/bogus_block), pattern "
        "description, num_cases if applicable.\n"
        "3. For loops: address, type (key_expansion/memcpy/infinite), iteration count.\n"
        "4. Provide a 'summary' paragraph in English — 2-3 sentences describing "
        "the most actionable findings.\n"
        "5. Return ONLY valid JSON — no markdown fences, no explanations.\n\n"
        "Output schema:\n"
        "{\n"
        '  "functions": [\n'
        '    {"address": "0x1A4F0", "name_hint": "sub_1A4F0", "type": "crypto", '
        '"algorithm_hint": "AES-128 key expansion", "confidence": "high", '
        '"evidence": "S-Box lookup at 0x1A4F8, 10-round loop with Rcon XOR at 0x1A520", '
        '"recommendation": "Hook at 0x1A4F0 entry to capture 16-byte key"}\n'
        '  ],\n'
        '  "ollvm_blocks": [\n'
        '    {"address": "0x1B200", "type": "dispatcher", '
        '"pattern": "switch-case main dispatcher with state var", "num_cases": 16}\n'
        '  ],\n'
        '  "loops": [\n'
        '    {"address": "0x1A500", "type": "key_expansion", "iterations": 10}\n'
        '  ],\n'
        '  "summary": "Found 1 suspected AES-128 encrypt function at 0x1A4F0 '
        'with visible S-Box and 10-round key expansion.  Also found 1 OLLVM '
        'flattening dispatcher at 0x1B200 (16 cases).  Recommend hooking 0x1A4F0 '
        'entry for key extraction."\n'
        "}"
    )

    raw = call_vision(prompt, image_path, provider)

    # Parse JSON — VLM may wrap in ```json fences
    raw = raw.strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```[a-zA-Z]*\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)

    result = json.loads(raw)

    # Ensure all expected keys exist with defaults
    defaults: dict = {
        "functions": [],
        "ollvm_blocks": [],
        "loops": [],
        "summary": "",
    }
    for k, v in defaults.items():
        result.setdefault(k, v)

    # Normalize function entries
    func_keys = {"address", "name_hint", "type", "algorithm_hint", "confidence",
                 "evidence", "recommendation"}
    for fn in result.get("functions", []):
        for k in func_keys:
            fn.setdefault(k, None if k == "address" else "")

    # Normalize ollvm block entries
    block_keys = {"address", "type", "pattern", "num_cases"}
    for blk in result.get("ollvm_blocks", []):
        for k in block_keys:
            default_val = 0 if k == "num_cases" else (None if k == "address" else "")
            blk.setdefault(k, default_val)

    # Normalize loop entries
    loop_keys = {"address", "type", "iterations"}
    for lp in result.get("loops", []):
        for k in loop_keys:
            default_val = 0 if k == "iterations" else (None if k == "address" else "")
            lp.setdefault(k, default_val)

    return result
