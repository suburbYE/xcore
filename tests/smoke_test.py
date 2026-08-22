"""
smoke_test.py — xcore 四模块集成烟雾测试

用合成 ARM64 AES 循环字节码 + 模拟 AES 伪代码跑端到端。

作者: xcore
许可: MIT
"""

import sys
from pathlib import Path

# 路径引导
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "modules" / "native"))
sys.path.insert(0, str(PROJECT_ROOT))

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

from modules.native.register_view import RegisterView, NEONVectorNode
from modules.native.bb_extractor import extract_core_bb, match_loop_counter
from modules.native.micro_executor import (
    MicroExecutor, DMPEngine,
    _page_align_down, _page_align_up, _page_align_size,
)
from modules.native.ir_slicer_psc import (
    slice_pseudocode, inject_anchor_header, infer_seed_vars,
)

# ────────────────────────────────────────────────────────────
# 硬编码 ARM64 字节码: MOV W8,#10 + SUBS + B.NE + RET
# 避免 keystone 依赖
# ────────────────────────────────────────────────────────────

# MOV W8, #10; loop: SUBS W8, W8, #1; B.NE loop; RET
AES_LOOP_BYTES = bytes([
    0x28, 0x01, 0x80, 0x52,  # MOVZ W8, #0x9  (实际是 MOV W8, #9 → 纠正为 #10)
    0x08, 0x05, 0x00, 0x71,  # SUBS W8, W8, #1
    0xC1, 0xFF, 0xFF, 0x54,  # B.NE -4 (loop back)
    0xC0, 0x03, 0x5F, 0xD6,  # RET
])

# 我们手工汇编: MOV W8, #10 的正确编码
# ARM64 MOVZ Wd, #imm16, lsl #shift
# 10 = 0xA, 无左移
# MOVZ W8, #10: 0x52 80 01 48 → 小端: 48 01 80 52... 
# 实际上 0x52800148 在 Capstone 反汇编后应该是 MOV W8, #10
# 让我们用 ARM64 正确编码

# 用 python 直接构造(已知正确的编码):
# movz w8, #10: 11010010100_0000000000001010_01000 = 0x52800148
MOV_W8_10    = bytes([0x48, 0x01, 0x80, 0x52])  # MOVZ W8, #10 (little-endian)
SUBS_W8_W8_1 = bytes([0x08, 0x05, 0x00, 0x71])  # SUBS W8, W8, #1
B_NE_LOOP    = bytes([0xC1, 0xFF, 0xFF, 0x54])  # B.NE -4 (offset -4 instruction)
RET_A64      = bytes([0xC0, 0x03, 0x5F, 0xD6])  # RET

AES_LOOP_BYTES = MOV_W8_10 + SUBS_W8_W8_1 + B_NE_LOOP + RET_A64

# 完整函数: stp + mov w8,#10 + loop(aese/aesmc) + str + ldp + ret
# 实际就用 AES_LOOP_BYTES 作为目标
AES_FULL_BYTES = (
    bytes([0xFD, 0x7B, 0xBF, 0xA9]) +  # STP X29, X30, [SP, #-16]!
    bytes([0xFD, 0x03, 0x00, 0x91]) +  # MOV X29, SP
    MOV_W8_10 +
    SUBS_W8_W8_1 +
    B_NE_LOOP +
    bytes([0xFD, 0x7B, 0xC1, 0xA8]) +  # LDP X29, X30, [SP], #16
    RET_A64
)


# ────────────────────────────────────────────────────────────
# 模拟 AES 伪代码 (IDA decompile 风格)
# ────────────────────────────────────────────────────────────

MOCK_AES_PSEUDO = r"""__int64 __fastcall sub_1A3C(__int64 a1, __int64 a2, __int64 a3)
{
  __int64 result; // x0
  __int64 v4; // x8
  __int128 v5; // q0
  __int128 v6; // q1
  int v7; // w9

  v5 = *(_OWORD *)a1;
  v6 = *(_OWORD *)a2;
  v7 = 10;
  do
  {
    v5 = _aese(v5, v6);
    v5 = _aesmc(v5);
    --v7;
  }
  while ( v7 );
  *(_OWORD *)a3 = v5;
  return a3;
}"""

MOCK_SEED_VARS = ["a1", "a2", "a3"]


# ────────────────────────────────────────────────────────────
# 测试用例
# ────────────────────────────────────────────────────────────

def test_register_view():
    """Test: RegisterView 基础解析"""
    alias, width = RegisterView.resolve_alias("W8")
    assert alias == "R8", f"Unexpected alias: {alias}"
    assert width == 32, f"Unexpected bit width: {width}"

    alias2, width2 = RegisterView.resolve_alias("X8")
    assert alias2 == "R8", f"Unexpected alias: {alias2}"
    assert width2 == 64, f"Unexpected bit width: {width2}"

    num = RegisterView.parse_reg_num("W9")
    assert num == 9

    print("[PASS] test_register_view")

def test_page_align():
    """Test: _page_align 三函数"""
    assert _page_align_down(0x1234) == 0x1000
    assert _page_align_up(0x1234)   == 0x2000
    base, size = _page_align_size(0x1234, 0x567)
    assert base == 0x1000
    assert size == 0x2000
    print("[PASS] test_page_align")

def test_bb_extractor():
    """Test: extract_core_bb + match_loop_counter"""
    code = AES_FULL_BYTES
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    bbs = extract_core_bb(code, base_rva=0x1000, md=md)
    assert bbs, "extract_core_bb returned empty"

    # 第一个 BB 应包含 loop
    loop_bb = bbs[0]
    info = match_loop_counter(loop_bb.insns)
    assert info is not None, "match_loop_counter missed AES-128 pattern"
    assert info["value"] == 10, f"Expected 10 rounds, got {info['value']}"
    print(f"[PASS] test_bb_extractor: {len(bbs)} BB(s), loop={info}")

def test_micro_executor():
    """Test: MicroExecutor 微执行 AES 循环"""
    code = AES_LOOP_BYTES
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    bbs = extract_core_bb(code, base_rva=0x1000, md=md)
    assert bbs, "BB extraction failed"

    me = MicroExecutor(algorithm_hint="AES")
    trace = me.execute(bb=bbs[0], function_name="aes_loop_test")

    assert trace.executed_inst_count > 0, "No instructions executed"
    assert trace.path_hash, "path_hash is empty"
    assert trace.registers, "Register dump is empty"

    print(f"[PASS] test_micro_executor: {trace.executed_inst_count} insts, "
          f"PC={hex(trace.registers.get('PC', 0))}")

def test_dmp_compare():
    """Test: DMP 双跑对比"""
    code = AES_LOOP_BYTES
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    bbs = extract_core_bb(code, base_rva=0x1000, md=md)

    me = MicroExecutor(algorithm_hint="AES")

    plain_a = bytes(range(0x00, 0x10))
    key_a   = bytes(range(0x10, 0x20))
    plain_b = bytes(range(0x20, 0x30))
    key_b   = bytes(range(0x30, 0x40))

    trace_a = me.execute(bb=bbs[0], plaintext=plain_a, key=key_a, function_name="dmp_a")
    trace_b = me.execute(bb=bbs[0], plaintext=plain_b, key=key_b, function_name="dmp_b")

    dmp = DMPEngine.compare(trace_a, trace_b)
    assert dmp.status in ("PATH_ALIGNED", "PATH_DIVERGED"), f"Unexpected DMP status: {dmp.status}"

    print(f"[PASS] test_dmp_compare: {dmp.status} / confidence={dmp.confidence} "
          f"({trace_a.executed_inst_count} vs {trace_b.executed_inst_count} insts)")

def test_ir_slice():
    """Test: ir_slicer_psc 切片 + inject_anchor_header"""
    lines = MOCK_AES_PSEUDO.split("\n")

    # 切片
    sliced = slice_pseudocode(lines=lines, seed_vars=MOCK_SEED_VARS)

    assert sliced, "slice_pseudocode returned empty"
    assert len(sliced) < len(lines), f"Slice not smaller: {len(sliced)} >= {len(lines)}"

    # 关键行应保留
    sliced_text = "\n".join(sliced)
    assert "aese" in sliced_text.lower() or "v5" in sliced_text, "Missing key variable in slice"

    # Anchor header
    contract = {
        "function": "sub_1A3C",
        "algorithm": "AES-128",
        "confidence": "HIGH",
        "dmp_status": "PATH_ALIGNED",
        "path_hash": "abc123def456",
        "executed_inst_count": 22,
        "loop_info": {"counter_reg": "W8", "total_iterations": 10},
        "anchors": {"sbox": {"rva": "0x402000", "size": 256}},
    }
    header = inject_anchor_header(contract)
    assert "@algorithm AES-128" in header
    assert "@loop W8=10" in header

    print(f"[PASS] test_ir_slice: {len(lines)}→{len(sliced)} lines, header={len(header)} chars")

def test_infer_seed_vars():
    """Test: infer_seed_vars 自动识别"""
    seeds = infer_seed_vars(MOCK_AES_PSEUDO)
    assert "a1" in seeds, f"Missing a1 in seeds: {seeds}"
    assert "a2" in seeds, f"Missing a2 in seeds: {seeds}"
    print(f"[PASS] test_infer_seed_vars: {seeds}")

def test_four_module_imports():
    """Test: 四模块全部可导入"""
    from modules.native.register_view  import RegisterView, NEONVectorNode
    from modules.native.bb_extractor   import extract_core_bb, is_block_end, match_loop_counter
    from modules.native.micro_executor import MicroExecutor, DMPEngine
    from modules.native.ir_slicer_psc  import slice_pseudocode, inject_anchor_header, infer_seed_vars
    print("[PASS] test_four_module_imports")


# ────────────────────────────────────────────────────────────
# Main
# ────────────────────────────────────────────────────────────

def main():
    tests = [
        ("imports",  test_four_module_imports),
        ("reg_view", test_register_view),
        ("align",    test_page_align),
        ("bb_extr",  test_bb_extractor),
        ("micro",    test_micro_executor),
        ("dmp",      test_dmp_compare),
        ("ir_slice", test_ir_slice),
        ("infer",    test_infer_seed_vars),
    ]

    passed = 0
    failed = []

    for name, fn in tests:
        try:
            fn()
            passed += 1
        except Exception as e:
            print(f"[FAIL] {name}: {e}")
            import traceback
            traceback.print_exc()
            failed.append(name)

    print(f"\n{'='*50}")
    print(f"  Smoke Test: {passed}/{len(tests)} PASSED")
    if failed:
        print(f"  FAILURES: {', '.join(failed)}")
    print(f"{'='*50}")

    sys.exit(0 if not failed else 1)

if __name__ == "__main__":
    main()
