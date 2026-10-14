"""
pipeline_runner.py — xcore 001→004 管道调度器

串联:
  1. IDAPython Headless 提取伪代码 + 种子变量
  2. BB 提取 + Unicorn 微执行 → 产出 trace contract
  3. IR 切片 → 产出 sliced_prompt.c

用法:
  # 真实模式 (需要 IDA Pro)
  python pipeline_runner.py libtarget.so 0x1A3C -a AES -o out/

  # Mock 模式 (内置合成 AES 伪代码测试)
  python pipeline_runner.py --mock -o out/

作者: xcore
许可: MIT
"""

from __future__ import annotations

import argparse
import json
import os
import struct
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Optional

# 动态设置路径 (支持从仓库根执行)
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from modules.native.bb_extractor import extract_core_bb, match_loop_counter, BasicBlock, match_loop_counter_cross_bb, build_cfg
from modules.native.micro_executor import MicroExecutor, DMPEngine, TraceResult
from modules.native.ir_slicer_psc import slice_pseudocode, inject_anchor_header, infer_seed_vars

# ────────────────────────────────────────────────────────────
# 路径常量
# ────────────────────────────────────────────────────────────

SCRIPTS_DIR = PROJECT_ROOT / "scripts"
IDA_EXPORTER = SCRIPTS_DIR / "ida_exporter.py"


# ────────────────────────────────────────────────────────────
# Stage 1: IDAPython 提取
# ────────────────────────────────────────────────────────────

def stage1_idapython(
    so_path: str,
    target_rva: int,
    output_dir: str,
    ida_path: str = "idat64.exe",
) -> tuple[str, list[str], dict]:
    """
    运行 IDAPython Headless 提取伪代码。

    返回:
        (raw_pseudocode, seed_vars, anchors_dict)
    """
    if not Path(so_path).exists():
        raise FileNotFoundError(f"SO file not found: {so_path}")

    os.makedirs(output_dir, exist_ok=True)

    # 写入辅助配置文件 (TARGET_RVA)
    rva_config = os.path.join(output_dir, "rva_config.py")
    with open(rva_config, "w") as f:
        f.write(f"TARGET_RVA = {target_rva:#x}\n")

    cmd = [
        ida_path,
        "-A",                           # 自动模式
        f"-S{IDA_EXPORTER} {output_dir}",
        "-L", os.path.join(output_dir, "ida.log"),
        so_path,
    ]
    print(f"[Stage1] Running IDA: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

    if result.returncode != 0:
        print(f"[Stage1] IDA stderr: {result.stderr}")

    # 读取产物
    pseudo_path = os.path.join(output_dir, "pseudocode.c")
    seeds_path  = os.path.join(output_dir, "seeds.json")
    anchors_path = os.path.join(output_dir, "anchors.json")

    if not Path(pseudo_path).exists():
        raise RuntimeError("IDA did not produce pseudocode.c")

    with open(pseudo_path, "r", encoding="utf-8") as f:
        raw_pseudocode = f.read()

    seed_vars = []
    if Path(seeds_path).exists():
        with open(seeds_path, "r") as f:
            seed_vars = json.load(f).get("seed_vars", [])

    anchors = {}
    if Path(anchors_path).exists():
        with open(anchors_path, "r") as f:
            anchors = json.load(f)

    print(f"[Stage1] Done: {len(raw_pseudocode)} chars, seeds={seed_vars}, anchors={len(anchors)}")
    return raw_pseudocode, seed_vars, anchors


# ────────────────────────────────────────────────────────────
# Stage 1b: Mock 模式 (无 IDA 时的内置测试数据)
# ────────────────────────────────────────────────────────────

MOCK_AES_PSEUDOCODE = r"""__int64 __fastcall aes128_encrypt(__int64 plaintext, __int64 key, __int64 output)
{
  __int128 state;
  __int128 roundkey;
  unsigned int round;

  state = *(_OWORD *)plaintext;
  roundkey = *(_OWORD *)key;
  for ( round = 10; round; --round )
  {
    state = _aese(state, roundkey);
    state = _aesmc(state);
  }
  *(_OWORD *)output = state;
  return output;
}"""

MOCK_AES_BB_BYTES = bytes([
    # AES-128 循环核心: 初始化 + 循环体 + B.NE + RET
    # MOV W8, #10            ; round = 10
    # .loop:
    # EOR X0, X0, X1         ; state ^= roundkey  (模拟 _aese)
    # ROR X0, X0, #8         ; 模拟 _aesmc
    # SUBS W8, W8, #1        ; round--
    # B.NE .loop
    # STR X0, [X2]           ; *output = state
    # RET
    0x48, 0x01, 0x80, 0x52,  # MOV W8, #10
    0x00, 0x00, 0x01, 0xCA,  # EOR X0, X0, X1
    0x00, 0x20, 0xC0, 0x93,  # EXTR X0, X0, X0, #8  (ROR #8)
    0x08, 0x05, 0x00, 0x71,  # SUBS W8, W8, #1
    0xA1, 0xFF, 0xFF, 0x54,  # B.NE -0xC  → EOR
    0x40, 0x00, 0x00, 0xF9,  # STR X0, [X2]
    0xC0, 0x03, 0x5F, 0xD6,  # RET
])


def stage1_mock(algo_hint: str = "AES") -> tuple[str, list[str], dict]:
    """内置合成测试数据。"""
    print("[Stage1-Mock] Using built-in mock pseudocode")
    raw = MOCK_AES_PSEUDOCODE
    seeds = infer_seed_vars(raw)
    anchors = {}
    return raw, seeds, anchors


# ────────────────────────────────────────────────────────────
# Stage 2: BB 提取 + 微执行
# ────────────────────────────────────────────────────────────

def stage2_execute(
    so_path: Optional[str],
    target_rva: int,
    algo_hint: str,
    anchors: dict,
    use_mock: bool = False,
) -> TraceResult:
    """
    从 .so 中提取目标 BB，Unicorn 微执行，返回 TraceResult。
    """
    if use_mock:
        # Mock 模式: 用内置 AES 字节码
        code = MOCK_AES_BB_BYTES
        base_rva = 0x1000
        print(f"[Stage2-Mock] Using built-in AES bytes ({len(code)} bytes)")
    else:
        # 真实模式: 从 .so 读取目标函数字节码
        if not so_path or not Path(so_path).exists():
            raise FileNotFoundError(f"SO not found: {so_path}")
        # TODO: 使用 lief/pyelftools 解析 ELF，定位 target_rva 对应指令
        # 目前简化: 读取文件，从 target_rva 偏移取 MAX_BB_SIZE 字节
        MAX_BB_SIZE = 0x200
        with open(so_path, "rb") as f:
            f.seek(target_rva)
            code = f.read(MAX_BB_SIZE)
        base_rva = target_rva
        print(f"[Stage2] Read {len(code)} bytes from {so_path} @ 0x{target_rva:X}")

    # 反汇编 + BB 提取
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    bbs = extract_core_bb(code, base_rva=base_rva, md=md)

    if not bbs:
        raise RuntimeError("No basic blocks extracted")

    print(f"[Stage2] Extracted {len(bbs)} BB(s)")

    # 选择主 BB（优先取含循环惯用语的）
    main_bb = bbs[0]
    cross_bb_result = None
    for bb in bbs:
        if match_loop_counter(bb.insns):
            main_bb = bb
            break
    else:
        # 单 BB 未命中 → 跨 BB 回退（CFG 平坦化场景）
        cfg = build_cfg(bbs)
        cross_bb_result = match_loop_counter_cross_bb(bbs, cfg)
        if cross_bb_result:
            main_bb = bbs[cross_bb_result["bb_index"]]

    # 微执行 (001)
    me = MicroExecutor(algorithm_hint=algo_hint)

    # DMP 双跑
    trace_a = me.execute(
        bb=main_bb,
        plaintext=bytes(range(0x00, 0x10)),
        key=bytes(range(0x10, 0x20)),
        function_name="dmp_plain_a",
        loop_info=cross_bb_result,
    )
    trace_b = me.execute(
        bb=main_bb,
        plaintext=bytes(range(0x20, 0x30)),
        key=bytes(range(0x30, 0x40)),
        function_name="dmp_plain_b",
        loop_info=cross_bb_result,
    )
    dmp = DMPEngine.compare(trace_a, trace_b)
    trace_a.dmp_status = dmp.status
    trace_a.dmp_confidence = dmp.confidence
    # 回写 contract，修正 DMP 状态
    if hasattr(trace_a, "contract"):
        trace_a.contract["dmp_status"] = dmp.status
        trace_a.contract["confidence"] = 0.95 if dmp.confidence == "HIGH" else 0.0

    print(f"[Stage2] Trace: {trace_a.executed_inst_count} insts, "
          f"DMP={dmp.status}/{dmp.confidence}, path_hash={trace_a.path_hash}")
    return trace_a


# ────────────────────────────────────────────────────────────
# Stage 3: IR 切片
# ────────────────────────────────────────────────────────────

def stage3_slice(
    raw_pseudocode: str,
    seed_vars: list[str],
    trace: TraceResult,
) -> str:
    """结合 contract 对伪代码切片。"""
    lines = raw_pseudocode.split("\n")

    # 优先复用 MicroExecutor 内置的 contract，否则自建
    contract = getattr(trace, "contract", None) or {
        "function": trace.function,
        "algorithm": "UNKNOWN",
        "confidence": "MEDIUM",
        "anchors": {},
        "loop_info": {},
        "dmp_status": getattr(trace, "dmp_status", "UNKNOWN"),
        "path_hash": trace.path_hash,
        "executed_inst_count": trace.executed_inst_count,
    }

    header = inject_anchor_header(contract)
    sliced = slice_pseudocode(lines=lines, seed_vars=seed_vars, trace_json=contract)

    result = header + "\n" + "\n".join(sliced)

    print(f"[Stage3] Sliced: {len(lines)}→{len(sliced)} lines, "
          f"output {len(result)} chars")
    return result


# ────────────────────────────────────────────────────────────
# 主入口
# ────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="xcore 001→004 Pipeline Runner")
    parser.add_argument("so_path", nargs="?", help="目标 .so 文件路径")
    parser.add_argument("target_rva", nargs="?", type=lambda x: int(x, 0),
                        default=0, help="目标函数 RVA (如 0x1A3C)")
    parser.add_argument("-a", "--algorithm", default="AES",
                        help="算法提示 (AES/SM4/SHA256)")
    parser.add_argument("-o", "--output-dir", default="output",
                        help="输出目录 (默认 output)")
    parser.add_argument("--mock", action="store_true",
                        help="使用内置 AES 模拟数据 (无需 IDA)")
    parser.add_argument("--ida", default="idat64.exe",
                        help="IDA 可执行文件路径")
    args = parser.parse_args()

    if not args.mock and not args.so_path:
        parser.error("需要提供 so_path 或使用 --mock")

    os.makedirs(args.output_dir, exist_ok=True)

    # ── Stage 1: 提取伪代码 ──
    if args.mock:
        raw, seeds, anchors = stage1_mock(args.algorithm)
    else:
        raw, seeds, anchors = stage1_idapython(
            args.so_path, args.target_rva,
            args.output_dir, args.ida,
        )

    # ── Stage 2: 微执行 ──
    trace = stage2_execute(
        args.so_path, args.target_rva,
        args.algorithm, anchors,
        use_mock=args.mock,
    )

    # ── Stage 3: 切片 ──
    sliced_prompt = stage3_slice(raw, seeds, trace)

    # ── 输出 ──
    out_path = os.path.join(args.output_dir, "sliced_prompt.c")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(sliced_prompt)

    print(f"\n{'='*60}")
    print(f"  Pipeline complete: {out_path}")
    print(f"  {len(sliced_prompt)} chars ready for LLM")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
