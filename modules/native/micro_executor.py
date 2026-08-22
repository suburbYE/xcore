"""
micro_executor.py — Unicorn 微执行器

核心 BB 切片模拟执行 + 锚点注入 + DMP 双跑降级。
产出 JSON 契约供 004 ir_slicer_psc 使用。

依赖: capstone, unicorn, register_view, bb_extractor

作者: xcore
许可: MIT
"""

from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
from unicorn.arm64_const import (
    UC_ARM64_REG_X0,
    UC_ARM64_REG_X1,
    UC_ARM64_REG_X2,
    UC_ARM64_REG_X3,
    UC_ARM64_REG_X4,
    UC_ARM64_REG_X5,
    UC_ARM64_REG_X6,
    UC_ARM64_REG_X7,
    UC_ARM64_REG_X8,
    UC_ARM64_REG_X9,
    UC_ARM64_REG_X10,
    UC_ARM64_REG_X11,
    UC_ARM64_REG_X12,
    UC_ARM64_REG_X13,
    UC_ARM64_REG_X14,
    UC_ARM64_REG_X15,
    UC_ARM64_REG_X16,
    UC_ARM64_REG_X17,
    UC_ARM64_REG_X18,
    UC_ARM64_REG_X19,
    UC_ARM64_REG_X20,
    UC_ARM64_REG_X21,
    UC_ARM64_REG_X22,
    UC_ARM64_REG_X23,
    UC_ARM64_REG_X24,
    UC_ARM64_REG_X25,
    UC_ARM64_REG_X26,
    UC_ARM64_REG_X27,
    UC_ARM64_REG_X28,
    UC_ARM64_REG_SP,
    UC_ARM64_REG_LR,
    UC_ARM64_REG_PC,
)

from .bb_extractor import (
    BasicBlock,
    extract_core_bb,
    is_block_end,
    match_loop_counter,
    _extract_branch_target,
)
from .register_view import RegisterView

# ────────────────────────────────────────────────────────────
# 常量
# ────────────────────────────────────────────────────────────

PAGE_SIZE = 0x1000                                   # 4KB

# 模拟内存布局
CODE_BASE   = 0x100000                               # 2MB 代码段基址
STACK_BASE  = 0x300000                               # 1MB 栈基址
STACK_SIZE  = 0x100000
ANCHOR_PLAINTEXT = 0x400000                          # 锚点: Plaintext Buffer (0x400000-0x401FFF)
ANCHOR_KEY       = 0x402000                          # 锚点: Key Buffer       (0x402000-0x403FFF)
ANCHOR_SBOX      = 0x404000                          # 锚点: S-Box            (0x404000-0x405FFF)
ANCHOR_REGION_SIZE = 0x2000                          # 每个锚点区域 8KB

# AES-128 标准 S-Box (前 16 字节)
AES_SBOX_HEAD = bytes([
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
])

# 高熵已知 Plaintext 模式串
ANCHOR_PLAINTEXT_PATTERN = bytes(range(0x00, 0x10))           # 0x00..0x0F

# 已知固定 Key (AES-128)
ANCHOR_KEY_PATTERN = bytes([
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
    0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
])

# 模拟硬上限
MAX_INSTRUCTIONS = 500
MAX_TIMEOUT_US   = 3_000_000                         # 3 秒

# X 寄存器表 (索引 0-28 + SP(31) + LR(30))
_XREG_TABLE = [
    UC_ARM64_REG_X0,  UC_ARM64_REG_X1,  UC_ARM64_REG_X2,  UC_ARM64_REG_X3,
    UC_ARM64_REG_X4,  UC_ARM64_REG_X5,  UC_ARM64_REG_X6,  UC_ARM64_REG_X7,
    UC_ARM64_REG_X8,  UC_ARM64_REG_X9,  UC_ARM64_REG_X10, UC_ARM64_REG_X11,
    UC_ARM64_REG_X12, UC_ARM64_REG_X13, UC_ARM64_REG_X14, UC_ARM64_REG_X15,
    UC_ARM64_REG_X16, UC_ARM64_REG_X17, UC_ARM64_REG_X18, UC_ARM64_REG_X19,
    UC_ARM64_REG_X20, UC_ARM64_REG_X21, UC_ARM64_REG_X22, UC_ARM64_REG_X23,
    UC_ARM64_REG_X24, UC_ARM64_REG_X25, UC_ARM64_REG_X26, UC_ARM64_REG_X27,
    UC_ARM64_REG_X28,
]

# ────────────────────────────────────────────────────────────
# 数据结构
# ────────────────────────────────────────────────────────────

@dataclass
class TraceResult:
    """单次 Unicorn 模拟执行结果"""
    function: str                                   # 函数名 / RVA
    executed_inst_count: int
    path_hash: str                                  # 指令序列哈希
    registers: Dict[str, int]                       # X0-X28 + SP/LR
    memory_dump: bytes                              # 完整模拟内存 dump
    exit_reason: str                                # "EXIT_INSTRUCTION" / "MAX_COUNT" / "ERROR"
    error_msg: str = ""

    def to_contract(self) -> dict:
        """转为 001→004 JSON 契约"""
        return {
            "function": self.function,
            "algorithm": "Unknown",
            "confidence": 0.0,
            "anchors": {},
            "loop_info": {},
            "dmp_status": "SINGLE_RUN",
            "path_hash": self.path_hash,
            "executed_inst_count": self.executed_inst_count,
        }


@dataclass
class DMPResult:
    """DMP 双跑对比结果"""
    status: str                                      # "PATH_ALIGNED" | "PATH_DIVERGED"
    confidence: str                                  # "HIGH" | "LOW"
    constant_regions: List[dict] = field(default_factory=list)
    dynamic_regions: List[dict] = field(default_factory=list)
    divergence_point: Optional[int] = None


# ────────────────────────────────────────────────────────────
# 内存对齐
# ────────────────────────────────────────────────────────────

def _page_align_down(addr: int) -> int:
    """向下对齐到 4KB 边界"""
    return addr & ~(PAGE_SIZE - 1)


def _page_align_up(addr: int) -> int:
    """向上对齐到 4KB 边界"""
    return (addr + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)


def _page_align_size(addr: int, size: int) -> Tuple[int, int]:
    """
    返回页对齐后的基址和大小（基址向下对齐，size 向上覆盖到页边界）。
    Unicorn mem_map 强制要求 4KB 对齐。
    """
    aligned_addr = _page_align_down(addr)
    end = addr + size
    aligned_end = _page_align_up(end)
    return aligned_addr, aligned_end - aligned_addr

# ────────────────────────────────────────────────────────────
# 模拟执行 Hook
# ────────────────────────────────────────────────────────────

class _InstructionTracer:
    """指令计数 + 路径哈希收集"""

    def __init__(self):
        self.count = 0
        self.insn_hashes: List[int] = []

    def hook(self, uc: Uc, address: int, size: int, user_data):
        self.count += 1
        self.insn_hashes.append(address)

    @property
    def path_hash(self) -> str:
        raw = struct.pack(f"<{len(self.insn_hashes)}I", *self.insn_hashes)
        return hashlib.sha256(raw).hexdigest()[:16]


# ────────────────────────────────────────────────────────────
# MicroExecutor
# ────────────────────────────────────────────────────────────

class MicroExecutor:
    """
    Unicorn 微执行器。

    用法:
        me = MicroExecutor()
        result = me.execute(bb, algo_hint="AES")

        # DMP 双跑
        result_a = me.execute(bb, plaintext_A, key)
        result_b = me.execute(bb, plaintext_B, key)
        dmp = DMPEngine.compare(result_a, result_b)
    """

    def __init__(self, algorithm_hint: str = "AES"):
        self.algorithm_hint = algorithm_hint              # "AES" | "SHA256" | "SM4" | None
        self.md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        self.md.detail = True

    # ── 主入口 ──

    def execute(
        self,
        bb: BasicBlock,
        plaintext: Optional[bytes] = None,
        key: Optional[bytes] = None,
        function_name: str = "unknown",
        loop_info: Optional[dict] = None,
    ) -> TraceResult:
        """
        模拟执行一个 BB。

        参数:
            bb:        目标 BasicBlock
            plaintext: 自定义明文（DMP 降级时传入）
            key:       自定义密钥
            function_name: 函数标识
            loop_info: 外部预计算的循环计数结果，传入时跳过内部惯用语匹配

        返回:
            TraceResult，含寄存器 + 内存 dump
        """
        # 1. 惯用语匹配 → 获取循环计数
        if loop_info is None:
            loop_info = match_loop_counter(bb.insns)

        # 2. 分配 Unicorn
        uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self._map_memory(uc, bb)

        # 3. 写入代码
        code = b"".join(insn.bytes for insn in bb.insns)
        uc.mem_write(CODE_BASE + bb.start_rva - _page_align_down(bb.start_rva), code)

        # 4. 初始化寄存器
        self._init_registers(uc, loop_info)

        # 5. 锚点注入 或 DMP 自定义输入
        if plaintext and key:
            self._inject_custom_input(uc, plaintext, key)
        else:
            self._anchor_inject(uc, self.algorithm_hint)

        # 6. 设置 hook + 执行
        tracer = _InstructionTracer()
        uc.hook_add(4, tracer.hook)                    # UC_HOOK_CODE (v2: 4)

        start_addr = CODE_BASE + bb.start_rva - _page_align_down(bb.start_rva)
        end_addr = CODE_BASE + bb.end_rva + 4 - _page_align_down(bb.start_rva)

        exit_reason = "OK"
        error_msg = ""
        try:
            uc.emu_start(start_addr, end_addr, timeout=MAX_TIMEOUT_US, count=MAX_INSTRUCTIONS)
        except Exception as e:
            exit_reason = "ERROR"
            error_msg = str(e)

        if tracer.count >= MAX_INSTRUCTIONS:
            exit_reason = "MAX_COUNT"

        # 7. Dump 结果
        regs = self._dump_registers(uc)
        mem = self._dump_memory(uc)

        result = TraceResult(
            function=function_name,
            executed_inst_count=tracer.count,
            path_hash=tracer.path_hash,
            registers=regs,
            memory_dump=mem,
            exit_reason=exit_reason,
            error_msg=error_msg,
        )

        # 8. 填充 anchor 信息到契约
        self._annotate_contract(result, loop_info)

        return result

    # ── 内存映射 ──

    def _map_memory(self, uc: Uc, bb: BasicBlock):
        """映射代码段、栈、锚点区域"""
        # 代码段 (2MB)
        uc.mem_map(CODE_BASE, 2 * 1024 * 1024)

        # 栈 (1MB)
        uc.mem_map(STACK_BASE, STACK_SIZE)

        # 锚点区域
        uc.mem_map(ANCHOR_PLAINTEXT, ANCHOR_REGION_SIZE)
        uc.mem_map(ANCHOR_KEY, ANCHOR_REGION_SIZE)
        uc.mem_map(ANCHOR_SBOX, ANCHOR_REGION_SIZE)

        # 设置 SP
        uc.reg_write(UC_ARM64_REG_SP, STACK_BASE + STACK_SIZE - 0x1000)

    # ── 寄存器初始化 ──

    def _init_registers(self, uc: Uc, loop_info: Optional[dict]):
        """初始化通用寄存器"""
        # 全部归零
        for reg in _XREG_TABLE:
            uc.reg_write(reg, 0)

        # 惯用语匹配结果 → 设置循环计数器
        if loop_info:
            reg_str = loop_info["reg"]                 # "W8" / "X8"
            value = loop_info["value"]
            reg_num = RegisterView.parse_reg_num(reg_str)
            uc.reg_write(_XREG_TABLE[reg_num], value)

    # ── 锚点注入 ──

    def _anchor_inject(self, uc: Uc, algo_hint: str):
        """标准算法锚点注入"""
        if algo_hint and algo_hint.upper() == "AES":
            uc.mem_write(ANCHOR_PLAINTEXT, ANCHOR_PLAINTEXT_PATTERN)
            uc.mem_write(ANCHOR_KEY, ANCHOR_KEY_PATTERN)
            # S-Box (标准 AES Rijndael)
            uc.mem_write(ANCHOR_SBOX, AES_SBOX_HEAD)
        elif algo_hint and algo_hint.upper() == "SM4":
            # SM4 S-Box (前 16 字节)
            sm4_sbox_head = bytes([
                0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7,
                0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
            ])
            uc.mem_write(ANCHOR_SBOX, sm4_sbox_head)
        # 不抛异常——未知算法静默跳过锚点注入，后续 DMP 降级接管

    def _inject_custom_input(self, uc: Uc, plaintext: bytes, key: bytes):
        """DMP 降级: 自定义明文 + 密钥注入"""
        uc.mem_write(ANCHOR_PLAINTEXT, plaintext.ljust(16, b"\x00")[:16])
        uc.mem_write(ANCHOR_KEY, key.ljust(16, b"\x00")[:16])

    # ── Dump ──

    def _dump_registers(self, uc: Uc) -> Dict[str, int]:
        regs = {}
        for i, reg_const in enumerate(_XREG_TABLE):
            regs[f"X{i}"] = uc.reg_read(reg_const)
        regs["SP"] = uc.reg_read(UC_ARM64_REG_SP)
        regs["LR"] = uc.reg_read(UC_ARM64_REG_LR)
        regs["PC"] = uc.reg_read(UC_ARM64_REG_PC)
        return regs

    def _dump_memory(self, uc: Uc) -> bytes:
        """Dump 全部映射内存（只读方式）"""
        return uc.mem_read(CODE_BASE, 2 * 1024 * 1024 + 3 * ANCHOR_REGION_SIZE)

    # ── 契约标注 ──

    def _annotate_contract(self, result: TraceResult, loop_info: Optional[dict]):
        """将锚点扫描 + 循环信息写入 result"""
        contract = result.to_contract()

        # 循环信息
        if loop_info:
            contract["loop_info"] = {
                "counter_reg": loop_info["reg"],
                "total_iterations": loop_info["value"],
                "loop_head_rva": "N/A",
            }

        # 锚点定位: 在内存中扫描标准 S-Box 位置
        sbox_offset = self._find_sbox_in_memory(result.memory_dump)
        if sbox_offset is not None:
            contract["anchors"]["sbox"] = {
                "rva": hex(sbox_offset),
                "size": 256,
                "standard": True,
            }
            contract["algorithm"] = "AES-128"
            contract["confidence"] = 0.95

        result.function = contract["function"]
        result.contract = contract  # 附加完整契约到 result

    def _find_sbox_in_memory(self, memory: bytes) -> Optional[int]:
        """在内存中扫描 AES S-Box 起始特征"""
        idx = memory.find(AES_SBOX_HEAD)
        return idx if idx >= 0 else None


# ────────────────────────────────────────────────────────────
# DMP 引擎 (Differential Memory Profiling)
# ────────────────────────────────────────────────────────────

class DMPEngine:
    """
    DMP 双跑降级。

    用法:
        result = DMPEngine.compare(trace_a, trace_b)
    """

    @staticmethod
    def compare(trace_a: TraceResult, trace_b: TraceResult) -> DMPResult:
        """
        对比两次 Unicorn 执行结果。

        PATH_ALIGNED:   两次执行的指令路径完全一致 → 安全 diff
        PATH_DIVERGED:  路径分岔 → 降级标记，返回分岔点
        """
        # 路径一致性校验
        if (trace_a.executed_inst_count != trace_b.executed_inst_count or
                trace_a.path_hash != trace_b.path_hash):
            div_point = DMPEngine._find_divergence(trace_a, trace_b)
            return DMPResult(
                status="PATH_DIVERGED",
                confidence="LOW",
                divergence_point=div_point,
            )

        # 路径一致 → 内存 diff
        const_regions, dyn_regions = DMPEngine._diff_memory(
            trace_a.memory_dump, trace_b.memory_dump
        )
        return DMPResult(
            status="PATH_ALIGNED",
            confidence="HIGH",
            constant_regions=const_regions,
            dynamic_regions=dyn_regions,
        )

    @staticmethod
    def _diff_memory(
        mem_a: bytes, mem_b: bytes
    ) -> Tuple[List[dict], List[dict]]:
        """
        逐字节对比两份内存 dump。

        返回:
            (constant_regions, dynamic_regions)
            每个 region: {"offset": int, "size": int}
        """
        if len(mem_a) != len(mem_b):
            # 不应该发生——路径对齐时内存 layout 相同
            min_len = min(len(mem_a), len(mem_b))
            mem_a = mem_a[:min_len]
            mem_b = mem_b[:min_len]

        constant_regions: List[dict] = []
        dynamic_regions: List[dict] = []

        i = 0
        while i < len(mem_a):
            start = i
            # 收集连续相同/不同 区段
            is_same = (mem_a[i] == mem_b[i])
            while i < len(mem_a) and (mem_a[i] == mem_b[i]) == is_same:
                i += 1
            region = {"offset": start, "size": i - start}
            if is_same:
                constant_regions.append(region)
            else:
                dynamic_regions.append(region)

        return constant_regions, dynamic_regions

    @staticmethod
    def _find_divergence(
        trace_a: TraceResult, trace_b: TraceResult
    ) -> Optional[int]:
        """找到两条路径的第一个不同地址"""
        # 路径哈希不同 → 逐字节对比指令序列（这里仅返回占位）
        # 完整实现需要储存每条指令地址 + 反汇编文本
        return None
