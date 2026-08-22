"""
bb_extractor.py — 基本块识别 + 出口判断 + 汇编惯用语匹配

依赖: capstone, register_view

作者: xcore
许可: MIT
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from capstone import CsInsn, CS_ARCH_ARM64, CS_MODE_ARM

from modules.native.register_view import RegisterView

# ────────────────────────────────────────────────────────────
# 出口指令分类
# ────────────────────────────────────────────────────────────

EXIT_INSTRUCTIONS = frozenset({"bl", "blr", "br", "ret"})

INTER_BLOCK = frozenset({
    "b", "b.eq", "b.ne", "b.lt", "b.gt", "b.le", "b.ge",
    "b.cs", "b.cc", "b.mi", "b.pl", "b.vs", "b.vc",
    "b.hi", "b.ls", "cbz", "cbnz", "tbz", "tbnz",
})


@dataclass
class BasicBlock:
    """基本块"""
    start_rva: int                                   # 起始 RVA
    end_rva: int                                     # 最后一条指令的 RVA（含）
    size: int                                        # 字节长度
    insns: list[CsInsn]                              # Capstone 指令列表
    is_terminal: bool = False                        # 是否以绝对 Exit 结尾


# ────────────────────────────────────────────────────────────
# 出口判断 (策略 A/B 混合)
# ────────────────────────────────────────────────────────────

def is_block_end(
    insn: CsInsn,
    target_rva: int | None = None,
    slice_range: tuple[int, int] | None = None,
) -> bool:
    """
    判断当前指令是否为 BB 终点。

    参数:
        insn:         Capstone 指令对象
        target_rva:   跳转目标地址（b/b.cond/cbz 等），非跳转指令传 None
        slice_range:  当前切片范围 (start_rva, end_rva)，仅用于 INTER_BLOCK 判断

    返回:
        True  = 截断，BB 终止
        False = 允许继续
    """
    mnemonic = insn.mnemonic.lower()

    if mnemonic in EXIT_INSTRUCTIONS:
        return True

    if mnemonic in INTER_BLOCK:
        if target_rva is None or slice_range is None:
            return True                       # 无法判目标 → 保守截断
        start, end = slice_range
        if start <= target_rva <= end:
            return False                      # 闭环，允许回跳
        return True                           # 逃逸，截断

    return False


# ────────────────────────────────────────────────────────────
# BB 提取
# ────────────────────────────────────────────────────────────

def extract_core_bb(
    code: bytes,
    base_rva: int,
    md,
) -> list[BasicBlock]:
    """
    从 ARM64 字节码提取不含 BL/BLR 的核心 BB 列表。

    参数:
        code:     目标函数字节码
        base_rva: 基址 RVA (0-based)
        md:       capstone.Cs 实例，已初始化 CS_ARCH_ARM64 + CS_MODE_ARM

    返回:
        切分后的 BasicBlock 列表，按 start_rva 升序
    """
    blocks: list[BasicBlock] = []
    insns: list[CsInsn] = list(md.disasm(code, base_rva))

    if not insns:
        return blocks

    bb_start_idx = 0
    bb_start_rva = insns[0].address

    for i, insn in enumerate(insns):
        mnemonic = insn.mnemonic.lower()
        target_rva = _extract_branch_target(insn)

        # 遇到 BL/BLR → 在此截断，它们不应出现在核心 BB 切片内
        is_exit = (mnemonic in EXIT_INSTRUCTIONS or
                   _is_call_like(mnemonic))

        if is_exit and i > bb_start_idx:
            # 截断当前 BB（不含当前 call 指令）
            bb_insns = insns[bb_start_idx:i]
            bb_rva = bb_insns[0].address
            bb_end_rva = bb_insns[-1].address
            bb_size = bb_end_rva - bb_rva + bb_insns[-1].size
            blocks.append(BasicBlock(
                start_rva=bb_rva,
                end_rva=bb_end_rva,
                size=bb_size,
                insns=bb_insns,
                is_terminal=True,
            ))
            bb_start_idx = i + 1                    # 从 call 下一条重新开始

        elif is_exit and i == bb_start_idx:
            # 独立的一条 call，跳过
            bb_start_idx = i + 1

    # 尾部残余
    if bb_start_idx < len(insns):
        bb_insns = insns[bb_start_idx:]
        bb_rva = bb_insns[0].address
        bb_end_rva = bb_insns[-1].address
        bb_size = bb_end_rva - bb_rva + bb_insns[-1].size
        blocks.append(BasicBlock(
            start_rva=bb_rva,
            end_rva=bb_end_rva,
            size=bb_size,
            insns=bb_insns,
            is_terminal=False,
        ))

    return blocks


def _extract_branch_target(insn: CsInsn) -> int | None:
    """从 Capstone 指令提取跳转目标 RVA。"""
    mnemonic = insn.mnemonic.lower()
    if mnemonic in INTER_BLOCK or mnemonic in {"b", "bl"}:
        if insn.operands:
            op = insn.operands[0]
            if op.type == 1:                       # IMM (imm)
                return op.imm
    return None


def _is_call_like(mnemonic: str) -> bool:
    """BL/BLR 或其它调用类指令。"""
    return mnemonic in ("bl", "blr")


# ────────────────────────────────────────────────────────────
# 汇编惯用语匹配 (Idiom Matching)
# ────────────────────────────────────────────────────────────

# 密码学敏感轮数常量
CRYPTO_ROUND_IMM = frozenset({10, 12, 14, 16, 32, 64, 80})

# MOV 指令 Capstone ID（ARM64 下有多种变体）
_MOV_MNEMONICS = frozenset({"mov", "movz"})


# ── 标志位设置 & 条件跳转扩展常量 ──
_FLAG_SET_MNEMONICS = frozenset({"subs", "adds", "ands", "cmp", "cmn", "tst"})
_COND_BRANCH_MNEMONICS = frozenset({
    "b.ne", "b.eq", "b.lt", "b.gt", "b.le", "b.ge",
    "b.lo", "b.hi",
})


def match_loop_counter(insns: list[CsInsn]) -> dict | None:
    """
    匹配密码学循环计数模式（扩展版，三类通用模式）。

    模式 A（倒计数）: MOV Wn, #IMM (IMM ∈ CRYPTO_ROUND_IMM)
                     + SUBS/ADDS/ANDS Wn, Wn, #step
                     + B.cond / CBZ / CBNZ
    模式 B（正计数）: CMP Wn, #bound (bound 即轮数)
                     + ADD Wn, Wn, #step（增量证据）
                     + B.cond
    模式 C（直接测试）: CBZ/CBNZ/TBZ/TBNZ Wn, target
                        (Wn 由 MOV #IMM 初始化)

    参数:
        insns: Capstone 指令列表（至少 3 条）

    返回:
        {'reg': 'W8', 'value': 10, 'insn_index': N} 或 None
    """
    if len(insns) < 3:
        return None

    scan_window = min(len(insns), 256)

    # ═══════════════════════════════════════════════════════
    # 阶段 1: MOV #imm 候选（倒计数初始值）
    # ═══════════════════════════════════════════════════════
    mov_candidates: dict[int, tuple[int, int]] = {}
    for i in range(scan_window):
        insn = insns[i]
        if insn.mnemonic.lower() not in _MOV_MNEMONICS:
            continue
        imm = _extract_imm(insn)
        if imm is None or imm not in CRYPTO_ROUND_IMM:
            continue
        target_reg = _extract_reg_num(insn, is_dst=True)
        if target_reg is not None:
            mov_candidates[target_reg] = (imm, i)

    # ═══════════════════════════════════════════════════════
    # 阶段 2: 扫描标志位设置指令 & 条件/直接跳转
    # ═══════════════════════════════════════════════════════
    for i in range(scan_window):
        insn = insns[i]
        mnemonic = insn.mnemonic.lower()

        # ── 2a: 标志位设置指令（SUBS/ADDS/ANDS/CMP/CMN/TST）──
        if mnemonic in _FLAG_SET_MNEMONICS:
            test_reg = _get_test_reg(insn)
            if test_reg is None:
                continue

            # 确定轮数值与锚点索引
            if test_reg in mov_candidates:
                # 模式 A: 倒计数，轮数来自 MOV
                bound, anchor_idx = mov_candidates[test_reg]
            elif mnemonic == "cmp":
                # 模式 B: 正计数，轮数来自 CMP 立即数 + 需增量证据
                bound = _extract_imm(insn)
                if bound is None or not _has_increment(insns, test_reg, scan_window):
                    continue
                anchor_idx = i
            else:
                continue

            # 搜索条件分支（含 B.cond 和 CBZ/CBNZ）
            for j in range(i + 1, min(scan_window, i + 8)):
                branch = insns[j]
                bm = branch.mnemonic.lower()

                if bm in _COND_BRANCH_MNEMONICS:
                    return _build_counter_result(test_reg, bound, anchor_idx)

                if test_reg in mov_candidates and bm in ("cbz", "cbnz"):
                    if _extract_reg_num(branch, is_dst=True) == test_reg:
                        return _build_counter_result(test_reg, bound, anchor_idx)

        # ── 2b: 直接寄存器测试分支（CBZ/CBNZ）──
        elif mnemonic in ("cbz", "cbnz"):
            test_reg = _extract_reg_num(insn, is_dst=True)
            if test_reg is not None and test_reg in mov_candidates:
                bound, idx = mov_candidates[test_reg]
                return _build_counter_result(test_reg, bound, idx)

        # ── 2c: 位测试分支（TBZ/TBNZ）──
        elif mnemonic in ("tbz", "tbnz"):
            test_reg = _extract_reg_num(insn, is_dst=True)
            if test_reg is not None and test_reg in mov_candidates:
                bound, idx = mov_candidates[test_reg]
                return _build_counter_result(test_reg, bound, idx)

    return None


# ═══════════════════════════════════════════════════════
# 辅助函数
# ═══════════════════════════════════════════════════════

def _build_counter_result(arch_reg: int, value: int, insn_index: int) -> dict:
    """构造统一的循环计数匹配结果。"""
    _, bit_width = RegisterView.resolve_alias(f"W{arch_reg}")
    return {
        "reg": f"W{arch_reg}" if bit_width == 32 else f"X{arch_reg}",
        "value": value,
        "insn_index": insn_index,
    }


def _get_test_reg(insn: CsInsn) -> int | None:
    """
    从标志位设置指令中提取"被测试的寄存器"。

    Capstone 对 CMP/CMN/TST 的表示不一致：
      - 仅 2 操作数：[Rn, #imm]            → operands[0] 即 Rn
      - 带隐式 WZR：[WZR, Rn, #imm]        → operands[0]=WZR, operands[1]=Rn
    统一策略：先取 operands[0]，若为 WZR/XZR(31) 则回退到 operands[1]。
    """
    mnemonic = insn.mnemonic.lower()
    if mnemonic in ("cmp", "cmn", "tst"):
        reg0 = _extract_reg_num(insn, is_dst=True)
        if reg0 == 31:
            return _extract_reg_num(insn, is_dst=False)
        return reg0
    return _extract_reg_num(insn, is_dst=True)


def _has_increment(insns: list[CsInsn], reg: int, max_idx: int) -> bool:
    """
    检查 BB 内是否存在 ADD Rn, Rn, #step 模式（正计数证据）。

    用于模式 B：确认 CMP 比较的寄存器确实是循环计数器。
    """
    if reg == 31:
        return False                            # WZR/XZR/SP 不可能是循环计数器
    for i in range(max_idx):
        insn = insns[i]
        if insn.mnemonic.lower() != "add":
            continue
        dst = _extract_reg_num(insn, is_dst=True)
        if dst != reg:
            continue
        src = _extract_reg_num(insn, is_dst=False)
        if src == reg:
            return True
    return False


def _extract_imm(insn: CsInsn) -> int | None:
    """提取指令中第一个立即数操作数（MOV/CMP 通用）。"""
    for op in insn.operands:
        if op.type == 2:                           # IMM type in Capstone
            return op.imm
    return None


def _extract_reg_num(insn: CsInsn, is_dst: bool = True) -> int | None:
    """
    从 Capstone 指令提取架构寄存器编号 (0-31)。

    Capstone 内部使用自己的枚举值（如 ARM64_REG_W8 = 195），
    我们需要映射回架构编号 0-31。

    is_dst=True: 取第一个操作数（目标寄存器）
    is_dst=False: 取后续操作数中的寄存器
    """
    # Capstone v5 ARM64 寄存器枚举基址 (实测值)
    # ARM64_REG_W0 = 187, ARM64_REG_X0 = 218
    _CAPSTONE_W0 = 187
    _CAPSTONE_X0 = 218
    _CAPSTONE_SP = 5

    op_idx = 0 if is_dst else 1
    if op_idx >= len(insn.operands):
        return None
    op = insn.operands[op_idx]
    if op.reg == 0:                                # op.type != REG
        return None

    cs_reg = op.reg

    # 映射 Capstone 枚举 → 架构编号
    if _CAPSTONE_W0 <= cs_reg <= _CAPSTONE_W0 + 31:
        return cs_reg - _CAPSTONE_W0
    if _CAPSTONE_X0 <= cs_reg <= _CAPSTONE_X0 + 31:
        return cs_reg - _CAPSTONE_X0

    # SP
    if cs_reg == _CAPSTONE_SP:
        return 31

    return None


# ═══════════════════════════════════════════════════════
# CFG 构建
# ═══════════════════════════════════════════════════════

def build_cfg(blocks: list[BasicBlock]) -> dict[int, list[int]]:
    """
    根据 BB 列表构建控制流图（邻接表）。

    策略：
      - 遍历每个 BB 的最后一条（对条件分支还要看倒数第二条）
      - 无条件跳转 (b)：target 单后继
      - 条件跳转 (b.cond/cbz/cbnz/tbz/tbnz)：target + fall-through 双后继
      - 终端 (ret/br/blr)：无后继

    参数:
        blocks: 按 start_rva 升序排列的 BasicBlock 列表

    返回:
        {bb_index: [succ_index, ...]}
    """
    cfg: dict[int, list[int]] = {}

    # 建立 RVA → bb_index 快速索引
    rva_to_idx: dict[int, int] = {}
    for idx, bb in enumerate(blocks):
        rva_to_idx[bb.start_rva] = idx

    # 找目标 BB：RVA 匹配 start_rva 或落入某个 BB 范围
    def _find_bb(target_rva: int) -> int | None:
        if target_rva in rva_to_idx:
            return rva_to_idx[target_rva]
        # 退化：落入某个 BB 内部（少见但防御）
        for idx, bb in enumerate(blocks):
            if bb.start_rva <= target_rva <= bb.end_rva:
                return idx
        return None

    for i, bb in enumerate(blocks):
        cfg[i] = []
        if not bb.insns:
            continue

        last = bb.insns[-1]
        last_mnem = last.mnemonic.lower()

        # 终端指令 → 无后继
        if last_mnem in EXIT_INSTRUCTIONS:
            continue

        # 无条件跳转
        if last_mnem == "b":
            target = _extract_branch_target(last)
            if target is not None:
                succ = _find_bb(target)
                if succ is not None:
                    cfg[i].append(succ)
            continue

        # 条件跳转 + 可能 fall-through
        if last_mnem in ("cbz", "cbnz", "tbz", "tbnz") or last_mnem.startswith("b."):
            target = _extract_branch_target(last)
            if target is not None:
                succ = _find_bb(target)
                if succ is not None and succ not in cfg[i]:
                    cfg[i].append(succ)

            # fall-through: 下一个 BB（按 RVA 顺序）
            if i + 1 < len(blocks):
                fall_through = i + 1
                if fall_through not in cfg[i]:
                    cfg[i].append(fall_through)
            continue

        # 非分支结尾 → 顺序 fall-through
        if i + 1 < len(blocks):
            cfg[i].append(i + 1)

    return cfg


# ═══════════════════════════════════════════════════════
# 跨 BB 循环计数匹配
# ═══════════════════════════════════════════════════════

def match_loop_counter_cross_bb(
    all_blocks: list[BasicBlock],
    cfg: dict[int, list[int]],
) -> dict | None:
    """
    跨 BB 匹配密码学循环计数模式（CFG 平坦化兼容）。

    阶段 1：遍历所有 BB，收集循环计数器种子——MOV/MOVZ Wn/Xn, #IMM
            其中 IMM ∈ CRYPTO_ROUND_IMM。
    阶段 2：沿 CFG 前向追踪每个种子的寄存器使用链，
            跨 BB 寻找对该寄存器的测试指令（SUBS/CMP/CBZ/CBNZ/TBZ/TBNZ），
            提取 bound 值。

    追踪规则：
      - 从种子 BB 出发，沿 CFG 后继 BFS 遍历
      - 进入 BB 后扫描指令：若遇测试模式匹配 → 返回结果
      - 若遇寄存器被覆写 → 该路径终止
      - 否则继续到后继 BB
      - visited set 防止循环追踪

    参数:
        all_blocks: 全部 BasicBlock 列表
        cfg:        build_cfg 输出的邻接表

    返回:
        {'reg': 'W8', 'value': 10, 'insn_index': N, 'bb_index': I} 或 None
    """
    from collections import deque

    # ═══════════════════════════════════════════════════
    # 阶段 1: 收集种子
    # ═══════════════════════════════════════════════════
    seeds: list[tuple[int, int, int, int]] = []  # (bb_idx, reg, imm, insn_idx)

    for bi, bb in enumerate(all_blocks):
        for ii, insn in enumerate(bb.insns):
            if insn.mnemonic.lower() not in _MOV_MNEMONICS:
                continue
            imm = _extract_imm(insn)
            if imm is None or imm not in CRYPTO_ROUND_IMM:
                continue
            reg = _extract_reg_num(insn, is_dst=True)
            if reg is not None:
                seeds.append((bi, reg, imm, ii))

    if not seeds:
        return None

    # ═══════════════════════════════════════════════════
    # 阶段 2: 沿 CFG 前向追踪
    # ═══════════════════════════════════════════════════

    for seed_bb_idx, seed_reg, seed_imm, seed_insn_idx in seeds:
        visited: set[int] = set()
        queue: deque[int] = deque([seed_bb_idx])

        while queue:
            cur_idx = queue.popleft()
            if cur_idx in visited:
                continue
            visited.add(cur_idx)

            bb = all_blocks[cur_idx]
            start_insn_idx = seed_insn_idx if cur_idx == seed_bb_idx else 0

            for ii in range(start_insn_idx, len(bb.insns)):
                insn = bb.insns[ii]
                mnemonic = insn.mnemonic.lower()

                # ── 检查寄存器覆写（在当前 BB 内，从种子之后）──
                if ii > start_insn_idx or cur_idx != seed_bb_idx:
                    if _is_reg_overwrite(insn, seed_reg):
                        # 标记覆写，跳出当前 BB 扫描
                        break

                # ── 测试模式 A: 标志位设置（SUBS/ADDS/ANDS/CMP/CMN/TST）──
                if mnemonic in _FLAG_SET_MNEMONICS:
                    test_reg = _get_test_reg(insn)
                    if test_reg == seed_reg:
                        # 确定 bound 值
                        if mnemonic == "cmp":
                            bound = _extract_imm(insn)
                            if bound is None:
                                bound = seed_imm
                        else:
                            bound = seed_imm
                        return {
                            "reg": f"W{seed_reg}" if seed_reg < 32 else f"X{seed_reg}",
                            "value": bound,
                            "insn_index": seed_insn_idx,
                            "bb_index": seed_bb_idx,
                        }

                # ── 测试模式 B: 直接寄存器测试（CBZ/CBNZ）──
                elif mnemonic in ("cbz", "cbnz"):
                    test_reg = _extract_reg_num(insn, is_dst=True)
                    if test_reg == seed_reg:
                        return {
                            "reg": f"W{seed_reg}" if seed_reg < 32 else f"X{seed_reg}",
                            "value": seed_imm,
                            "insn_index": seed_insn_idx,
                            "bb_index": seed_bb_idx,
                        }

                # ── 测试模式 C: 位测试（TBZ/TBNZ）──
                elif mnemonic in ("tbz", "tbnz"):
                    test_reg = _extract_reg_num(insn, is_dst=True)
                    if test_reg == seed_reg:
                        return {
                            "reg": f"W{seed_reg}" if seed_reg < 32 else f"X{seed_reg}",
                            "value": seed_imm,
                            "insn_index": seed_insn_idx,
                            "bb_index": seed_bb_idx,
                        }

            # 末条触发了 break（覆写）→ 不继续后继
            else:
                # 未在当前 BB 命中 → 继续到后继
                for succ in cfg.get(cur_idx, []):
                    if succ not in visited:
                        queue.append(succ)

    return None


def _is_reg_overwrite(insn: CsInsn, tracked_reg: int) -> bool:
    """
    判断指令是否覆写了给定寄存器（使其作为计数器失效）。

    覆写条件：
      - 指令写出目标寄存器 == tracked_reg
      - 且不是对被追踪寄存器的读-改-写（SUBS Wn, Wn, #1 仍算覆写，但 SUBS 本身
        在 _FLAG_SET_MNEMONICS 中已于调用方提前短路，此处不再重复判断）
    """
    mnemonic = insn.mnemonic.lower()

    # 标志位设置指令不会覆写寄存器（CMP/CMN/TST 不修改操作数寄存器）
    if mnemonic in _FLAG_SET_MNEMONICS:
        return False

    # CBZ/CBNZ/TBZ/TBNZ 不修改寄存器
    if mnemonic in ("cbz", "cbnz", "tbz", "tbnz"):
        return False

    # 条件/无条件跳转不修改寄存器
    if mnemonic.startswith("b.") or mnemonic in ("b", "br", "ret", "bl", "blr"):
        return False

    dst = _extract_reg_num(insn, is_dst=True)
    if dst is not None and dst == tracked_reg:
        return True

    return False
