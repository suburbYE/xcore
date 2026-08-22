"""
ir_slicer_psc.py — IDA/Ghidra 伪代码 IR 切片器

基于行级 SSA (正则 Def-Use) 的反向数据流切片。
配合 001 Micro Executor 的 JSON 契约，在 LLM 输入添加预标注注释头部。

不依赖 tree-sitter。不解析汇编层。

作者: xcore
许可: MIT
"""

from __future__ import annotations

import re
import json
from typing import Dict, List, Set, Optional

# ────────────────────────────────────────────────────────────
# 正则
# ────────────────────────────────────────────────────────────

VAR_PATTERN = re.compile(r'\b([va]\d+)\b')

# 匹配形如 v5 = ...; 或 (类型)v5 = ...; 的赋值
ASSIGN_PATTERN = re.compile(
    r'^\s*(?:\*|\([^)]+\)\s*)?([va]\d+)(?:\[[^\]]+\])?\s*=\s*(.+);'
)

# ────────────────────────────────────────────────────────────
# 行级 Def-Use 结构
# ────────────────────────────────────────────────────────────

class LineDefUse:
    """伪代码中一行的 def/use 信息"""

    __slots__ = (
        "line_idx", "raw_code", "defs", "uses",
        "is_mem_write", "mem_base",
    )

    def __init__(self, line_idx: int, raw_code: str):
        self.line_idx = line_idx
        self.raw_code = raw_code.strip()
        self.defs: Set[str] = set()
        self.uses: Set[str] = set()
        self.is_mem_write: bool = False
        self.mem_base: Optional[str] = None

    def parse(self):
        """提取本行的 def / use / 内存写入信息"""
        assign_match = ASSIGN_PATTERN.match(self.raw_code)
        lhs = self.raw_code.split("=")[0] if "=" in self.raw_code else ""

        # 判断左侧是否为指针解引用 (如 *v1 = ..., *(a1+4) = ...)
        is_deref_write = (
            lhs.lstrip().startswith("*") or "->" in lhs
        ) if lhs else False

        if assign_match and not is_deref_write:
            # 纯变量赋值: v5 = expr
            self.defs.add(assign_match.group(1))
            self.uses.update(VAR_PATTERN.findall(assign_match.group(2)))
        else:
            # 内存写入 / if 条件 / 函数调用 → 全部视为 Use
            self.uses.update(VAR_PATTERN.findall(self.raw_code))
            if is_deref_write or ("*" in self.raw_code and "=" in self.raw_code):
                self.is_mem_write = True
                bases = VAR_PATTERN.findall(lhs)
                if bases:
                    self.mem_base = bases[0]

# ────────────────────────────────────────────────────────────
# 反向切片 + 控制流剪枝
# ────────────────────────────────────────────────────────────

def slice_pseudocode(
    lines: List[str],
    seed_vars: Set[str],
    trace_json: Optional[dict] = None,
) -> str:
    """
    反向数据流切片主入口。

    参数:
        lines:      伪代码行列表（每行一条）
        seed_vars:  关注变量集合，如 {"v1", "a1"}（通常 = 返回变量 + 输出 buffer 基址）
        trace_json: 001 Micro Executor 产出的 JSON 契约（可选）

    返回:
        切片后 + 预标注注释的伪代码字符串
    """
    parsed = [LineDefUse(i, line) for i, line in enumerate(lines)]
    for pl in parsed:
        pl.parse()

    target_vars = set(seed_vars)
    active_indices: Set[int] = set()

    # 反向追踪 def-use 链
    for pl in reversed(parsed):
        # 规则 1: 精确变量 def 命中
        if pl.defs & target_vars:
            active_indices.add(pl.line_idx)
            target_vars.update(pl.uses)
            target_vars.difference_update(pl.defs)

        # 规则 2: 保守内存基址写入 — 强行保留，追所有变量
        elif pl.is_mem_write and pl.mem_base and pl.mem_base in target_vars:
            active_indices.add(pl.line_idx)
            target_vars.update(pl.uses)

    # 精细化控制流剪枝 + 括号配对
    sliced = _prune_and_reconstruct_flow(lines, active_indices)

    # 注入 001 Anchor 头部
    header = inject_anchor_header(trace_json) if trace_json else ""

    return header + "\n".join(sliced)


def _prune_and_reconstruct_flow(
    lines: List[str],
    active_indices: Set[int],
) -> List[str]:
    """
    保留 active 行 + 最近的 if/for/while 头 + 成对 { }。
    不保留孤立的 return / else / 无关控制流。
    """
    final = set(active_indices)

    # Step 1: 每个 active 行向上找最近控制流头
    for idx in sorted(active_indices):
        for j in range(idx - 1, -1, -1):
            stripped = lines[j].strip()
            if stripped.startswith(
                ("if", "for", "while", "else if", "switch")
            ):
                final.add(j)
                break
            # 遇到闭合边界，停止向上蔓延
            if stripped.startswith(("}", "return")) or stripped == "else":
                break

    # Step 2: 括号配对 — active 行所在块保留成对 { }
    bracket_stack: List[int] = []
    close_needed: Set[int] = set()
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped == "{":
            bracket_stack.append(i)
        elif stripped == "}":
            if bracket_stack:
                open_idx = bracket_stack.pop()
                if any(open_idx < act < i for act in active_indices):
                    close_needed.add(i)
                    final.add(open_idx)

    # Step 3: 拼接
    result: List[str] = []
    for i, line in enumerate(lines):
        if i in final or i in close_needed:
            result.append(line)

    return result


# ────────────────────────────────────────────────────────────
# Anchor 注释注入 (001 契约 → 004 头部)
# ────────────────────────────────────────────────────────────

def inject_anchor_header(trace_json: dict) -> str:
    """
    将 001 Micro Executor 的 JSON 契约转为 C 风格注释块。

    可独立调用，方便单元测试。
    """
    fn = trace_json.get("function", "Unknown")
    algo = trace_json.get("algorithm", "Unknown")
    conf = trace_json.get("confidence", 0)
    dmp = trace_json.get("dmp_status", "N/A")
    inst = trace_json.get("executed_inst_count", 0)

    anchors = trace_json.get("anchors", {})
    sbox = anchors.get("sbox", {})
    rk = anchors.get("round_keys", {})
    st = anchors.get("state_buffer", {})

    loop = trace_json.get("loop_info", {})

    lines = [
        "/*",
        " * ====================================================================",
        " * [DMP ANCHOR CONTEXT] - Auto-generated by 001 Micro Executor",
        f" * Function   : {fn}",
        f" * Algorithm  : {algo} (Confidence: {conf * 100:.0f}%)",
        f" * DMP Status : {dmp} (Exec Instructions: {inst})",
    ]

    sbox_rva = sbox.get("rva", "N/A")
    sbox_std = sbox.get("standard", False)
    lines.append(
        f" * Anchors    : S-Box @ RVA {sbox_rva} "
        f"(Standard: {sbox_std})"
    )

    rk_rva = rk.get("rva", "N/A")
    rk_size = rk.get("size", 0)
    rk_rounds = rk.get("rounds", 0)
    lines.append(
        f" *              RoundKeys @ RVA {rk_rva} "
        f"(Size: {rk_size}, Rounds: {rk_rounds})"
    )

    st_reg = st.get("register", "N/A")
    st_off = st.get("offset", 0)
    st_size = st.get("size", 0)
    lines.append(
        f" *              State Buffer @ Reg {st_reg}"
        f"+{st_off} (Size: {st_size} bytes)"
    )

    cnt_reg = loop.get("counter_reg", "N/A")
    cnt_iter = loop.get("total_iterations", 0)
    loop_rva = loop.get("loop_head_rva", "N/A")
    if cnt_reg != "N/A":
        lines.append(
            f" * Loop Info  : Head RVA {loop_rva}, "
            f"Counter {cnt_reg} ({cnt_iter} iterations)"
        )

    lines.append(" * ====================================================================")
    lines.append(" */")
    lines.append("")

    return "\n".join(lines)


# ────────────────────────────────────────────────────────────
# 便利: 从种子变量推断
# ────────────────────────────────────────────────────────────

def infer_seed_vars(lines: List[str]) -> Set[str]:
    """
    自动推断切片种子变量。

    规则:
    - 最后一条 return 语句的变量
    - 形如 *(a1 + ...) = ... 的输出 buffer 基址指针
    """
    seeds: Set[str] = set()

    # 倒查 return
    for line in reversed(lines):
        stripped = line.strip()
        if stripped.startswith("return "):
            seeds.update(VAR_PATTERN.findall(stripped))
            break

    # 内存写入的基址指针（疑似输出 buffer）
    for line in lines:
        stripped = line.strip()
        if "*" in stripped and "=" in stripped:
            lhs = stripped.split("=")[0]
            if lhs.lstrip().startswith("*"):
                bases = VAR_PATTERN.findall(lhs)
                seeds.update(bases)

    return seeds
