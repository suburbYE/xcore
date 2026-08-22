"""
ir_slicer_psc.py — 伪代码层 IR 切片器 (004 模块)

基于正则 SSA + 控制流亲和度剪枝，将 IDA 伪代码压缩到 100-200 行喂 LLM。

核心函数:
    slice_pseudocode(lines, seed_vars, trace_json) → list[str]
    inject_anchor_header(trace_json)               → str
    infer_seed_vars(raw_pseudocode)                → list[str]

设计决策（对话确认）:
    - 伪代码层切片，不做汇编层
    - 正则 SSA 而非 tree-sitter（IDA 伪代码已是 SSA）
    - 区分变量赋值 (Def) 与解引用内存写入 (*v1 = ... 是 Use 非 Def)
    - 控制流亲和度剪枝 + 括号配对
    - inject_anchor_header 独立导出

作者: xcore
许可: MIT
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set, Tuple

# ────────────────────────────────────────────────────────────
# 正则模式
# ────────────────────────────────────────────────────────────

_RE_VAR_ASSIGN = re.compile(
    r'^\s*([a-zA-Z_]\w*)\s*=\s*(?!\*)',            # v1 = ...   (纯赋值)
)                                                    # *v1 = ...  是内存写入，不匹配
_RE_VAR_USE   = re.compile(r'\b([a-zA-Z_]\w*)\b')

# 控制流关键字
_IF_KEYWORDS   = frozenset({'if', 'else'})
_LOOP_KEYWORDS = frozenset({'for', 'while', 'do'})
_FLOW_KEYWORDS = _IF_KEYWORDS | _LOOP_KEYWORDS

# ────────────────────────────────────────────────────────────
# Def-Use 解析
# ────────────────────────────────────────────────────────────

class LineDefUse:
    """伪代码单行 Def-Use 解析"""

    def __init__(self, line: str):
        self.line     = line
        self.stripped = line.strip()
        self.defs: Set[str]     = set()
        self.uses: Set[str]     = set()
        self._parse()

    def _parse(self):
        # Def: 纯赋值 lhs = rhs（左侧不是解引用 *ptr）
        m = _RE_VAR_ASSIGN.match(self.stripped)
        if m:
            lhs = m.group(1)
            if lhs not in ('if', 'for', 'while', 'do', 'else', 'return'):
                self.defs.add(lhs)

        # Use: 所有变量引用（包括赋值右侧和解引用写入）
        tokens = self.stripped.split()
        # 移除关键字
        kw_removed = [t for t in tokens
                      if t not in ('if', 'else', 'for', 'while', 'do', 'return',
                                   'break', 'continue', 'case', 'switch', 'goto')]
        for tok in kw_removed:
            # 清理操作符
            tok = re.sub(r'[^a-zA-Z0-9_]', '', tok)
            if tok and tok[0].isalpha():
                self.uses.add(tok)


# ────────────────────────────────────────────────────────────
# 控制流亲和度剪枝
# ────────────────────────────────────────────────────────────

def prune_and_reconstruct_flow(
    lines: List[str],
    kept_indices: Set[int],
) -> List[str]:
    """
    保留切片命中行 + 其必要性控制流结构行。

    规则:
    1. 向上找最近的 if/for/while 头
    2. 保留对应的成对 { }
    3. 保留 else 分支
    """
    if not kept_indices:
        return [""]

    min_idx = min(kept_indices)
    max_idx = max(kept_indices)

    # 向上扩展: 包含使 kept_indices 可达的控制流
    flow_indices: Set[int] = set()
    for idx in sorted(kept_indices):
        parent = _find_flow_parent(lines, idx)
        if parent is not None:
            flow_indices.add(parent)
            # 向上继续找到最外层
            while True:
                grandparent = _find_flow_parent(lines, parent)
                if grandparent is None:
                    break
                parent = grandparent
                flow_indices.add(parent)

    # 合并
    all_indices = kept_indices | flow_indices

    # 括号配对: 保留被选行的成对 {}
    brace_indices: Set[int] = set()
    brace_stack: List[int] = []
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped == '{':
            brace_stack.append(i)
        elif stripped == '}':
            if brace_stack:
                open_idx = brace_stack.pop()
                # 如果闭合范围与选中行有交集
                if _range_overlaps(open_idx, i, all_indices):
                    brace_indices.add(open_idx)
                    brace_indices.add(i)

    all_indices |= brace_indices

    # 重建
    result: List[str] = []
    for i in sorted(all_indices):
        if i < len(lines):
            result.append(lines[i])
    return result


def _find_flow_parent(lines: List[str], idx: int) -> Optional[int]:
    """向上找最近的 if/for/while 头（在 idx 之前且未被其他 } 闭合）"""
    depth = 0
    for i in range(idx - 1, -1, -1):
        stripped = lines[i].strip()
        if stripped == '}':
            depth += 1
        elif stripped == '{':
            depth -= 1
            if depth < 0:
                depth = 0
        elif depth == 0:
            first_word = stripped.split()[0] if stripped.split() else ""
            if first_word in _FLOW_KEYWORDS:
                return i
            if first_word == 'else':
                return i
    return None


def _range_overlaps(start: int, end: int, indices: Set[int]) -> bool:
    """判断 [start, end] 是否与 indices 有交集"""
    return bool(set(range(start, end + 1)) & indices)


# ────────────────────────────────────────────────────────────
# 变量亲和度传播 (Difference Update)
# ────────────────────────────────────────────────────────────

def propagate_seed_vars(
    lines: List[str],
    seed_vars: List[str],
) -> Set[int]:
    """
    从 seed_vars 出发，传播变量依赖，返回所有应保留的行号。

    规则:
    - 纯赋值 (非解引用赋值) 执行 difference_update
    - 解引用写入 (*v = ...) 视为 Use 非 Def
    - 传播方向: 向前 (t+1, t+2, ...) 且跳过无关行
    """
    var_versions: Dict[str, Set[int]] = {}
    for seed in seed_vars:
        var_versions.setdefault(seed, set()).add(-1)   # -1 表示外部定义

    parsed: List[LineDefUse] = [LineDefUse(l) for l in lines]
    result: Set[int] = set()

    for idx, p in enumerate(parsed):
        # 检查当前行的 uses 是否命中活跃变量
        hit = False
        for use_var in p.uses:
            if use_var in var_versions and var_versions[use_var]:
                hit = True
                break

        # For-loop 变量 (i, j, k...) 无条件保留
        if not hit and p.stripped.startswith('for '):
            hit = True

        if not hit:
            continue

        result.add(idx)

        # Def 传播: 纯赋值行更新差集
        for def_var in p.defs:
            if def_var not in var_versions:
                var_versions[def_var] = set()
            # 新版本替换旧版本 (SSA 语义简化)
            var_versions[def_var] = {idx}

    return result


# ────────────────────────────────────────────────────────────
# Anchor Header 注入
# ────────────────────────────────────────────────────────────

def inject_anchor_header(trace_json: dict) -> str:
    """
    生成 Anchor Header（C 注释块），嵌入 001 微执行产出的契约信息。

    输出示例:
        /*
         * @xcore-pipeline v0.2
         * @algorithm AES-128
         * @confidence HIGH
         * @dmp_path_aligned true
         * @loop W8=10 (密码学主循环)
         * @sbox_rva 0x402000
         */
    """
    lines = [
        "/*",
        " * @xcore-pipeline v0.2",
    ]

    algo = trace_json.get("algorithm", "Unknown")
    lines.append(f" * @algorithm {algo}")

    conf = trace_json.get("confidence", "LOW")
    lines.append(f" * @confidence {conf}")

    dmp = trace_json.get("dmp_status", "UNKNOWN")
    lines.append(f" * @dmp_status {dmp}")

    path_hash = trace_json.get("path_hash", "")
    if path_hash:
        lines.append(f" * @path_hash {path_hash}")

    inst_count = trace_json.get("executed_inst_count", 0)
    lines.append(f" * @executed_insts {inst_count}")

    loop = trace_json.get("loop_info", {})
    if loop:
        reg  = loop.get("counter_reg", "?")
        val  = loop.get("total_iterations", "?")
        lines.append(f" * @loop {reg}={val} (密码学主循环)")

    anchors = trace_json.get("anchors", {})
    for name, info in anchors.items():
        rva = info.get("rva", "N/A") if isinstance(info, dict) else info
        lines.append(f" * @anchor_{name}_rva {rva}")

    lines.append(" */")
    lines.append("")
    return "\n".join(lines)


# ────────────────────────────────────────────────────────────
# 主切片函数
# ────────────────────────────────────────────────────────────

def slice_pseudocode(
    lines: List[str],
    seed_vars: List[str],
    trace_json: Optional[dict] = None,
) -> List[str]:
    """
    伪代码切片主函数。

    参数:
        lines:      伪代码文本，按行分割
        seed_vars:  种子变量列表，如 ['a1', 'a2', 'v5']
        trace_json: 001 微执行契约 (可选)

    返回:
        切片后的伪代码行，已做控制流重建
    """
    if not lines or not seed_vars:
        return lines

    # 1. 变量亲和度传播
    hit_indices = propagate_seed_vars(lines, seed_vars)

    # 2. 控制流重建
    sliced = prune_and_reconstruct_flow(lines, hit_indices)

    return sliced


# ────────────────────────────────────────────────────────────
# 种子变量自动推断
# ────────────────────────────────────────────────────────────

def infer_seed_vars(raw_pseudocode: str) -> List[str]:
    """
    从伪代码文本中自动推断初始种子变量。

    规则:
    1. 函数入参: a1, a2, a3... (IDA 默认命名)
    2. return 语句中出现的变量
    3. *a1 = ... 模式中的基址指针 (输出 buffer)

    参数:
        raw_pseudocode: 完整伪代码字符串

    返回:
        种子变量列表 (去重)
    """
    seeds: Set[str] = set()
    lines = raw_pseudocode.split("\n")

    # 函数签名中的入参
    for line in lines[:15]:
        found = re.findall(r'\b(a\d+)\b', line)
        seeds.update(found)

    # return 变量
    for line in reversed(lines):
        stripped = line.strip()
        if stripped.startswith("return "):
            seeds.update(re.findall(r'\b([va]\d+)\b', stripped))
            break

    # 输出 buffer 写入
    for line in lines:
        # *a1 = ... / *(a1 + ...) = ...
        if re.match(r'^\s*\*\s*([a-zA-Z]\w*)', line):
            m = re.match(r'^\s*\*\s*([a-zA-Z]\w*)\b', line)
            if m:
                seeds.add(m.group(1))

    # 确保入参始终在
    if not seeds:
        seeds = {'a1', 'a2'}

    return sorted(seeds)
