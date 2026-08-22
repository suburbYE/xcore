"""
register_view.py — ARM64 寄存器归一化层

Wn/Xn 别名解析 + NEON 向量寄存器 16-Lane Bitmask 追踪 + Shuffle Map。

作者: xcore
许可: MIT
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# ────────────────────────────────────────────────────────────
# 通用寄存器：Wn / Xn 归一化
# ────────────────────────────────────────────────────────────


@dataclass
class RegisterView:
    """ARM64 通用寄存器抽象。Wn 是 Xn 的低 32 位视口。"""

    reg_num: int                                # 0-30 对应 X0-X30
    written_as_32bit: bool = False              # 最近一次写入是否为 Wn

    @staticmethod
    def parse_reg_num(reg_str: str) -> int:
        """从字符串提取寄存器编号。W8/X8/SP/LR 等 → 编号。"""
        clean = reg_str.strip().upper()
        if clean in ("SP", "WSP", "XSP"):
            return 31
        if clean in ("LR", "WLR", "XLR"):
            return 30
        if clean.startswith("W") or clean.startswith("X"):
            return int(clean[1:])
        raise ValueError(f"无法解析寄存器: {reg_str}")

    @staticmethod
    def resolve_alias(reg_str: str) -> tuple[str, int]:
        """
        统一归一化为 "Rn" + 位宽。

        返回:
            (canonical_name, bit_width)
            "W8" → ("R8", 32)
            "X8" → ("R8", 64)
        """
        clean = reg_str.strip().upper()
        num = RegisterView.parse_reg_num(clean)
        is_32bit = clean.startswith("W")
        return (f"R{num}", 32 if is_32bit else 64)

    @property
    def canonical(self) -> str:
        return f"R{self.reg_num}"

    def mark_write(self, bit_width: int):
        """标记最近一次写入的位宽。32 = Wn 写入，64 = Xn 写入。"""
        self.written_as_32bit = (bit_width == 32)


# ────────────────────────────────────────────────────────────
# NEON 向量寄存器：16-Lane Bitmask + Shuffle Map
# ────────────────────────────────────────────────────────────

# 所有会产生 Lane 重映射的 Shuffle 指令 (小写)
SHUFFLE_INSTRUCTIONS = frozenset(
    {"ext", "tbl", "tbx", "zip1", "zip2", "uzp1", "uzp2", "trn1", "trn2"}
)


@dataclass
class NEONVectorNode:
    """
    ARM64 128-bit NEON 向量寄存器抽象。

    每个 byte lane (0-15) 独立追踪 def 来源指令。
    支持全写 (AESE 0xFFFF) / 单字节写 (INS 1<<i) / Lane 重映射 (EXT/TBL/ZIP/TRN)。
    """

    reg_num: int                                 # 0-31 → V0-V31
    lane_defs: list[Optional[str]] = field(      # 每个 lane 的 def 来源指令 ID
        default_factory=lambda: [None] * 16
    )

    # ── 写入 ──

    def update_lanes(self, lane_mask: int, source_insn_id: str):
        """
        按 bitmask 标记 lane 的 def 来源。

        lane_mask 为 16-bit 位图 (0x0000-0xFFFF)。
        bit i 为 1 表示 byte lane i 被完全写入。
        """
        for i in range(16):
            if lane_mask & (1 << i):
                self.lane_defs[i] = source_insn_id

    def update_shuffle(self, lane_map: dict[int, tuple[NEONVectorNode, int]]):
        """
        Lane 重映射: EXT / TBL / ZIP / UZP / TRN 等指令。

        lane_map: {dest_lane_index: (src_node, src_lane_index)}
        将源寄存器的 lane def 链"穿透"到目标寄存器对应 lane。
        """
        for dst_i, (src_node, src_i) in lane_map.items():
            self.lane_defs[dst_i] = src_node.lane_defs[src_i]

    # ── 读取 ──

    def get_active_defs(self, read_mask: int) -> set[str]:
        """
        查询指定 lane 区间对应的 def 指令 ID 集合。

        read_mask: 16-bit 位图，如 0xFFFF=全读，0x0010=只读 byte 4。
        返回实际为这些 lane 贡献数据的指令 ID（去重）。
        """
        defs: set[str] = set()
        for i in range(16):
            if (read_mask & (1 << i)) and self.lane_defs[i] is not None:
                defs.add(self.lane_defs[i])
        return defs

    def any_lane_defined(self, lane_mask: int) -> bool:
        """至少一个指定 lane 有 def 来源。"""
        for i in range(16):
            if (lane_mask & (1 << i)) and self.lane_defs[i] is not None:
                return True
        return False

    # ── 便利方法 ──

    FULL_MASK: int = 0xFFFF                     # 全 16 lane

    @property
    def canonical(self) -> str:
        return f"V{self.reg_num}"


# ────────────────────────────────────────────────────────────
# NEON 指令解析辅助
# ────────────────────────────────────────────────────────────

def parse_neon_arrangement(op_str: str) -> int:
    """
    从 Capstone 操作数字符串提取 lane 数量。
    ".16b" → 16, ".8b" → 8, ".4s" → 4, ".2d" → 2。
    返回 0 表示解析失败。
    """
    op = op_str.strip().lower()
    if ".16b" in op or ".8h" in op or ".4s" in op:
        return 16
    if ".8b" in op or ".4h" in op or ".2s" in op:
        return 8
    if ".4b" in op or ".2h" in op:
        return 4
    if ".1d" in op:
        return 1
    return 0


def lane_mask_from_arrangement(arrangement: int) -> int:
    """将 lane 数量转为 16-bit 位图。16 → 0xFFFF, 8 → 0x00FF。"""
    if arrangement >= 16:
        return 0xFFFF
    return (1 << arrangement) - 1
