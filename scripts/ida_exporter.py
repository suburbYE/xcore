"""
ida_exporter.py — IDAPython 伪代码 + 种子变量提取脚本

在 IDA Pro GUI 或 Headless 模式下运行:
    idat64.exe -A -S"ida_exporter.py <output_dir>" libtarget.so

输出:
    pseudocode.c          — 目标函数伪代码文本
    seeds.json            — 自动推断的 seed_vars
    anchors.json          — .rodata 常量数组 RVA 列表

作者: xcore
许可: MIT
"""

import json
import os
import sys
import re
import idaapi
import ida_funcs
import ida_hexrays
import ida_segment
import ida_bytes
import ida_name

# ────────────────────────────────────────────────────────────
# 配置
# ────────────────────────────────────────────────────────────

# 目标函数 RVA (从命令行参数或手动修改)
TARGET_RVA = 0x0                 # 默认 0，由 pipeline_runner 传入

# 密码学常量表特征 (用于 .rodata 扫描)
CRYPTO_TABLE_SIGNATURES = {
    "AES_SBOX":     bytes([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5]),
    "AES_INVSBOX":  bytes([0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38]),
    "SM4_SBOX":     bytes([0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7]),
    "SHA256_K":     bytes([0x42, 0x8A, 0x2F, 0x98, 0x71, 0x37, 0x44, 0x91]),
}

# ────────────────────────────────────────────────────────────
# 主流程
# ────────────────────────────────────────────────────────────

def main():
    output_dir = "."
    if len(idc.ARGV) > 1:
        output_dir = idc.ARGV[1]
    os.makedirs(output_dir, exist_ok=True)

    # 1. 提取伪代码
    code, seed_vars = extract_pseudocode(TARGET_RVA)
    if code:
        with open(os.path.join(output_dir, "pseudocode.c"), "w", encoding="utf-8") as f:
            f.write(code)
        print(f"[ida_exporter] Pseudocode written ({len(code)} chars)")

    # 2. 种子变量
    seeds = {"seed_vars": list(seed_vars), "target_rva": hex(TARGET_RVA)}
    with open(os.path.join(output_dir, "seeds.json"), "w", encoding="utf-8") as f:
        json.dump(seeds, f, indent=2)
    print(f"[ida_exporter] Seeds: {seed_vars}")

    # 3. .rodata 常量锚点
    anchors = scan_rodata_tables()
    with open(os.path.join(output_dir, "anchors.json"), "w", encoding="utf-8") as f:
        json.dump(anchors, f, indent=2)
    print(f"[ida_exporter] Anchors found: {len(anchors)} tables")

    # 退出
    if idaapi.is_headless():
        idc.qexit(0)


# ────────────────────────────────────────────────────────────
# 伪代码提取
# ────────────────────────────────────────────────────────────

def extract_pseudocode(rva: int) -> tuple[str, set[str]]:
    """提取目标 RVA 的伪代码 + 自动推断种子变量"""
    func = ida_funcs.get_func(rva)
    if not func:
        print(f"[ida_exporter] No function at RVA 0x{rva:X}")
        return "", set()

    # 反编译
    try:
        cfunc = ida_hexrays.decompile(func)
        pseudocode = str(cfunc)
    except Exception as e:
        print(f"[ida_exporter] Decompile failed: {e}")
        return "", set()

    # 推断种子变量
    seed_vars = infer_seed_variables(pseudocode)

    return pseudocode, seed_vars


def infer_seed_variables(pseudocode: str) -> set[str]:
    """
    自动推断切片种子变量。

    规则:
    1. 函数入参: a1, a2 (IDA 默认命名)
    2. 返回值涉及的变量
    3. 写入 *(a1 + ...) 的基址指针
    """
    seeds: set[str] = set()

    lines = pseudocode.split("\n")

    # 函数入参 (匹配 void / __int64 __fastcall func(__int64 a1, ...) 模式)
    for line in lines[:20]:                            # 只在头部找
        found = re.findall(r'\b(a\d+)\b', line)
        seeds.update(found)

    # 返回值涉及的变量
    for line in reversed(lines):
        if line.strip().startswith("return "):
            seeds.update(re.findall(r'\b([va]\d+)\b', line))
            break

    # 写入输出 buffer 的指针
    for line in lines:
        if "*" in line and "=" in line:
            lhs = line.split("=")[0]
            if lhs.strip().startswith("*"):
                seeds.update(re.findall(r'\b([va]\d+)\b', lhs))

    # 去重去空
    return {s for s in seeds if s}


# ────────────────────────────────────────────────────────────
# .rodata 常量表扫描
# ────────────────────────────────────────────────────────────

def scan_rodata_tables() -> list[dict]:
    """扫描 .rodata 段中的密码学常量表"""
    results = []

    seg = ida_segment.get_segm_by_name(".rodata")
    if not seg:
        seg = ida_segment.get_segm_by_name(".rdata")
    if not seg:
        return results

    start, end = seg.start_ea, seg.end_ea

    for name, sig in CRYPTO_TABLE_SIGNATURES.items():
        ea = ida_bytes.bin_search(
            start, end, sig, None,
            ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOCASE
        )
        if ea != idaapi.BADADDR:
            results.append({
                "name": name,
                "rva": hex(ea),
                "size": 256 if "SBOX" in name else 64,
                "signature": sig.hex(),
            })

    return results


# ────────────────────────────────────────────────────────────
# 入口
# ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    main()
