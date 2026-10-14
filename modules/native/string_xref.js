#!/usr/bin/env node
/**
 * string_xref.js — 字符串交叉引用追踪
 * Phase 4b: 对 .so 中的关键字符串反向追踪其在 .text 段中的引用位置
 *
 * Usage: node string_xref.js --so <path> --strings <json_array> [--json]
 */

"use strict";

const fs = require("fs");
const path = require("path");
const { PEParser, detectFormat } = require("./pe_parser.js");

// ─── ELF 常量 ───────────────────────────────────────────────────────────────
const EI_CLASS       = 4;   // 1=32-bit, 2=64-bit
const EI_DATA        = 5;   // 1=LE, 2=BE
const EM_AARCH64     = 183;
const EM_ARM         = 40;
const EM_X86_64      = 62;

const PT_LOAD        = 1;
const PT_DYNAMIC     = 2;

const SHT_SYMTAB     = 2;
const SHT_STRTAB     = 3;
const SHT_DYNSYM     = 11;

// ─── 命令行解析 ─────────────────────────────────────────────────────────────
function parseArgs() {
  const args = process.argv.slice(2);
  const opts = { so: null, strings: null, json: false, maxScanSize: 0 };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--so" && i + 1 < args.length) opts.so = args[++i];
    else if (args[i] === "--strings" && i + 1 < args.length) opts.strings = JSON.parse(args[++i]);
    else if (args[i] === "--json") opts.json = true;
    else if (args[i] === "--max-scan-size" && i + 1 < args.length) opts.maxScanSize = parseInt(args[++i], 10) || 0;
  }
  if (!opts.so || !opts.strings || !Array.isArray(opts.strings)) {
    console.error("Usage: node string_xref.js --so <path> --strings <json_array> [--json]");
    process.exit(1);
  }
  return opts;
}

// ─── ELF 解析 ───────────────────────────────────────────────────────────────
class ELFParser {
  constructor(buf) {
    this.buf = buf;
    this.is64 = buf[EI_CLASS] === 2;
    this.isLE  = buf[EI_DATA] === 1;
    this._parseHeader();
  }

  _readUInt(offset, size) {
    if (size === 2) return this.isLE ? this.buf.readUInt16LE(offset) : this.buf.readUInt16BE(offset);
    if (size === 4) return this.isLE ? this.buf.readUInt32LE(offset) : this.buf.readUInt32BE(offset);
    if (size === 8) {
      return this.isLE
        ? Number(this.buf.readBigUInt64LE(offset))
        : Number(this.buf.readBigUInt64BE(offset));
    }
    return 0;
  }

  _parseHeader() {
    if (this.is64) {
      this.e_machine   = this._readUInt(18, 2);
      this.e_phoff     = this._readUInt(32, 8);
      this.e_phnum     = this._readUInt(56, 2);
      this.e_shoff     = this._readUInt(40, 8);
      this.e_shnum     = this._readUInt(60, 2);
      this.e_shstrndx  = this._readUInt(62, 2);
    } else {
      this.e_machine   = this._readUInt(18, 2);
      this.e_phoff     = this._readUInt(28, 4);
      this.e_phnum     = this._readUInt(44, 2);
      this.e_shoff     = this._readUInt(32, 4);
      this.e_shnum     = this._readUInt(48, 2);
      this.e_shstrndx  = this._readUInt(50, 2);
    }
  }

  getArch() {
    if (this.e_machine === EM_AARCH64) return "arm64";
    if (this.e_machine === EM_ARM)     return "arm32";
    if (this.e_machine === EM_X86_64)  return "x86_64";
    return "unknown";
  }

  getSections() {
    const sections = [];
    const shEntSize = this.is64 ? 64 : 40;
    for (let i = 0; i < this.e_shnum; i++) {
      const off = this.e_shoff + i * shEntSize;
      if (off + shEntSize > this.buf.length) break;
      const sh_name   = this._readUInt(off, 4);
      const sh_type   = this._readUInt(off + 4, 4);
      const sh_addr   = this._readUInt(off + (this.is64 ? 16 : 12), this.is64 ? 8 : 4);
      const sh_offset = this._readUInt(off + (this.is64 ? 24 : 16), this.is64 ? 8 : 4);
      const sh_size   = this._readUInt(off + (this.is64 ? 32 : 20), this.is64 ? 8 : 4);
      sections.push({ idx: i, sh_name, sh_type, sh_addr, sh_offset, sh_size });
    }
    // 解析段名
    if (this.e_shstrndx < sections.length) {
      const strSec = sections[this.e_shstrndx];
      for (const sec of sections) {
        sec.name = this._readCString(strSec.sh_offset + sec.sh_name);
      }
    }
    return sections;
  }

  _readCString(offset) {
    let end = offset;
    while (end < this.buf.length && this.buf[end] !== 0) end++;
    return this.buf.toString("utf8", offset, end);
  }

  /** 读取指定偏移和长度的 Buffer */
  slice(offset, length) {
    return this.buf.slice(offset, Math.min(offset + length, this.buf.length));
  }
}

// ─── 指令模式匹配 ───────────────────────────────────────────────────────────
class InstructionMatcher {
  constructor(arch, buf) {
    this.arch = arch;
    this.buf = buf;
  }

  /**
   * 搜索对指定地址的引用
   * @param {number} targetAddr - .rodata/.data 中字符串的虚拟地址（RVA/VA）
   * @param {number} textOffset - .text 段文件偏移
   * @param {number} textSize   - .text 段大小
   * @param {number} textVAddr  - .text 段虚拟地址（RVA/VA），用于 RIP 相对寻址换算
   * @returns {Array<{at: number, type: string}>}
   */
  findXRefs(targetAddr, textOffset, textSize, textVAddr) {
    const refs = [];
    const chunkSize = 4; // 对齐到 4 字节
    const end = textOffset + textSize - 4;

    if (this.arch === "arm64") {
      // ARM64: ADRP Xd, #page + ADD Xd, Xd, #offset 模式
      // ADRP 编码: 1xx10000 + Rd(5) + immhi(19) + immlo(2)
      // 实际搜索：遍历中找到 ADRP，然后检查下一条是否 ADD/LDR 且引用同一页
      for (let off = textOffset; off < end; off += 4) {
        const insn = this.buf.readUInt32LE(off);
        // ADRP: bits[31] == 1 && bits[29:24] == 10000 (简化)
        if ((insn & 0x9F000000) === 0x90000000) {
          const rd = insn & 0x1F;
          const immhi = (insn >> 5) & 0x7FFFF;
          const immlo = (insn >> 29) & 0x3;
          const page = ((immhi << 2) | immlo) << 12;
          // 下一条指令
          if (off + 4 <= end) {
            const next = this.buf.readUInt32LE(off + 4);
            // ADD Xd, Xd, #imm12: 1001000100 + imm12(12) + Rn(5) + Rd(5)
            if ((next & 0xFFC00000) === 0x91000000) {
              const rn = (next >> 5) & 0x1F;
              const nrd = next & 0x1F;
              if (rn === rd && nrd === rd) {
                const imm12 = (next >> 10) & 0xFFF;
                const addr = (((off - textOffset + textVAddr) & ~0xFFF) + page + imm12) >>> 0;
                if (addr === targetAddr || (addr & 0xFFFFFFFF) === (targetAddr & 0xFFFFFFFF)) {
                  refs.push({ at: off - textOffset, type: "adrp_add" });
                }
              }
            }
            // LDR Xt, [Xn, #offset]: 1111100001 + offset(12) + Rn(5) + Rt(5)
            // but unsigned offset: 1111100101...
            if ((next & 0xFFC00000) === 0xF9400000) {
              const rn = (next >> 5) & 0x1F;
              const rt = next & 0x1F;
              if (rn === rd) {
                const imm12 = ((next >> 10) & 0xFFF) << 2; // scaled by 4
                const addr = (((off - textOffset + textVAddr) & ~0xFFF) + page + imm12) >>> 0;
                if (addr === targetAddr || (addr & 0xFFFFFFFF) === (targetAddr & 0xFFFFFFFF)) {
                  refs.push({ at: off - textOffset, type: "adrp_ldr" });
                }
              }
            }
          }
        }
      }
    } else if (this.arch === "arm32") {
      // ARM32: LDR Rt, [PC, #imm] 模式 — PC 相对加载
      // LDR (literal): cond:4=1110, 01U001, U=1, 11111, Rt, imm12
      // 编码: 0xE59F0000 mask (U=1 literal load)
      for (let off = textOffset; off < end; off += 4) {
        const insn = this.buf.readUInt32LE(off);
        if ((insn & 0x0E5F0000) === 0x041F0000) {
          // LDR literal
          const u = (insn >> 23) & 1;
          const imm12 = insn & 0xFFF;
          const pc = (off - textOffset + textVAddr + 8);
          const addr = u ? pc + imm12 : pc - imm12;
          if ((addr & 0xFFFFFFFF) === (targetAddr & 0xFFFFFFFF)) {
            refs.push({ at: off - textOffset, type: "ldr_literal" });
          }
        }
        // Also check MOVW+MOVT pair for absolute addresses
        // MOVW: 0xE3000000, MOVT: 0xE3400000
        if ((insn & 0x0FFF0000) === 0x03000000) {
          // MOVW
          const rd = (insn >> 12) & 0xF;
          const imm16 = ((insn >> 4) & 0xF000) | (insn & 0xFFF);
          if (off + 8 <= end) {
            const next = this.buf.readUInt32LE(off + 4);
            if ((next & 0x0FFF0000) === 0x03400000) {
              const nrd = (next >> 12) & 0xF;
              if (nrd === rd) {
                const imm16h = ((next >> 4) & 0xF000) | (next & 0xFFF);
                const addr = (imm16h << 16) | imm16;
                if (addr === targetAddr) {
                  refs.push({ at: off - textOffset, type: "movw_movt" });
                }
              }
            }
          }
        }
      }
    } else if (this.arch === "x86_64") {
      // x86_64: LEA reg, [RIP+disp32] 模式
      // LEA r64: REX.W(48/4C) + 8D + ModRM + disp32
      for (let off = textOffset; off < end; off++) {
        if ((this.buf[off] === 0x48 || this.buf[off] === 0x4C) && this.buf[off + 1] === 0x8D) {
          const modrm = this.buf[off + 2];
          const mod = (modrm >> 6) & 0x3;
          const rm  = modrm & 0x7;
          // RIP-relative: mod=00, rm=101
          if (mod === 0 && rm === 5 && off + 7 < end) {
            const disp32 = this.buf.readInt32LE(off + 3);
            const rip = textVAddr + (off - textOffset) + 7;
            const addr = (rip + disp32) >>> 0;
            if (addr === targetAddr) {
              refs.push({ at: off - textOffset, type: "lea_rip" });
            }
          }
        }
        // MOV reg, [RIP+disp32]: REX.W + 8B + ModRM(00xxx101) + disp32
        if ((this.buf[off] === 0x48 || this.buf[off] === 0x4C) && this.buf[off + 1] === 0x8B) {
          const modrm = this.buf[off + 2];
          const mod = (modrm >> 6) & 0x3;
          const rm  = modrm & 0x7;
          if (mod === 0 && rm === 5 && off + 7 < end) {
            const disp32 = this.buf.readInt32LE(off + 3);
            const rip = textVAddr + (off - textOffset) + 7;
            const addr = (rip + disp32) >>> 0;
            if (addr === targetAddr) {
              refs.push({ at: off - textOffset, type: "mov_rip" });
            }
          }
        }
      }
    }
    return refs;
  }
}

// ─── 符号表解析（辅助函数命名） ─────────────────────────────────────────────
function parseSymbols(sections, parser) {
  const symMap = new Map(); // addr → name
  // PE 无 ELF dynsym 表，导入表符号不携带导出地址，直接返回空表（函数名回落 sub_XXXX）
  if (parser instanceof PEParser) return symMap;
  for (const sec of sections) {
    if (sec.sh_type !== SHT_SYMTAB && sec.sh_type !== SHT_DYNSYM) continue;

    const strSec = sections.find(s => s.name === ".strtab" || s.name === ".dynstr");
    if (!strSec) continue;

    const symEntSize = parser.is64 ? 24 : 16;
    const numSyms = Math.floor(sec.sh_size / symEntSize);

    for (let i = 0; i < numSyms; i++) {
      const symOff = sec.sh_offset + i * symEntSize;
      const st_name  = parser._readUInt(symOff, 4);
      const st_value = parser._readUInt(symOff + (parser.is64 ? 8 : 4), parser.is64 ? 8 : 4);
      if (st_value > 0 && st_name > 0) {
        const name = parser._readCString(strSec.sh_offset + st_name);
        if (name) symMap.set(st_value, name);
      }
    }
  }
  return symMap;
}

/** 根据地址查找最近符号名（用于自动命名 sub_XXXXX） */
function findEnclosingSymbol(addr, symMap) {
  let bestName = null;
  let bestDist = Infinity;
  for (const [symAddr, name] of symMap) {
    if (symAddr <= addr && (addr - symAddr) < bestDist) {
      bestDist = addr - symAddr;
      bestName = name;
    }
  }
  return bestName;
}

// ─── 引用类型推断 ───────────────────────────────────────────────────────────
function inferRefTypes(xrefs, textBuf, textOffset) {
  return xrefs.map(xref => {
    const off = xref.at + textOffset;
    const nearby = textBuf.slice(Math.max(0, off - 16), Math.min(textBuf.length, off + 20));
    const context = nearby.toString("hex");

    // 检测函数调用模式：xref 附近有 BL/BLR/CALL
    let type = "stack_store";
    if (context.includes("94000000") || context.includes("e8")) {
      type = "call_arg";
    } else if (context.includes("7100") || context.includes("83")) {
      // CMP/TEST → cmp_operand
      type = "cmp_operand";
    }

    return { ...xref, type };
  });
}

// ─── 主流程 ─────────────────────────────────────────────────────────────────
function main() {
  const opts = parseArgs();
  const buf = fs.readFileSync(opts.so);

  // 按文件格式选择解析器：ELF → ELFParser，PE → PEParser
  const fmt = detectFormat(buf);
  const parser = fmt === "pe" ? new PEParser(buf) : new ELFParser(buf);
  const arch = parser.getArch();

  if (!opts.json) {
    console.error(`[string_xref] Target: ${opts.so}`);
    console.error(`[string_xref] Arch: ${arch} (format: ${fmt})`);
    console.error(`[string_xref] Searching ${opts.strings.length} strings`);
  }

  const sections = parser.getSections();

  // 找到关键段（PE 只读数据段为 .rdata，ELF 为 .rodata）
  const textSec  = sections.find(s => s.name === ".text");
  const rodataSec = sections.find(s => s.name === ".rodata") || sections.find(s => s.name === ".rdata");
  const dataSec  = sections.find(s => s.name === ".data");
  const dataSections = [rodataSec, dataSec].filter(Boolean);

  if (!textSec) {
    console.error("[string_xref] ERROR: .text section not found");
    process.exit(1);
  }

  // 解析符号表供后续函数命名
  const symMap = parseSymbols(sections, parser);

  // --max-scan-size 0 = 全量扫描（不截断）
  const textSearchSize = (opts.maxScanSize > 0) ? Math.min(textSec.sh_size, opts.maxScanSize) : textSec.sh_size;
  const textBuf = buf.slice(textSec.sh_offset, textSec.sh_offset + textSearchSize);

  const matcher = new InstructionMatcher(arch, buf);
  const results = [];

  for (const searchStr of opts.strings) {
    const strBytes = Buffer.from(searchStr, "utf8");
    let found = false;

    // 在所有数据段中搜索字符串
    for (const ds of dataSections) {
      if (!ds || ds.sh_size === 0) continue;
      const searchSize = (opts.maxScanSize > 0) ? Math.min(ds.sh_size, opts.maxScanSize) : ds.sh_size;
      const dsBuf = buf.slice(ds.sh_offset, ds.sh_offset + searchSize);

      let searchPos = 0;
      while (searchPos <= dsBuf.length - strBytes.length) {
        const idx = dsBuf.indexOf(strBytes, searchPos);
        if (idx === -1) break;

        const strVAddr = ds.sh_addr + idx;
        const fileOffset = ds.sh_offset + idx;

        // 对该地址做交叉引用追踪
        const rawXRefs = matcher.findXRefs(strVAddr, textSec.sh_offset, textSearchSize, textSec.sh_addr);
        const typedXRefs = inferRefTypes(rawXRefs, textBuf, textSec.sh_offset);

        // 推断所在函数
        const enrichedXRefs = typedXRefs.map(xref => {
          const absAddr = xref.at + textSec.sh_addr;
          const funcName = findEnclosingSymbol(absAddr, symMap) || `sub_${xref.at.toString(16)}`;
          let context = "data_reference";
          if (xref.type === "call_arg") context = "signature generation entry";
          else if (xref.type === "cmp_operand") context = "string comparison";

          return {
            at: `0x${xref.at.toString(16)}`,
            func: funcName,
            type: xref.type,
            context
          };
        });

        results.push({
          string: searchStr,
          offset: `0x${(ds.sh_offset + idx).toString(16)}`,
          vaddr: `0x${strVAddr.toString(16)}`,
          section: ds.name,
          xrefs: enrichedXRefs
        });

        found = true;
        searchPos = idx + strBytes.length;
      }
    }

    if (!found && !opts.json) {
      console.error(`[string_xref] WARNING: string "${searchStr}" not found in data sections`);
    }
  }

  // 输出 JSON
  process.stdout.write(JSON.stringify(results, null, opts.json ? 0 : 2));
  if (!opts.json) process.stdout.write("\n");
}

main();
