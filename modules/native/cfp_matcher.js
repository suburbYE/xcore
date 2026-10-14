#!/usr/bin/env node
/**
 * cfp_matcher.js — L5 CFG+数据流模式匹配
 * Phase 4b: 指令流中的位运算密集模式识别（不依赖完整 CFG 解析）
 *
 * Usage: node cfp_matcher.js --so <path> [--json]
 */

"use strict";

const fs = require("fs");
const path = require("path");
const { PEParser, detectFormat } = require("./pe_parser.js");

// ─── ELF 常量 ───────────────────────────────────────────────────────────────
const EI_CLASS   = 4;
const EI_DATA    = 5;
const EM_AARCH64 = 183;
const EM_ARM     = 40;
const EM_X86_64  = 62;

// ─── 指令解码器（字节码模式匹配，零依赖） ──────────────────────────────────

/** ARM64 指令解码 */
class ARM64Decoder {
  /**
   * 解码单条指令（4 字节 LE）为操作助记符和操作数描述
   * 返回 { mnemonic, opStr, category }
   */
  decode(insn) {
    const op0 = (insn >> 25) & 0xF;

    // EXTR must be checked BEFORE Data processing immediate:
    // EXTR encoding: x 00 1111 0 0 0 in bits 31-22 (op0=9)
    // DP-imm: x 00/10 1000 x in bits 31-23 (op0=8 or 9)
    // Both share op0=8/9; EXTR distinguished by bit 24=1 + bit 22=0
    if ((insn & 0x1FE00000) === 0x13800000) {
      return { mnemonic: "EXTR", category: "shift" };
    }

    // Data processing immediate
    if (op0 >= 8 && op0 <= 9) {
      const op = (insn >> 29) & 0x3;
      if (op === 0) return { mnemonic: "ADD_imm",   category: "arith" };
      if (op === 1) return { mnemonic: "ADDS_imm",  category: "arith" };
      if (op === 2) return { mnemonic: "SUB_imm",   category: "arith" };
      if (op === 3) return { mnemonic: "SUBS_imm",  category: "arith" };
    }

    // Logical immediate
    if (op0 === 0x0C || op0 === 0x0D) {
      const op = (insn >> 29) & 0x3;
      if (op === 0) return { mnemonic: "AND_imm",   category: "logic" };
      if (op === 1) return { mnemonic: "ORR_imm",   category: "logic" };
      if (op === 2) return { mnemonic: "EOR_imm",   category: "logic" };
      if (op === 3) return { mnemonic: "ANDS_imm",  category: "logic" };
    }

    // Bitfield: SBFM/UBFM/BFI/BFXIL/SBFIZ/UBFIZ
    if ((insn & 0x1F800000) === 0x13000000) {
      const opc = (insn >> 29) & 0x3;
      if (opc === 0) return { mnemonic: "SBFM", category: "bitfield" };
      if (opc === 2) return { mnemonic: "UBFM", category: "bitfield" };
    }

    // Extract (UBFX/SBFX): bit 22=1 distinguishes from EXTR (bit 22=0)
    if ((insn & 0x1FC00000) === 0x13C00000) {
      return { mnemonic: "UBFX", category: "bitfield" };
    }

    // MADD/MSUB
    if ((insn & 0x1F800000) === 0x1B000000) {
      const op = (insn >> 31) & 1;
      return { mnemonic: op ? "MSUB" : "MADD", category: "arith" };
    }

    // ADD/SUB (shifted register): bits 28-24 = 01011
    if ((insn & 0x1F000000) === 0x0B000000) {
      return { mnemonic: "ADD_reg", category: "arith" };
    }

    // AND/ORR/EOR (shifted register): bits 28-24 = 01010
    if ((insn & 0x1F000000) === 0x0A000000) {
      const opc = (insn >> 29) & 0x3;
      if (opc === 0) return { mnemonic: "AND_reg", category: "logic" };
      if (opc === 1) return { mnemonic: "ORR_reg", category: "logic" };
      if (opc === 2) return { mnemonic: "EOR_reg", category: "logic" };
    }

    // Branches: B, BL, BLR, RET, BR, B.cond
    if ((insn & 0x7C000000) === 0x14000000) return { mnemonic: "B",    category: "branch" };
    if ((insn & 0x7C000000) === 0x14000000 && (insn >> 31)) return { mnemonic: "BL", category: "branch" };
    if ((insn & 0xFF000000) === 0x94000000) return { mnemonic: "BL",   category: "branch" };
    if ((insn & 0xFFFFFC1F) === 0xD63F0000) return { mnemonic: "BLR",  category: "branch" };
    if ((insn & 0xFFFFFC1F) === 0xD65F0000) return { mnemonic: "RET",  category: "branch" };

    // Compare: CMP (SUBS XZR, ...), TST (ANDS XZR, ...)
    if ((insn & 0xFFE00000) === 0xF1000000) return { mnemonic: "CMP", category: "compare" };
    if ((insn & 0xFFE00000) === 0xF2000000) return { mnemonic: "TST", category: "compare" };

    // MOVZ / MOVK
    if ((insn & 0x1F800000) === 0x12800000) return { mnemonic: "MOVN", category: "move" };
    if ((insn & 0x1F800000) === 0x52800000) return { mnemonic: "MOVZ", category: "move" };
    if ((insn & 0x1F800000) === 0x72800000) return { mnemonic: "MOVK", category: "move" };

    // Loads/Stores (simplified)
    if ((insn & 0xFFC00000) === 0xF9400000) return { mnemonic: "LDR",  category: "load"  };
    if ((insn & 0xFFC00000) === 0xF9000000) return { mnemonic: "STR",  category: "store" };

    return { mnemonic: "UNK", category: "unknown" };
  }
}

/** ARM32 指令解码 */
class ARM32Decoder {
  decode(insn) {
    const cond = (insn >> 28) & 0xF;
    const op   = (insn >> 21) & 0xF;
    const op1  = (insn >> 20) & 0x1F;

    // Data processing
    if (cond === 0xE || cond === 0) {
      // AND / EOR / SUB / RSB / ADD / ADC / SBC / RSC / TST / TEQ / CMP / CMN / ORR / MOV / BIC / MVN
      if ((op & 0xC) === 0) return { mnemonic: "AND", category: "logic" };
      if (op === 1) return { mnemonic: "EOR", category: "logic" };
      if (op === 2) return { mnemonic: "SUB", category: "arith" };
      if (op === 4) return { mnemonic: "ADD", category: "arith" };
      if (op === 8) return { mnemonic: "TST", category: "compare" };
      if (op === 0xA) return { mnemonic: "CMP", category: "compare" };
      if (op === 0xC) return { mnemonic: "ORR", category: "logic" };
      if (op === 0xD) return { mnemonic: "MOV", category: "move" };

      // Shifted register variants
      if ((insn & 0x0E000010) === 0x00000010) return { mnemonic: "AND_S", category: "logic" };
    }

    // Multiply: MUL/MLA
    if ((insn & 0x0FE000F0) === 0x00000090) return { mnemonic: "MUL",  category: "arith" };
    if ((insn & 0x0FE000F0) === 0x00200090) return { mnemonic: "MLA",  category: "arith" };

    // Branch: B / BL
    if ((insn & 0x0F000000) === 0x0A000000) return { mnemonic: "B",   category: "branch" };
    if ((insn & 0x0F000000) === 0x0B000000) return { mnemonic: "BL",  category: "branch" };

    // MOVW / MOVT
    if ((insn & 0x0FFF0000) === 0x03000000) return { mnemonic: "MOVW", category: "move" };
    if ((insn & 0x0FFF0000) === 0x03400000) return { mnemonic: "MOVT", category: "move" };

    // ROR (MOV with rotate)
    if ((insn & 0x0FEF0FF0) === 0x01A00070 && (insn & 0xFF0) !== 0) return { mnemonic: "ROR", category: "shift" };

    return { mnemonic: "UNK", category: "unknown" };
  }
}

/** x86_64 指令解码（简化） */
class X8664Decoder {
  decode(buf, offset) {
    const b = buf[offset];
    if (b === undefined) return { mnemonic: "EOF", category: "unknown" };

    // REX prefixes
    let rex = 0;
    let pos = offset;
    if ((b & 0xF0) === 0x40) { rex = b; pos++; }

    const op = buf[pos];
    if (op === undefined) return { mnemonic: "EOF", category: "unknown" };

    // MOV reg, reg
    if (op === 0x89) return { mnemonic: "MOV", category: "move", len: 3 };
    if (op === 0x8B) return { mnemonic: "MOV", category: "move", len: 3 };
    // MOV reg, imm64
    if ((op & 0xF8) === 0xB8) return { mnemonic: "MOV_imm", category: "move", len: (rex & 8) ? 9 : 6 };

    // Arithmetic
    if (op === 0x01) return { mnemonic: "ADD", category: "arith", len: 3 };
    if (op === 0x29) return { mnemonic: "SUB", category: "arith", len: 3 };
    if (op === 0x31) return { mnemonic: "XOR", category: "logic", len: 3 };
    if (op === 0x21) return { mnemonic: "AND", category: "logic", len: 3 };
    if (op === 0x09) return { mnemonic: "OR",  category: "logic", len: 3 };

    // ADD/SUB/XOR/AND/CMP with imm32
    if (op === 0x81) {
      const reg = (buf[pos + 1] >> 3) & 7;
      if (reg === 0) return { mnemonic: "ADD_imm", category: "arith", len: 6 };
      if (reg === 5) return { mnemonic: "SUB_imm", category: "arith", len: 6 };
      if (reg === 6) return { mnemonic: "XOR_imm", category: "logic", len: 6 };
      if (reg === 7) return { mnemonic: "CMP_imm", category: "compare", len: 6 };
    }

    // ROL reg, imm8: C1 /0 ib
    if (op === 0xC1 && ((buf[pos + 1] >> 3) & 7) === 0) return { mnemonic: "ROL", category: "shift", len: 3 };
    // ROR reg, imm8: C1 /1 ib
    if (op === 0xC1 && ((buf[pos + 1] >> 3) & 7) === 1) return { mnemonic: "ROR", category: "shift", len: 3 };
    // SHL reg, imm8: C1 /4 ib
    if (op === 0xC1 && ((buf[pos + 1] >> 3) & 7) === 4) return { mnemonic: "SHL", category: "shift", len: 3 };
    // SHR reg, imm8: C1 /5 ib
    if (op === 0xC1 && ((buf[pos + 1] >> 3) & 7) === 5) return { mnemonic: "SHR", category: "shift", len: 3 };

    // IMUL reg, reg: 0F AF /r
    if (op === 0x0F && buf[pos + 1] === 0xAF) return { mnemonic: "IMUL", category: "arith", len: 3 };

    // CALL rel32: E8
    if (op === 0xE8) return { mnemonic: "CALL", category: "branch", len: 5 };
    // JMP rel32: E9
    if (op === 0xE9) return { mnemonic: "JMP",  category: "branch", len: 5 };
    // RET: C3
    if (op === 0xC3) return { mnemonic: "RET",  category: "branch", len: 1 };

    // CMP
    if (op === 0x39) return { mnemonic: "CMP",  category: "compare", len: 3 };
    if (op === 0x3B) return { mnemonic: "CMP",  category: "compare", len: 3 };

    return { mnemonic: "UNK", category: "unknown", len: 1 };
  }
}

// ─── 模式匹配器 ─────────────────────────────────────────────────────────────

class PatternMatcher {
  constructor(arch, buf, textOffset, textSize) {
    this.arch = arch;
    this.buf = buf;
    this.textOffset = textOffset;
    this.textSize = textSize;

    if (arch === "arm64")  this.decoder = new ARM64Decoder();
    else if (arch === "arm32") this.decoder = new ARM32Decoder();
    else this.decoder = new X8664Decoder();
  }

  /** 遍历 .text 段，解码所有指令为序列 */
  decodeAll() {
    const insns = [];
    if (this.arch === "arm64" || this.arch === "arm32") {
      // 固定 4 字节对齐
      for (let off = this.textOffset; off < this.textOffset + this.textSize - 4; off += 4) {
        const raw = this.buf.readUInt32LE(off);
        const dec = this.decoder.decode(raw);
        insns.push({ offset: off - this.textOffset, raw, ...dec });
      }
    } else {
      // x86_64: 变长
      let off = this.textOffset;
      const end = this.textOffset + this.textSize;
      while (off < end) {
        const dec = this.decoder.decode(this.buf, off);
        const len = dec.len || 4;
        insns.push({ offset: off - this.textOffset, raw: 0, ...dec });
        off += len;
      }
    }
    return insns;
  }

  /** 检测 ROR/ROL 链：连续 2+ 条 ROR/ROL/EXTR */
  detectRorChains(insns) {
    const hits = [];
    const targetMnems = this.arch === "x86_64"
      ? ["ROR", "ROL"]
      : ["EXTR", "ROR", "UBFX"]; // ARM64 uses EXTR for ROR, ARM32 uses ROR

    let chainLen = 0;
    let chainStart = null;

    for (const insn of insns) {
      if (targetMnems.includes(insn.mnemonic) || insn.category === "shift") {
        if (chainLen === 0) chainStart = insn.offset;
        chainLen++;
      } else {
        if (chainLen >= 2) {
          hits.push(`0x${chainStart.toString(16)}`);
        }
        chainLen = 0;
        chainStart = null;
      }
      // 允许中间插入 1 条非移位指令（如 MOV）
      if (chainLen > 0 && chainLen <= 3) {
        // 检查下一条是不是移位
      }
    }
    if (chainLen >= 2) hits.push(`0x${chainStart.toString(16)}`);

    return hits;
  }

  /** 检测 XOR 掩码链：连续对疑似同一寄存器 XOR 不同常量 */
  detectXorChains(insns) {
    const hits = [];

    if (this.arch === "arm64") {
      // ARM64: EOR_imm 连续出现
      let chainLen = 0;
      let chainStart = null;
      for (const insn of insns) {
        if (insn.mnemonic === "EOR_imm") {
          if (chainLen === 0) chainStart = insn.offset;
          chainLen++;
        } else {
          if (chainLen >= 2) {
            hits.push(`0x${chainStart.toString(16)}`);
          }
          chainLen = 0;
          chainStart = null;
        }
      }
      if (chainLen >= 2) hits.push(`0x${chainStart.toString(16)}`);
    } else if (this.arch === "x86_64") {
      let chainLen = 0;
      let chainStart = null;
      for (const insn of insns) {
        if (insn.mnemonic === "XOR_imm") {
          if (chainLen === 0) chainStart = insn.offset;
          chainLen++;
        } else {
          if (chainLen >= 2) {
            hits.push(`0x${chainStart.toString(16)}`);
          }
          chainLen = 0;
          chainStart = null;
        }
      }
      if (chainLen >= 2) hits.push(`0x${chainStart.toString(16)}`);
    }

    return hits;
  }

  /** 检测 Shift+Add 组合：LSL/LSR + ADD/SUB → WyHash mum64 特征 */
  detectShiftAdd(insns) {
    const hits = [];
    // 滑动窗口：在 5 条指令内查找 (shift 类 + arith 类) 配对
    for (let i = 0; i < insns.length - 4; i++) {
      const window = insns.slice(i, i + 5);
      const hasShift = window.some(w => w.category === "shift" || w.category === "bitfield");
      const hasArith = window.some(w => w.category === "arith");
      if (hasShift && hasArith) {
        // 进一步验证是否是 mul-like: MADD + shift
        const hasMul = window.some(w => ["MADD", "MSUB", "MUL", "MLA", "IMUL"].includes(w.mnemonic));
        if (hasMul) {
          hits.push(`0x${window[0].offset.toString(16)}`);
        }
      }
    }
    return [...new Set(hits)].slice(0, 10);
  }

  /** 检测 WyHash MADD 模式：MADD + 移位 + XOR 密集区 */
  detectWyhashMadd(insns) {
    const hits = [];
    // 在 10 条指令窗口内检测：MADD + bitfield/shift + EOR/AND
    for (let i = 0; i < insns.length - 9; i++) {
      const window = insns.slice(i, i + 10);
      const hasMadd  = window.some(w => w.mnemonic === "MADD" || w.mnemonic === "IMUL");
      const hasShift = window.some(w => w.category === "shift" || w.category === "bitfield");
      const hasXor   = window.some(w => w.mnemonic === "EOR_imm" || w.mnemonic === "EOR" || w.mnemonic === "XOR_imm");
      if (hasMadd && hasShift && hasXor) {
        hits.push(`0x${window[0].offset.toString(16)}`);
      }
    }
    return [...new Set(hits)].slice(0, 10);
  }

  /** 检测 MD5 四函数模式：F(B,C,D) = (B&C) | (~B&D) */
  detectMd5Round(insns) {
    const hits = [];
    // AND + NOT + AND + OR 序列（在 6 条指令内）
    for (let i = 0; i < insns.length - 5; i++) {
      const window = insns.slice(i, i + 6);
      const andCount = window.filter(w => w.mnemonic.startsWith("AND") || w.mnemonic === "AND_imm").length;
      const orrCount = window.filter(w => w.mnemonic === "ORR_imm" || w.mnemonic === "ORR" || w.mnemonic === "OR").length;
      if (andCount >= 2 && orrCount >= 1) {
        hits.push(`0x${window[0].offset.toString(16)}`);
      }
    }
    return [...new Set(hits)].slice(0, 5);
  }

  /** 检测 AES MixColumns xtime 模式：LSL + EOR 在相邻字节上重复 */
  detectAesMixCols(insns) {
    const hits = [];
    // 检测 LSL#1 + EOR 模式
    for (let i = 0; i < insns.length - 3; i++) {
      const window = insns.slice(i, i + 4);
      const lslEorPattern = window.filter(w =>
        (w.category === "shift" || w.category === "bitfield") && w.mnemonic !== "UNK"
      ).length >= 1;
      const xorCount = window.filter(w =>
        w.mnemonic === "EOR_imm" || w.mnemonic === "EOR" || w.mnemonic === "XOR_imm"
      ).length >= 1;
      if (lslEorPattern && xorCount) {
        hits.push(`0x${window[0].offset.toString(16)}`);
      }
    }
    return [...new Set(hits)].slice(0, 5);
  }

  /** 检测 ChaCha20 quarter-round: ADD+EOR+EXTR 密集聚类（每 QR 含 4 组，非连续） */
  detectChaCha20QR(insns) {
    const hits = [];
    // ChaCha20 核心循环: 24 条指令内含有 3+ ADD/EOR/EXTR
    // 每条 QR: ADD_reg + LDR/STR×2 + EOR_reg + EXTR + STR 约 7 条，需要大窗口
    for (let i = 0; i < insns.length - 23; i++) {
      const window = insns.slice(i, i + 24);
      let addCount = 0, eorCount = 0, extrCount = 0;
      for (const insn of window) {
        if (["ADD_reg","ADD_imm","ADDS_imm","MADD"].includes(insn.mnemonic)) addCount++;
        if (["EOR_reg","EOR_imm"].includes(insn.mnemonic)) eorCount++;
        if (["EXTR"].includes(insn.mnemonic)) extrCount++;
      }
      if (addCount >= 3 && eorCount >= 3 && extrCount >= 3) {
        hits.push(`0x${window[0].offset.toString(16)}`);
      }
    }
    return [...new Set(hits)].slice(0, 10);
  }

  /** 统计循环轮数（TEA 16/32 轮：CMP+B.cond 回跳模式） */
  detectLoops(insns) {
    // 简化检测：找 CMP + B.cond 对，且目标地址在当前指令之前（回跳=循环）
    const loopRounds = [];
    for (let i = 0; i < insns.length; i++) {
      if (insns[i].category !== "compare") continue;
      // 后 3 条中找条件分支（回跳）
      for (let j = i + 1; j < Math.min(i + 4, insns.length); j++) {
        if (insns[j].mnemonic === "B" && this.arch === "arm64") {
          // ARM64 B.cond is in "B" category with cond check
          // Simplified: detect B with negative offset
          const raw = insns[j].raw;
          if (raw !== undefined) {
            const offset = ((raw & 0x3FFFFFF) << 2);
            // Sign extend 26-bit
            const signedOff = offset >= (1 << 27) ? offset - (1 << 28) : offset;
            if (signedOff < 0) {
              loopRounds.push(`0x${insns[i].offset.toString(16)}`);
            }
          }
        }
      }
    }
    return loopRounds;
  }
}

// ─── ELF 解析器 ─────────────────────────────────────────────────────────────
class MiniELFParser {
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
      this.e_machine  = this._readUInt(18, 2);
      this.e_shoff    = this._readUInt(40, 8);
      this.e_shnum    = this._readUInt(60, 2);
      this.e_shstrndx = this._readUInt(62, 2);
    } else {
      this.e_machine  = this._readUInt(18, 2);
      this.e_shoff    = this._readUInt(32, 4);
      this.e_shnum    = this._readUInt(48, 2);
      this.e_shstrndx = this._readUInt(50, 2);
    }
  }

  getSections() {
    const sections = [];
    const shEntSize = this.is64 ? 64 : 40;
    for (let i = 0; i < this.e_shnum; i++) {
      const off = this.e_shoff + i * shEntSize;
      if (off + shEntSize > this.buf.length) break;
      sections.push({
        sh_name:   this._readUInt(off, 4),
        sh_type:   this._readUInt(off + 4, 4),
        sh_addr:   this._readUInt(off + (this.is64 ? 16 : 12), this.is64 ? 8 : 4),
        sh_offset: this._readUInt(off + (this.is64 ? 24 : 16), this.is64 ? 8 : 4),
        sh_size:   this._readUInt(off + (this.is64 ? 32 : 20), this.is64 ? 8 : 4),
      });
    }
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
}

// ─── 命令行 ─────────────────────────────────────────────────────────────────
function parseArgs() {
  const args = process.argv.slice(2);
  const opts = { so: null, json: false, maxScanSize: 0 };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--so" && i + 1 < args.length) opts.so = args[++i];
    else if (args[i] === "--json") opts.json = true;
    else if (args[i] === "--max-scan-size" && i + 1 < args.length) opts.maxScanSize = parseInt(args[++i], 10) || 0;
  }
  return opts;
}

function main() {
  const opts = parseArgs();
  if (!opts.so) {
    console.error("Usage: node cfp_matcher.js --so <path> [--json]");
    process.exit(1);
  }

  const buf = fs.readFileSync(opts.so);

  // 按文件格式选择解析器：ELF → MiniELFParser，PE → PEParser
  const fmt = detectFormat(buf);
  const parser = fmt === "pe" ? new PEParser(buf) : new MiniELFParser(buf);
  const arch = fmt === "pe" ? parser.getArch() :
               parser.e_machine === EM_AARCH64 ? "arm64" :
               parser.e_machine === EM_ARM ? "arm32" :
               parser.e_machine === EM_X86_64 ? "x86_64" : "unknown";

  if (!opts.json) {
    console.error(`[cfp_matcher] Target: ${opts.so}`);
    console.error(`[cfp_matcher] Arch: ${arch} (format: ${fmt})`);
  }

  const sections = parser.getSections();
  const textSec = sections.find(s => s.name === ".text");

  if (!textSec) {
    const result = { patterns: [], score: 0, error: ".text section not found" };
    process.stdout.write(JSON.stringify(result, null, opts.json ? 0 : 2));
    return;
  }

  // --max-scan-size 0 = 全量扫描（不截断）
  const textSize = (opts.maxScanSize > 0) ? Math.min(textSec.sh_size, opts.maxScanSize) : textSec.sh_size;
  const matcher = new PatternMatcher(arch, buf, textSec.sh_offset, textSize);

  if (!opts.json) console.error("[cfp_matcher] Decoding instructions...");
  const insns = matcher.decodeAll();
  if (!opts.json) console.error(`[cfp_matcher] Decoded ${insns.length} instructions`);

  // Run all pattern detectors
  const rorChains    = matcher.detectRorChains(insns);
  const xorChains    = matcher.detectXorChains(insns);
  const shiftAdd     = matcher.detectShiftAdd(insns);
  const wyhashMadd   = matcher.detectWyhashMadd(insns);
  const md5Round     = matcher.detectMd5Round(insns);
  const aesMixCols   = matcher.detectAesMixCols(insns);
  const chacha20QR   = matcher.detectChaCha20QR(insns);
  const loops        = matcher.detectLoops(insns);

  const patterns = [];

  if (rorChains.length > 0) {
    patterns.push({ name: "ror_chain_x3", count: rorChains.length, locations: rorChains.slice(0, 5) });
  }
  if (xorChains.length > 0) {
    patterns.push({ name: "xor_mask_chain", count: xorChains.length, locations: xorChains.slice(0, 5) });
  }
  if (shiftAdd.length > 0) {
    patterns.push({ name: "shift_add_combo", count: shiftAdd.length, locations: shiftAdd.slice(0, 5) });
  }
  if (wyhashMadd.length > 0) {
    patterns.push({ name: "wyhash_madd_pattern", count: wyhashMadd.length, locations: wyhashMadd.slice(0, 5) });
  }
  if (md5Round.length > 0) {
    patterns.push({ name: "md5_round_pattern", count: md5Round.length, locations: md5Round.slice(0, 5) });
  }
  if (aesMixCols.length > 0) {
    patterns.push({ name: "aes_mixcols_pattern", count: aesMixCols.length, locations: aesMixCols.slice(0, 5) });
  }
  if (chacha20QR.length > 0) {
    patterns.push({ name: "chacha20_qr_pattern", count: chacha20QR.length, locations: chacha20QR.slice(0, 5) });
  }
  if (loops.length > 0) {
    patterns.push({ name: "loop_pattern", count: loops.length, locations: loops.slice(0, 5) });
  }

  // L5 得分：每个模式族 0.04，上限 0.20
  const score = Math.min(0.20, patterns.length * 0.04);

  const result = { patterns, score };
  process.stdout.write(JSON.stringify(result, null, opts.json ? 0 : 2));
  if (!opts.json) process.stdout.write("\n");
}

main();
