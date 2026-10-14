#!/usr/bin/env node
/**
 * pe_parser.js — PE (Portable Executable) section 解析器
 * Phase 4b: 为 constant_scanner / string_xref / cfp_matcher 提供 PE 支持，
 *           使 DLL/EXE 不再因 ELF-only 解析而丢失 L2/L3/L5/xrefs。
 *
 * 接口与 ELFParser 对齐（getSections / _readUInt / _readCString / getArch / is64 / isLE），
 * 便于上层模块按相同方式消费。
 */

"use strict";

// PE 常量
const IMAGE_FILE_MACHINE_I386   = 0x014C;
const IMAGE_FILE_MACHINE_ARM    = 0x01C0;
const IMAGE_FILE_MACHINE_ARMNT  = 0x01C4;
const IMAGE_FILE_MACHINE_AMD64  = 0x8664;
const IMAGE_FILE_MACHINE_ARM64  = 0xAA64;

const IMAGE_DIRECTORY_ENTRY_IMPORT = 1;

/**
 * 轻量 PE 解析器：解析 DOS/COFF/Optional/Section Table，
 * 并支持 import 表遍历（L3 符号层）。
 */
class PEParser {
  constructor(buf) {
    this.buf = buf;
    this.isLE = true; // PE 一律小端
    this.is64 = false;
    this.e_machine = 0;
    this.peOffset = -1;
    this._parseHeader();
  }

  _readUInt(offset, size) {
    if (size === 2) return this.buf.readUInt16LE(offset);
    if (size === 4) return this.buf.readUInt32LE(offset);
    if (size === 8) return Number(this.buf.readBigUInt64LE(offset));
    return 0;
  }

  _parseHeader() {
    const buf = this.buf;
    if (buf.length < 0x40) return;
    if (buf[0] !== 0x4D || buf[1] !== 0x5A) return; // 非 MZ

    const e_lfanew = buf.readUInt32LE(0x3C);
    if (e_lfanew + 24 > buf.length) return;
    if (buf.toString("latin1", e_lfanew, e_lfanew + 4) !== "PE\x00\x00") return;

    this.peOffset = e_lfanew;
    this.e_machine = buf.readUInt16LE(e_lfanew + 4);
    this.numSections = buf.readUInt16LE(e_lfanew + 6);
    this.sizeOfOptionalHeader = buf.readUInt16LE(e_lfanew + 20);

    const optOff = e_lfanew + 24;
    if (optOff + 2 > buf.length) return;
    const optMagic = buf.readUInt16LE(optOff);
    this.is64 = optMagic === 0x20B; // PE32+ (0x20B) / PE32 (0x10B)

    // NumberOfRvaAndSizes: PE32 @ optOff+92, PE32+ @ optOff+108
    const ddirCountOff = optOff + (this.is64 ? 108 : 92);
    if (ddirCountOff + 4 <= buf.length) {
      this.numDataDirs = buf.readUInt32LE(ddirCountOff);
    }
    // DataDirectory 起始: PE32 @ optOff+96, PE32+ @ optOff+112
    this.dataDirOff = optOff + (this.is64 ? 112 : 96);

    // AddressOfEntryPoint @ optOff+16（RVA），ImageBase @ optOff+24
    if (optOff + 28 <= buf.length) {
      this.entryPoint = buf.readUInt32LE(optOff + 16);
      this.imageBase = this.is64 ? Number(buf.readBigUInt64LE(optOff + 24)) : buf.readUInt32LE(optOff + 24);
    }

    // Section table 紧跟在 optional header 之后
    this.sectionTableOff = optOff + this.sizeOfOptionalHeader;
  }

  getArch() {
    const m = this.e_machine;
    if (m === IMAGE_FILE_MACHINE_AMD64) return "x86_64";
    if (m === IMAGE_FILE_MACHINE_I386)  return "x86";
    if (m === IMAGE_FILE_MACHINE_ARM64) return "arm64";
    if (m === IMAGE_FILE_MACHINE_ARM || m === IMAGE_FILE_MACHINE_ARMNT) return "arm32";
    return "unknown";
  }

  /** 与 ELF getSections() 对齐：sh_addr=RVA, sh_offset=PointerToRawData, sh_size=SizeOfRawData */
  getSections() {
    const sections = [];
    if (this.peOffset < 0 || this.sectionTableOff <= 0) return sections;

    const entSize = 40;
    for (let i = 0; i < this.numSections; i++) {
      const off = this.sectionTableOff + i * entSize;
      if (off + entSize > this.buf.length) break;

      const nameBytes = this.buf.slice(off, off + 8);
      const nameEnd = nameBytes.indexOf(0);
      const name = (nameEnd === -1 ? nameBytes : nameBytes.slice(0, nameEnd)).toString("utf8");

      sections.push({
        idx: i,
        sh_name: 0,                    // PE 无 sh_name 偏移语义
        sh_type: 0,
        sh_addr:  this._readUInt(off + 12, 4),  // VirtualAddress (RVA)
        sh_offset: this._readUInt(off + 20, 4), // PointerToRawData
        sh_size:  this._readUInt(off + 16, 4),  // SizeOfRawData
        characteristics: this._readUInt(off + 36, 4),
        name,
      });
    }
    return sections;
  }

  /** RVA → 文件偏移（通过 section 映射），找不到返回 -1 */
  rvaToOffset(rva) {
    for (const sec of this.getSections()) {
      const va = sec.sh_addr, raw = sec.sh_offset, size = sec.sh_size;
      if (rva >= va && rva < va + size) return raw + (rva - va);
    }
    return -1;
  }

  _readCString(offset) {
    if (offset < 0 || offset >= this.buf.length) return "";
    let end = offset;
    while (end < this.buf.length && this.buf[end] !== 0) end++;
    return this.buf.toString("utf8", offset, end);
  }

  /** 解析导入表，返回 [{dll, func}]（L3 符号层） */
  getImports() {
    const imports = [];
    if (this.peOffset < 0 || !this.dataDirOff) return imports;

    const dirCount = this.numDataDirs || 0;
    if (IMAGE_DIRECTORY_ENTRY_IMPORT >= dirCount) return imports;
    const importDirOff = this.dataDirOff + IMAGE_DIRECTORY_ENTRY_IMPORT * 8;
    const importRVA = this._readUInt(importDirOff, 4);
    const importSize = this._readUInt(importDirOff + 4, 4);
    if (!importRVA || !importSize) return imports;

    const dirFileOff = this.rvaToOffset(importRVA);
    if (dirFileOff < 0) return imports;

    // 遍历 IMAGE_IMPORT_DESCRIPTOR（20 字节/项），直到全 0
    const entSize = 20;
    for (let i = 0; ; i++) {
      const off = dirFileOff + i * entSize;
      if (off + entSize > this.buf.length) break;
      const originalFirstThunk = this._readUInt(off, 4);
      const nameRVA   = this._readUInt(off + 12, 4);
      const firstThunk = this._readUInt(off + 16, 4);
      if (!nameRVA && !originalFirstThunk && !firstThunk) break; // 结束标记

      const dllName = this._readCString(this.rvaToOffset(nameRVA));
      if (!dllName) continue;

      const thunkRVA = originalFirstThunk || firstThunk;
      const thunkFileOff = this.rvaToOffset(thunkRVA);
      if (thunkFileOff < 0) continue;

      const thunkSize = this.is64 ? 8 : 4;
      for (let t = 0; ; t++) {
        const toff = thunkFileOff + t * thunkSize;
        if (toff + thunkSize > this.buf.length) break;
        let thunk;
        let byName;
        let nameRVA2;
        if (this.is64) {
          const t64 = this.buf.readBigUInt64LE(toff);
          if (t64 === 0n) break;
          // 64位最高位为序数导入标志（0x8000000000000000）
          byName = (t64 & 0x8000000000000000n) === 0n;
          thunk = Number(t64 & 0x7FFFFFFFFFFFFFFFn);
        } else {
          const t32 = this._readUInt(toff, 4);
          if (t32 === 0) break;
          byName = (t32 & 0x80000000) === 0;
          thunk = t32 & 0x7FFFFFFF;
        }
        if (!byName) continue;
        nameRVA2 = thunk;
        const nameFileOff = this.rvaToOffset(nameRVA2);
        if (nameFileOff < 0) continue;
        const funcName = this._readCString(nameFileOff + 2); // 跳过 Hint(2)
        if (funcName) imports.push({ dll: dllName, func: funcName });
      }
    }
    return imports;
  }
}

/** 检测文件格式：'elf' / 'pe' / 'macho' / 'unknown' */
function detectFormat(buf) {
  if (!buf || buf.length < 4) return "unknown";
  const magic = buf.toString("latin1", 0, 4);
  if (magic === "\x7fELF") return "elf";
  if (buf[0] === 0x4D && buf[1] === 0x5A) {
    // 进一步校验 PE 签名，避免误判 DOS stub
    if (buf.length >= 0x40) {
      const e_lfanew = buf.readUInt32LE(0x3C);
      if (buf.toString("latin1", e_lfanew, e_lfanew + 4) === "PE\x00\x00") return "pe";
    }
  }
  if (magic === "\xfe\xed\xfa\xce" || magic === "\xfe\xed\xfa\xcf" ||
      magic === "\xce\xfa\xed\xfe" || magic === "\xcf\xfa\xed\xfe") return "macho";
  return "unknown";
}

module.exports = { PEParser, detectFormat };
