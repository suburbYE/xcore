#!/usr/bin/env node
/**
 * constant_scanner.js — L2+L3+L4 联合扫描
 * Phase 4b: 常量池扫描 + 导入符号扫描 + 指纹库匹配
 *
 * Usage: node constant_scanner.js --so <path> --fingerprints-dir <dir> [--json]
 */

"use strict";

const fs = require("fs");
const path = require("path");
const { PEParser, detectFormat } = require("./pe_parser.js");

// ─── ELF 常量 ───────────────────────────────────────────────────────────────
const EI_CLASS      = 4;
const EI_DATA       = 5;
const EM_AARCH64    = 183;
const EM_ARM        = 40;
const EM_X86_64     = 62;
const SHT_DYNSYM    = 11;
const SHT_STRTAB    = 3;
const SHT_DYNAMIC   = 6;

// ─── 内置密码学常量库（十六进制字符串，无空格） ─────────────────────────────
const CRYPTO_CONSTANTS = {
  // AES S-Box (256 bytes, first 32 for quick scan)
  "aes_sbox":    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0",
  // AES Inv-S-Box (256 bytes, first 32)
  "aes_inv_sbox":"52096ad53036a538bf40a39e81f3d7fb7ce339829b2fff87348e4344c4dee9cb",
  // SM4 S-Box (256 bytes, first 64 for quick scan, GB/T 32907)
  "sm4_sbox":    "d690e9feccec138871621a0c350437c754208aac18b42a0abc83d06541b2764faee22c224b711c921fa5f12d86f3c3ca6da884931e46aa5bcf4a8e087788b4c1c1054106b51a41e547c9073c880c08c4e3660c2b43571b6f4bc98417cc7c4824bb7153e607da06440000d074d76c4b1e1ce7cd7b772e51c1a0e2e0e8e469f00c5",
  // SM4 FK constants (4 x uint32 LE)
  "sm4_fk_0":    "c6bab1a3",
  "sm4_fk_1":    "5033aa56",
  "sm4_fk_2":    "97917d67",
  "sm4_fk_3":    "dc2270b2",
  // SM4 CK constants (32 x uint32 LE, first 16)
  "sm4_ck":      "150e0700312a231c4d463f3869625b54858e97a0bdb6c5ccd9eaf2f8051c2b3a594867765146b540b710c988a7d6e510363838e0ca9ae8a2cbbad8b0705e36242c",
  // TEA delta (uint32 LE)
  "tea_delta":   "b979379e",
  // CRC32 polynomial (reflected, uint32 LE)
  "crc32_poly":  "2083b8ed",
  // MD5 T-table (first 4 of 64, uint32 LE)
  "md5_t_00":    "78a46ad7",
  "md5_t_01":    "56b7c8e7",
  "md5_t_02":    "70dbbd12",
  "md5_t_03":    "0e7cee24",
  // SHA1 K-constants (4 x uint32 BE)
  "sha1_k0":     "5a827999",
  "sha1_k1":     "6ed9eba1",
  "sha1_k2":     "8f1bbcdc",
  "sha1_k3":     "ca62c1d6",
  // SHA256 K-constants (first 8 of 64, uint32 BE)
  "sha256_k00":  "428a2f98",
  "sha256_k01":  "71374491",
  "sha256_k02":  "b5c0fbcf",
  "sha256_k03":  "e9b5dba5",
  "sha256_k04":  "3956c25b",
  "sha256_k05":  "59f111f1",
  "sha256_k06":  "923f82a4",
  "sha256_k07":  "ab1c5ed5",
  // WyHash mixer constant (little-endian)
  "wyhash_mixer":"692d38eb08eadf9d",
  // WyHash k constants
  "wyhash_k1_k5":"4f40902f3b6ae19a",
  "wyhash_k2_k4":"2731cb975cc8a5c3",
  "wyhash_k3":   "73f298be6fb692b4",
  "wyhash_k6":   "57659e50c7d749c9",
  // QUIC S-Box ASCII string
  "quic_sbox":   "515549435f53545245414d5f53455155454e4345525f494e56414c49445f5354415445",
  // ChaCha20 initial state constant ("expand 32-byte k")
  "chacha20_const": "657870616e642033322d62797465206b",
};

// ─── Boyer-Moore 搜索（字节级） ─────────────────────────────────────────────
function boyerMooreSearch(haystack, needle) {
  const results = [];
  const n = haystack.length;
  const m = needle.length;
  if (m === 0 || m > n) return results;

  // 坏字符表（简化版，仅用最后出现位置）
  const badChar = new Array(256).fill(m);
  for (let i = 0; i < m - 1; i++) {
    badChar[needle[i]] = m - 1 - i;
  }

  let i = 0;
  while (i <= n - m) {
    let j = m - 1;
    while (j >= 0 && haystack[i + j] === needle[j]) j--;
    if (j < 0) {
      results.push(i);
      i += (i + m < n) ? badChar[haystack[i + m]] || m : 1;
    } else {
      i += Math.max(1, badChar[haystack[i + j]] - (m - 1 - j));
    }
  }
  return results;
}

// 通配符搜索：pattern 由 tokens 描述，支持三类字节匹配：
//   - "??"        任意字节
//   - "[xx-yy]"   范围字节（十六进制小写），如 "[80-9f]"
//   - "xx"        精确字节
// 用于指令级常量链（如 AArch64 mov/movk 的寄存器位不固定），Boyer-Moore 无法直接支持，
// 这里用朴素滑动窗口，仅当 pattern 含通配/范围时启用。
function parseFpPattern(pattern) {
  const tokens = [];
  const re = /\[[0-9a-f]{2}-[0-9a-f]{2}\]|\?\?|[0-9a-f]{2}/gi;
  let m;
  while ((m = re.exec(pattern)) !== null) {
    const t = m[0].toLowerCase();
    if (t === "??") {
      tokens.push(null); // null = 任意字节
    } else if (t.startsWith("[")) {
      const [lo, hi] = t.slice(1, -1).split("-").map(x => parseInt(x, 16));
      tokens.push([lo, hi]); // [min, max] 范围
    } else {
      tokens.push(parseInt(t, 16));
    }
  }
  return tokens;
}

function matchToken(byteVal, token) {
  if (token === null) return true;
  if (Array.isArray(token)) return byteVal >= token[0] && byteVal <= token[1];
  return byteVal === token;
}

function wildcardSearch(haystack, tokens) {
  const results = [];
  const n = haystack.length;
  const m = tokens.length;
  if (m === 0 || m > n) return results;
  for (let i = 0; i <= n - m; i++) {
    let j = 0;
    while (j < m && matchToken(haystack[i + j], tokens[j])) j++;
    if (j === m) results.push(i);
  }
  return results;
}

// ─── L2 常量池扫描 ─────────────────────────────────────────────────────────
function scanConstants(buf, sections, maxScanSize) {
  const hits = [];
  // ELF: .rodata/.data；PE: .rdata/.data
  const rodataSec = sections.find(s => s.name === ".rodata") || sections.find(s => s.name === ".rdata");
  const dataSec   = sections.find(s => s.name === ".data");
  const searchSections = [rodataSec, dataSec].filter(Boolean);

  if (searchSections.length === 0) return { hits: [], score: 0 };

  const uniqueFamilies = new Set();

  for (const [name, hex] of Object.entries(CRYPTO_CONSTANTS)) {
    const needle = Buffer.from(hex, "hex");
    let found = false;

    for (const sec of searchSections) {
      if (!sec || sec.sh_size === 0) continue;
      // --max-scan-size 0 = 全量扫描（不截断）
      const scanSize = (maxScanSize > 0) ? Math.min(sec.sh_size, maxScanSize) : sec.sh_size;
      const secBuf = buf.slice(sec.sh_offset, sec.sh_offset + scanSize);

      const matches = boyerMooreSearch(secBuf, needle);
      if (matches.length > 0) {
        hits.push({
          constant: name,
          section: sec.name,
          count: matches.length,
          locations: matches.slice(0, 5).map(m => `0x${(sec.sh_offset + m).toString(16)}`)
        });
        found = true;

        // 归类到算法家族
        if (name.startsWith("aes_")) uniqueFamilies.add("aes");
        else if (name.startsWith("sm4_")) uniqueFamilies.add("sm4");
        else if (name.startsWith("sha1_")) uniqueFamilies.add("sha1");
        else if (name.startsWith("sha256_")) uniqueFamilies.add("sha256");
        else if (name.startsWith("md5_")) uniqueFamilies.add("md5");
        else if (name.startsWith("wyhash")) uniqueFamilies.add("wyhash");
        else if (name.startsWith("tea_")) uniqueFamilies.add("tea");
        else if (name.startsWith("crc")) uniqueFamilies.add("crc32");
        else if (name.startsWith("quic")) uniqueFamilies.add("quic");
        else if (name.startsWith("chacha")) uniqueFamilies.add("chacha20");
        break;
      }
    }
  }

  // 得分：命中 2+ 不同家族 → 0.15
  const score = uniqueFamilies.size >= 2 ? 0.15 : (uniqueFamilies.size === 1 ? 0.08 : 0);
  return { hits, score, families: [...uniqueFamilies] };
}

// ─── L3 导入符号扫描 ────────────────────────────────────────────────────────
function scanImports(buf, sections, parser) {
  // PE 分支：走导入表（getImports），L3 语义等价
  if (parser instanceof PEParser) {
    const hits = [];
    const imports = parser.getImports();
    const CRYPTO_IMPORT_PATTERNS = [
      "HMAC_", "AES_", "SHA", "EVP_", "MD5_", "RSA_", "ECDSA_",
      "CRYPTO_", "OPENSSL_", "BoringSSL", "RAND_", "PKCS"
    ];
    for (const imp of imports) {
      const name = `${imp.dll}!${imp.func}`;
      for (const pat of CRYPTO_IMPORT_PATTERNS) {
        if (imp.func.includes(pat) || imp.dll.includes(pat)) {
          hits.push({ symbol: name, value: `0x0` });
          break;
        }
      }
    }
    const score = Math.min(0.10, hits.length * 0.02);
    return { hits, score, source: "pe_imports" };
  }

  const hits = [];
  const symSec = sections.find(s => s.sh_type === SHT_DYNSYM);
  if (!symSec) return { hits: [], score: 0 };

  const strSec = sections.find(s => s.name === ".dynstr");
  if (!strSec) return { hits: [], score: 0 };

  const symEntSize = parser.is64 ? 24 : 16;
  const numSyms = Math.floor(symSec.sh_size / symEntSize);

  const CRYPTO_IMPORT_PATTERNS = [
    "HMAC_", "AES_", "SHA", "EVP_", "MD5_", "RSA_", "ECDSA_",
    "CRYPTO_", "OPENSSL_", "BoringSSL", "RAND_", "PKCS"
  ];

  for (let i = 0; i < numSyms; i++) {
    const symOff = symSec.sh_offset + i * symEntSize;
    const st_name  = parser._readUInt(symOff, 4);
    const st_value = parser._readUInt(symOff + (parser.is64 ? 8 : 4), parser.is64 ? 8 : 4);

    if (st_name === 0) continue;
    const name = parser._readCString(strSec.sh_offset + st_name);
    if (!name) continue;

    // 匹配密码学相关导入
    for (const pat of CRYPTO_IMPORT_PATTERNS) {
      if (name.includes(pat)) {
        hits.push({ symbol: name, value: `0x${st_value.toString(16)}` });
        break;
      }
    }
  }

  // L3 得分：sigmod(hit_count / 5)
  const score = Math.min(0.10, hits.length * 0.02);
  return { hits, score };
}

// ─── L4 指纹库匹配 ──────────────────────────────────────────────────────────
// L1 规则引擎有 noise-gate 会跳过 <5 字节的 hex 模式；指纹层原先没有同等闸门，
// 于是 4 字节的 crc32_poly（20 83 b8 ed）在多 MB 文件里靠巧合就能命中。
const MIN_FP_PATTERN_BYTES = 5;

function scanFingerprints(buf, fingerprintsDir) {
  const hits = [];
  let totalScore = 0;

  if (!fs.existsSync(fingerprintsDir)) {
    return { hits: [], score: 0, error: `Fingerprints dir not found: ${fingerprintsDir}` };
  }

  const files = fs.readdirSync(fingerprintsDir).filter(f => f.endsWith(".json") && f !== "manifest.json");

  for (const file of files) {
    const fpPath = path.join(fingerprintsDir, file);
    let fp;
    try {
      fp = JSON.parse(fs.readFileSync(fpPath, "utf8"));
    } catch (e) {
      continue;
    }

    if (!fp.patterns || !Array.isArray(fp.patterns)) continue;

    // 弱指纹降权：weak=true 的指纹（如递增 IV 表等数据表类弱特征）在大型二进制
    // （Unity IL2CPP 等）中极易被数据区碰巧命中。
    //
    // max_hits 限制的是「同一个 pattern 出现多少次」，但实测证明这个方向是错的：
    // libhash_x_iv 在 kernel_drv_x.sys（某厂商内核驱动）里命中，匹配的是一张 256 字节
    // 恒等表（00 01 02…0F + 30 31…3F，相距 0x30）—— 任何做数字格式化的程序都有这张表，
    // 且它天然只出现 1-2 次，永远过不了 max_hits 这道闸。
    //
    // 真正该看的是「这个 pattern 本身有多通用」：恒等表、连续字节序列这类结构在任何
    // 二进制里都可能存在，靠出现次数抑制不住。所以对弱指纹再加一道「通用性」判据。
    const isWeak = fp.weak === true;
    const maxHits = (typeof fp.max_hits === "number") ? fp.max_hits : 3;

    // 通用模式检测：连续的 0..N 递增序列、纯 ASCII 数字串、纯 0x00/0xFF 填充。
    // 这些结构出现即视为巧合，不参与弱指纹判定。
    const isGenericPattern = (patStr) => {
      const bytes = patStr.replace(/\s+/g, "").match(/../g);
      if (!bytes || bytes.length < 4) {
        // 短于 4 字节的模式在 MB 级文件里没有区分度
        return true;
      }
      const vals = bytes.map(b => parseInt(b, 16)).filter(v => !Number.isNaN(v));
      if (vals.length !== bytes.length) return false;  // 含通配符，交给原有逻辑
      // 连续递增序列（步长 1）：00 01 02 … / 30 31 32 …
      let asc = true;
      for (let i = 1; i < vals.length; i++) {
        if (vals[i] !== (vals[i - 1] + 1) & 0xff) { asc = false; break; }
      }
      if (asc && vals.length >= 4) return true;
      // 全是可打印 ASCII（数字/字母表片段）
      if (vals.every(v => v >= 0x20 && v < 0x7f)) return true;
      // 全 0 或全 FF 填充
      if (vals.every(v => v === 0x00) || vals.every(v => v === 0xff)) return true;
      return false;
    };

    const matchedPatterns = [];
    const weakDiscarded = [];
    const genericDiscarded = [];
    for (const patStr of fp.patterns) {
      // 指纹层原先没有 rules.json 那道 noise-gate（跳过 <5 字节的模式），
      // 于是 4 字节的 crc32_poly 在多 MB 文件里靠巧合就命中。这里补上同等判据。
      const bareHex = patStr.replace(/\s+/g, "").replace(/\?\?/g, "ff");
      if (bareHex.length / 2 < MIN_FP_PATTERN_BYTES) {
        genericDiscarded.push({ pattern: patStr, count: 0 });
        continue;
      }
      if (isGenericPattern(patStr)) {
        genericDiscarded.push({ pattern: patStr, count: 0 });
        continue;
      }
      // 去除空格；支持 "??"（任意字节）与 "[xx-yy]"（范围）通配符，用于指令级常量链
      const hex = patStr.replace(/\s+/g, "").replace(/\?\?/g, "ff").replace(/\[[0-9a-f]{2}-[0-9a-f]{2}\]/g, "ff");
      const needle = Buffer.from(hex, "hex");
      const hasWildcard = patStr.includes("??") || /\[[0-9a-f]{2}-[0-9a-f]{2}\]/.test(patStr);
      const matches = hasWildcard
        ? wildcardSearch(buf, parseFpPattern(patStr.replace(/\s+/g, "")))
        : boyerMooreSearch(buf, needle);
      if (matches.length > 0) {
        const item = {
          pattern: patStr,
          count: matches.length,
          locations: matches.slice(0, 3).map(m => `0x${m.toString(16)}`)
        };
        if (isWeak && matches.length > maxHits) {
          weakDiscarded.push(item);
        } else {
          matchedPatterns.push(item);
        }
      }
    }

    const dec = fp.decision || "OR";
    const minHits = fp.min_hits || 1;
    let triggered = false;

    if (dec === "OR") {
      triggered = matchedPatterns.length >= minHits;
    } else if (dec === "AND") {
      // 弱指纹的 AND 仅要求有效（未剔除）pattern 数达到 min_hits；
      // 普通指纹保持原语义：全部 pattern 命中。
      triggered = isWeak
        ? matchedPatterns.length >= minHits
        : matchedPatterns.length >= fp.patterns.length && matchedPatterns.length >= minHits;
    }

    if (triggered) {
      const hitEntry = {
        fingerprint: fp.name,
        algorithm: fp.algorithm,
        source: fp.source || "unknown",
        matched_patterns: matchedPatterns
      };
      if (weakDiscarded.length > 0) {
        hitEntry.weak_discarded = weakDiscarded.map(d => `${d.pattern}(${d.count})`);
      }
      if (genericDiscarded.length > 0) {
        // 显式暴露被通用性判据剔除的模式，便于回看是否误伤
        hitEntry.generic_discarded = genericDiscarded.map(d => d.pattern);
      }
      hits.push(hitEntry);
      totalScore += 0.25; // L4 每个命中指纹 +0.25，上限由外部 cap
    }
  }

  // L4 总得分上限 0.25
  const score = Math.min(0.25, totalScore);
  return { hits, score };
}

// ─── ELF 解析器（最小实现） ─────────────────────────────────────────────────
class MiniELFParser {
  constructor(buf) {
    this.buf = buf;
    this.is64 = buf[EI_CLASS] === 2;
    this.isLE = buf[EI_DATA] === 1;
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
        idx: i,
        sh_name:   this._readUInt(off, 4),
        sh_type:   this._readUInt(off + 4, 4),
        sh_addr:   this._readUInt(off + (this.is64 ? 16 : 12), this.is64 ? 8 : 4),
        sh_offset: this._readUInt(off + (this.is64 ? 24 : 16), this.is64 ? 8 : 4),
        sh_size:   this._readUInt(off + (this.is64 ? 32 : 20), this.is64 ? 8 : 4),
      });
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
}

// ─── 命令行 ─────────────────────────────────────────────────────────────────
function parseArgs() {
  const args = process.argv.slice(2);
  const opts = { so: null, fingerprintsDir: null, json: false, maxScanSize: 0 };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--so" && i + 1 < args.length) opts.so = args[++i];
    else if (args[i] === "--fingerprints-dir" && i + 1 < args.length) opts.fingerprintsDir = args[++i];
    else if (args[i] === "--json") opts.json = true;
    else if (args[i] === "--max-scan-size" && i + 1 < args.length) opts.maxScanSize = parseInt(args[++i], 10) || 0;
  }
  if (!opts.so) {
    console.error("Usage: node constant_scanner.js --so <path> --fingerprints-dir <dir> [--json]");
    process.exit(1);
  }
  return opts;
}

// ─── 文件头解析（ELF / PE / Mach-O）────────────────────────────────────────
// 返回架构字符串，未知格式返回 "unknown"
function detectArch(buf) {
  if (!buf || buf.length < 2) return "unknown";
  const magic = buf.toString("latin1", 0, 4);

  // ELF: \x7fELF
  if (magic === "\x7fELF") {
    const eiData = buf[5];
    const isLE = eiData === 1;
    const eMachine = isLE ? buf.readUInt16LE(18) : buf.readUInt16BE(18);
    if (eMachine === EM_AARCH64) return "arm64";
    if (eMachine === EM_ARM)     return "arm32";
    if (eMachine === EM_X86_64)  return "x86_64";
    return "unknown";
  }

  // PE: MZ 魔数 + e_lfanew 偏移处 PE\0\0 + IMAGE_FILE_HEADER.Machine
  if (buf[0] === 0x4D && buf[1] === 0x5A) { // 'M''Z'
    if (buf.length < 0x40) return "unknown";
    const e_lfanew = buf.readUInt32LE(0x3C);
    if (buf.toString("latin1", e_lfanew, e_lfanew + 4) !== "PE\x00\x00") return "unknown";
    const machine = buf.readUInt16LE(e_lfanew + 4);
    if (machine === 0x8664) return "x86_64";      // IMAGE_FILE_MACHINE_AMD64
    if (machine === 0x014C) return "x86";          // IMAGE_FILE_MACHINE_I386
    if (machine === 0xAA64) return "arm64";        // IMAGE_FILE_MACHINE_ARM64
    if (machine === 0x01C0 || machine === 0x01C4) return "arm32"; // ARM / ARMNT
    return "unknown";
  }

  // Mach-O: 0xfeedface / 0xfeedfacf / 0xcefaedfe / 0xcffaedfe
  if (magic === "\xfe\xed\xfa\xce" || magic === "\xfe\xed\xfa\xcf" ||
      magic === "\xce\xfa\xed\xfe" || magic === "\xcf\xfa\xed\xfe") {
    return "macho";
  }

  return "unknown";
}

function main() {
  const opts = parseArgs();
  const buf = fs.readFileSync(opts.so);

  // 按文件格式选择解析器：ELF → MiniELFParser，PE → PEParser，其他 → 无 section
  const fmt = detectFormat(buf);
  const isELF = fmt === "elf";
  const arch = detectArch(buf);
  let sections = [];
  let parser = null;
  if (isELF) {
    parser = new MiniELFParser(buf);
    sections = parser.getSections();
  } else if (fmt === "pe") {
    parser = new PEParser(buf);
    sections = parser.getSections();
  }

  if (!opts.json) {
    console.error(`[constant_scanner] Target: ${opts.so}`);
    console.error(`[constant_scanner] Arch: ${arch} (format: ${fmt})`);
  }

  // L2: 常量池
  const l2 = scanConstants(buf, sections, opts.maxScanSize);
  // L3: 导入符号（ELF dynsym / PE import table）
  const l3 = parser ? scanImports(buf, sections, parser) : { hits: [], score: 0 };
  // L4: 指纹库
  const l4 = scanFingerprints(buf, opts.fingerprintsDir || path.join(__dirname, "..", "..", "rules", "fingerprints", "algorithms"));

  const result = {
    target: path.basename(opts.so),
    arch,
    L2_constants: l2,
    L3_symbols: l3,
    L4_fingerprints: l4
  };

  process.stdout.write(JSON.stringify(result, null, opts.json ? 0 : 2));
  if (!opts.json) process.stdout.write("\n");
}

main();
