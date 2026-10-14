#!/usr/bin/env node
/**
 * section_probe.js — PE 异常节字节级探测
 *
 * 背景（踩坑固化）：鸣潮/库洛客户端初扫见 .tvm0/.-v:/.iCZ/.std 等非标准节名，
 * 曾凭节名直接判为"腾讯自研 VM 加固"；字节级核对后发现：
 *   - .tvm0 节头 !mdb=/!seed= 是 LLVM bitcode 模块元数据签名（含 private_dbg 编译路径），
 *     并非 VMP/TenProtect 壳，也非 OpenSSL；
 *   - OpenSSL 误报源是该 DLL 静态链入的 OpenSSL 3.1.4（.rdata 大量 EVP_/rsa routines）。
 * 因此：异常节名 ≠ VM 加固，必须做节内字节核对。
 *
 * 用法：
 *   node section_probe.js --file <pe_path> [--json]
 *   或 require 后调用 analyzeSections(fd, headerBuf, { wantSectionNames, maxMB })
 *
 * 输出：每节 name / rva / raw / size / chars / printable / entropy / needles / verdict
 */
"use strict";

const fs = require("fs");
const { PEParser } = require("./pe_parser.js");

// ─── 特征集 ────────────────────────────────────────────────────────────
const LLVM_NEEDLES = [
  "!mdb=", "!seed=", "private_dbg", "llvm", "llvmbc", "bitcode",
  "BC\xc0\xde",           // LLVM bitcode 魔数
  "\x0b\x17\xc0\xde",     // bitcode wrapper 魔数
];
const OPENSSL_NEEDLES = ["EVP_", "OPENSSL_", "CRYPTO_", "rsa routines", "bignum routines", "libcrypto", "OpenSSL"];
const VM_NEEDLES = ["VMP", "VMProtect", "Tencent", "virtualprotect", "vm_entry", "vmp0", "Themida", "themida", "pushad", "popad"];
const ACE_NEEDLES = ["anti", "ACE", "protect", "obfuscat", "detour", "hook"];

// 非标准节名（触发字节级核对；标准节名也可手动指定）
const ABNORMAL_NAMES = new Set([".tvm0", ".tvm", ".std", ".-v:", ".iCZ", ".detourc", ".detourd", ".ddata", ".tvmc"]);

function printableRatio(buf, sample = 65536) {
  const n = Math.min(buf.length, sample);
  let p = 0;
  for (let i = 0; i < n; i++) {
    const c = buf[i];
    if ((c >= 0x20 && c <= 0x7e) || c === 0x09 || c === 0x0a || c === 0x0d || c === 0) p++;
  }
  return n ? +(p / n).toFixed(3) : 0;
}

function entropy(buf, sample = 1048576) {
  const n = Math.min(buf.length, sample);
  if (!n) return 0;
  const freq = new Array(256).fill(0);
  for (let i = 0; i < n; i++) freq[buf[i]]++;
  let H = 0;
  for (let i = 0; i < 256; i++) {
    if (freq[i]) { const p = freq[i] / n; H -= p * Math.log2(p); }
  }
  return +H.toFixed(3);
}

function countNeedles(buf, needles) {
  const hits = {};
  const latin = buf.toString("latin1");
  for (const n of needles) {
    let idx = 0, cnt = 0;
    while ((idx = latin.indexOf(n, idx)) !== -1) { cnt++; idx += n.length; }
    if (cnt) hits[n] = cnt;
  }
  return hits;
}

/**
 * 分析单个文件的所有节（或仅 wantSectionNames 指定的节）。
 * @param {string} fp 文件绝对路径
 * @param {object} opts { wantSectionNames: string[], maxMBPerSec: number, headMB: number }
 */
function analyzeFile(fp, opts = {}) {
  const want = opts.wantSectionNames || null; // null = 全部节
  const maxMB = opts.maxMBPerSec || 4;
  const headMB = opts.headMB || 8;
  const fd = fs.openSync(fp, "r");
  try {
    const head = Buffer.alloc(headMB * 1048576);
    const readHead = fs.readSync(fd, head, 0, head.length, 0);
    const p = new PEParser(head.subarray(0, readHead));
    const results = {
      file: fp,
      size: fs.statSync(fp).size,
      arch: p.getArch(),
      is64: p.is64,
      entryPoint: p.entryPoint,
      imageBase: p.imageBase,
      sections: [],
    };
    for (const s of p.getSections()) {
      if (want && !want.includes(s.name)) continue;
      const size = Math.min(s.sh_size, maxMB * 1048576);
      if (size <= 0) continue;
      const buf = Buffer.alloc(size);
      fs.readSync(fd, buf, 0, size, s.sh_offset);
      const needles = {
        llvm: countNeedles(buf, LLVM_NEEDLES),
        openssl: countNeedles(buf, OPENSSL_NEEDLES),
        vm: countNeedles(buf, VM_NEEDLES),
        ace: countNeedles(buf, ACE_NEEDLES),
      };
      const abnormal = ABNORMAL_NAMES.has(s.name);
      results.sections.push({
        name: s.name,
        abnormal,
        rva: s.sh_addr,
        raw: s.sh_offset,
        size: s.sh_size,
        chars: s.characteristics,
        printable: printableRatio(buf),
        entropy: entropy(buf),
        needles,
        verdict: judgeVerdict(s, needles, abnormal),
      });
    }
    return results;
  } finally {
    fs.closeSync(fd);
  }
}

/** 判定：normal_text / data / llvm_bitcode / openssl_static / vm_shell / suspicious */
function judgeVerdict(sec, needles, abnormal) {
  const llvm = Object.keys(needles.llvm).length > 0;
  const ossl = Object.keys(needles.openssl).length > 0;
  const vm = Object.keys(needles.vm).length > 0;
  const isExec = (sec.characteristics & 0x20000000) !== 0; // IMAGE_SCN_MEM_EXECUTE

  // LLVM bitcode 元数据签名是最强证据：!mdb=/!seed=/private_dbg 出现即判定
  if (needles.llvm["!mdb="] || needles.llvm["!seed="] || needles.llvm["private_dbg"] || needles.llvm["BC\xc0\xde"] || needles.llvm["\x0b\x17\xc0\xde"]) {
    return "llvm_bitcode";
  }
  if (abnormal && ossl && !vm && sec.printable > 0.6) return "openssl_static";
  if (abnormal && vm && !ossl && !isExec && sec.printable < 0.5) return "suspicious_data"; // 孤立串命中，非壳
  if (abnormal && isExec && sec.printable < 0.5 && sec.entropy > 6.5 && !ossl && !llvm && !vm) return "high_entropy_code"; // 加密/压缩可执行段
  if (abnormal && vm && isExec) return "vm_shell_candidate"; // 仍需人工确认
  if (abnormal) return "abnormal_check";
  return "normal";
}

function main() {
  const args = process.argv.slice(2);
  const fp = args[args.indexOf("--file") + 1];
  const asJson = args.includes("--json");
  if (!fp) {
    console.error("用法: node section_probe.js --file <pe_path> [--json]");
    process.exit(1);
  }
  const res = analyzeFile(fp);
  if (asJson) { console.log(JSON.stringify(res, null, 2)); return; }
  console.log(`== ${res.file} (${res.size} bytes, ${res.arch}, EP=0x${(res.entryPoint || 0).toString(16)}) ==`);
  for (const s of res.sections) {
    console.log(
      `${s.name.padEnd(10)} [${s.verdict.padEnd(18)}] raw=0x${s.raw.toString(16).padStart(8, "0")} size=${s.size} ` +
      `print=${s.printable} ent=${s.entropy}` +
      (s.abnormal ? "  <-- 非标准节名" : "")
    );
    for (const [k, v] of Object.entries(s.needles)) {
      if (Object.keys(v).length) console.log(`     ${k}: ${JSON.stringify(v)}`);
    }
  }
}

if (require.main === module) main();
module.exports = { analyzeFile, judgeVerdict, printableRatio, entropy, LLVM_NEEDLES, ABNORMAL_NAMES };
