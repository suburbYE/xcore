#!/usr/bin/env node
/**
 * api_probe.js - Web API 签名与参数探测
 * Phase 5w: Web 分析模块 - 签名/参数定位
 *
 * Usage:
 *   node api_probe.js --js <path|url> [--json]
 *   node api_probe.js --dir <dir> [--json]
 *
 * 目标：
 *   1. 从 JS/HTML 中提取 API 端点（/api/* 等）
 *   2. 定位签名相关调用（sign/token/hmac/md5/sha256/base64 等关键词）
 *   3. 还原请求参数名与来源（表单字段、localStorage、cookie、常量表）
 *   4. 输出可继续下钻的线索（函数名、参数名、可疑常量）
 */

"use strict";

const fs = require("fs");
const path = require("path");

// ─── CLI 解析 ────────────────────────────────────────────────
function parseArgs(argv) {
  const args = { js: "", dir: "", json: false };
  for (let i = 0; i < argv.length; i++) {
    switch (argv[i]) {
      case "--js": case "--file": args.js = argv[++i] || ""; break;
      case "--dir": args.dir = argv[++i] || ""; break;
      case "--json": args.json = true; break;
    }
  }
  return args;
}

const SIGN_KW = [
  "sign", "signature", "token", "ts", "nonce", "sid", "session",
  "device_id", "client_time", "platform", "app_version", "uuid",
];
const CRYPTO_KW = [
  "hmac", "md5", "sha1", "sha256", "base64", "crypto", "encrypt",
  "aes", "rsa", "chacha", "sm4", "xxtea",
];
const HEADER_KW = [
  "x-gorgon", "x-argus", "x-ladon", "x-medusa", "x-khronos", "x-soter",
  "x-tyhon", "x-helio", "authorization", "cookie",
];

function collectFiles(dir, exts, acc = []) {
  for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, ent.name);
    if (ent.isDirectory()) collectFiles(p, exts, acc);
    else if (exts.has(path.extname(ent.name).toLowerCase())) acc.push(p);
  }
  return acc;
}

// 从 JS 文本中定位签名相关代码段
function probeText(src, fileLabel) {
  const hits = [];
  const lines = src.split("\n");
  lines.forEach((line, i) => {
    const low = line.toLowerCase();
    const found = [];
    for (const kw of SIGN_KW) {
      if (low.includes(kw)) { found.push(`sign:${kw}`); break; }
    }
    for (const kw of CRYPTO_KW) {
      if (low.includes(kw)) { found.push(`crypto:${kw}`); break; }
    }
    for (const kw of HEADER_KW) {
      if (low.includes(kw)) { found.push(`header:${kw}`); break; }
    }
    if (found.length) {
      hits.push({ file: fileLabel, line: i + 1, kinds: [...new Set(found)].slice(0, 6), code: line.trim().slice(0, 160) });
    }
  });
  return hits;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.js && !args.dir) {
    console.error("[!] Usage: node api_probe.js --js <path> | --dir <dir> [--json]");
    process.exit(1);
  }

  const report = { scannedAt: new Date().toISOString(), files: [], hits: [], endpoints: new Set() };
  const files = args.dir
    ? collectFiles(path.resolve(args.dir), new Set([".js", ".html", ".mjs", ".json"]))
    : [path.resolve(args.js)];

  for (const f of files) {
    let src;
    try { src = fs.readFileSync(f, "utf8"); } catch (e) { continue; }
    report.files.push(f);
    const hits = probeText(src, f);
    report.hits.push(...hits);
    // 端点提取
    const epRe = /["'`](\/(?:api|v\d+|ajax|gateway|rest|sdk|passport)[^"'`\s?]*)["'`]/g;
    let m;
    while ((m = epRe.exec(src)) !== null) report.endpoints.add(m[1]);
  }

  if (args.json) {
    const out = { ...report, endpoints: [...report.endpoints] };
    console.log(JSON.stringify(out, null, 2));
  } else {
    console.log(`[+] files: ${report.files.length}, hits: ${report.hits.length}, endpoints: ${report.endpoints.size}`);
    if (report.hits.length) {
      console.log("--- top hits ---");
      for (const h of report.hits.slice(0, 30)) {
        console.log(`  ${h.file}:${h.line} [${h.kinds.join(",")}] ${h.code}`);
      }
    }
    if (report.endpoints.size) {
      console.log("--- endpoints ---");
      for (const ep of [...report.endpoints].slice(0, 30)) console.log("  " + ep);
    }
  }
}

if (require.main === module) main();
module.exports = { probeText, collectFiles };
