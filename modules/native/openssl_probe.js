#!/usr/bin/env node
/**
 * openssl_probe.js — OpenSSL libcrypto 静态链接探测
 * Phase 4b 辅助模块
 *
 * 用途：识别目标 so/dll 是否静态链入 OpenSSL libcrypto（含 BoringSSL 变体区分）。
 * 背景：zmd(sample_e.dll) / ark(sample_f.dll) 因静态链入 OpenSSL 3.1.4
 *       libcrypto，被 xcore 误判为天美 VMP/TPShell64 壳同源 / 自研安全 SDK。
 *       本模块负责把这些特征归因到 OpenSSL，供 target_scanner 降权。
 *
 * 特征分级：
 *   [HIGH]  版本串 "OpenSSL x.y.z"（opensslv.h 编译进 .rodata，几乎必带）
 *   [HIGH]  ERR 库名字符串（"xxx routines" 错误表，libcrypto 静态链接成百上千条）
 *   [MED]   OpenSSL 特有 API/配置字符串（EVP_*、OPENSSL_cleanse、openssl.cnf 等）
 *   [MED]   符号表残留（EVP_/OPENSSL_/CRYPTO_/BN_/RSA_/X509_ 等，未 strip 时）
 *
 * Usage: node openssl_probe.js --so <path> [--json]
 */

"use strict";

const fs = require("fs");
const path = require("path");

// ─── 特征定义 ───────────────────────────────────────────────────────────────
// 版本串：opensslv.h 的 OPENSSL_VERSION_TEXT，格式 "OpenSSL 3.1.4 24 Oct 2023"
const VERSION_RE = /OpenSSL\s+(\d+\.\d+\.\d+[a-z]?)/g;

// ERR 错误字符串表（.rodata 静态字符串，libcrypto 必带，格式 "error:...:xxx routines:..."）
const ERR_ROUTINES_RE = /[a-z0-9_]+ routines/g;

// OpenSSL 特有 API / 配置字符串（强特征，命中 3+ 即 MED 级证据）
const OPENSSL_API_STRINGS = [
  "EVP_DigestInit_ex",
  "EVP_DigestUpdate",
  "EVP_DigestFinal_ex",
  "EVP_EncryptInit_ex",
  "EVP_DecryptInit_ex",
  "EVP_CipherInit_ex",
  "EVP_CIPHER_CTX",
  "EVP_MD_CTX",
  "EVP_PKEY_CTX",
  "OPENSSL_cleanse",
  "OPENSSL_init_crypto",
  "OPENSSL_init_ssl",
  "CRYPTO_malloc",
  "CRYPTO_clear_realloc",
  "CRYPTO_free",
  "openssl.cnf",
  "digital envelope routines",
  "crypto/bn",
  "crypto/evp",
  "crypto/rsa",
  "crypto/aes",
  "crypto/sm4",
  "crypto/modes",
  "crypto/md5",
  "crypto/sha"
];

// 符号前缀（dynsym/.strtab/PE export 未 strip 时出现）
const OPENSSL_SYM_PREFIXES = [
  "EVP_", "OPENSSL_", "CRYPTO_", "BN_", "RSA_", "EC_", "BIO_",
  "PEM_", "X509_", "RAND_", "PKCS", "HMAC_", "SHA256_", "SHA1_",
  "MD5_", "AES_", "BUF_", "ASN1_", "OBJ_", "ENGINE_", "CONF_",
  "EVP_", "OSSL_", "DSA_", "DH_", "RC4_", "DES_", "BF_", "CAST_"
];

// ─── 字符串提取（不依赖 section 解析，兼容 ELF/PE/Mach-O） ──────────────────
// 返回所有可打印 ASCII 字符串（长度 >= 4）
function extractStrings(buf, minLen) {
  const strings = [];
  const n = buf.length;
  const min = minLen || 4;
  let i = 0;
  while (i < n) {
    // 找可打印段起点
    while (i < n && !(buf[i] >= 0x20 && buf[i] <= 0x7E)) i++;
    const start = i;
    while (i < n && (buf[i] >= 0x20 && buf[i] <= 0x7E)) i++;
    if (i - start >= min) {
      strings.push(buf.toString("latin1", start, i));
    }
  }
  return strings;
}

// ─── 符号名提取（从字符串里挑形似符号的 token） ──────────────────────────────
function countSymbolPrefixHits(strings) {
  const counts = {};
  for (const s of strings) {
    for (const p of OPENSSL_SYM_PREFIXES) {
      if (s.startsWith(p)) {
        counts[p] = (counts[p] || 0) + 1;
        break;
      }
    }
  }
  return counts;
}

// ─── 主探测 ─────────────────────────────────────────────────────────────────
function probe(buf) {
  const evidence = [];
  const result = {
    detected: false,
    version: null,
    strength: null,
    evidence: []
  };

  const strings = extractStrings(buf, 4);

  // 1) 版本串（HIGH）
  let versionMatch = null;
  for (const s of strings) {
    const m = VERSION_RE.exec(s);
    if (m) { versionMatch = m[1]; break; }
  }
  if (versionMatch) {
    result.detected = true;
    result.version = versionMatch;
    result.strength = "high";
    evidence.push({ type: "version_string", detail: "OpenSSL " + versionMatch, count: 1 });
  }

  // 2) ERR routines 计数（HIGH）
  let errRoutines = 0;
  let errSample = [];
  for (const s of strings) {
    // 只统计 "xxx routines" 形态的错误表条目，跳过 "digital envelope routines" 重复计数
    const ms = s.match(ERR_ROUTINES_RE);
    if (ms) {
      for (const m of ms) {
        if (!m.includes("routines routines")) {
          errRoutines++;
          if (errSample.length < 3 && !errSample.includes(m)) errSample.push(m);
        }
      }
    }
  }
  if (errRoutines >= 20) {
    if (!result.detected) {
      result.detected = true;
      result.strength = result.strength || "medium";
    } else if (result.strength === "high") {
      // 版本串 + 错误表 → 维持 high，补强证据
    }
    evidence.push({ type: "err_routines", detail: "OpenSSL ERR table (" + errSample.join(", ") + ")", count: errRoutines });
  } else if (errRoutines > 0) {
    evidence.push({ type: "err_routines", detail: "few ERR routines", count: errRoutines });
  }

  // 3) 特有 API/配置字符串（MED）
  let apiHits = [];
  for (const s of strings) {
    for (const api of OPENSSL_API_STRINGS) {
      if (s.includes(api)) {
        apiHits.push(api);
        break;
      }
    }
  }
  const apiUnique = [...new Set(apiHits)];
  if (apiUnique.length >= 3) {
    if (!result.detected) {
      result.detected = true;
      result.strength = result.strength || "medium";
    }
    evidence.push({ type: "api_strings", detail: apiUnique.slice(0, 8).join(", "), count: apiUnique.length });
  } else if (apiUnique.length > 0) {
    evidence.push({ type: "api_strings", detail: apiUnique.join(", "), count: apiUnique.length });
  }

  // 4) 符号前缀（MED）
  const symCounts = countSymbolPrefixHits(strings);
  let symTotal = 0;
  for (const k of Object.keys(symCounts)) symTotal += symCounts[k];
  const evpHits = symCounts["EVP_"] || 0;
  const osslHits = (symCounts["OPENSSL_"] || 0) + (symCounts["OSSL_"] || 0);
  if (symTotal >= 50 && (evpHits >= 5 || osslHits >= 5)) {
    if (!result.detected) {
      result.detected = true;
      result.strength = result.strength || "medium";
    }
    evidence.push({
      type: "symbol_prefixes",
      detail: "EVP_=" + evpHits + " OPENSSL_=" + osslHits + " total=" + symTotal,
      count: symTotal
    });
  } else if (symTotal > 0) {
    evidence.push({ type: "symbol_prefixes", detail: "EVP_=" + evpHits + " total=" + symTotal, count: symTotal });
  }

  result.evidence = evidence;
  return result;
}

// ─── CLI ────────────────────────────────────────────────────────────────────
function parseArgs() {
  const args = process.argv.slice(2);
  const opts = { so: null, json: false };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--so" && i + 1 < args.length) opts.so = args[++i];
    else if (args[i] === "--json") opts.json = true;
  }
  if (!opts.so) {
    console.error("Usage: node openssl_probe.js --so <path> [--json]");
    process.exit(1);
  }
  return opts;
}

function main() {
  const opts = parseArgs();
  const buf = fs.readFileSync(opts.so);
  const result = probe(buf);

  if (!opts.json) {
    console.error("[openssl_probe] Target: " + opts.so);
    console.error("[openssl_probe] Detected: " + result.detected + (result.version ? " (OpenSSL " + result.version + ")" : "") + " strength=" + result.strength);
  }
  process.stdout.write(JSON.stringify(result, null, opts.json ? 0 : 2));
  if (!opts.json) process.stdout.write("\n");
}

if (require.main === module) {
  main();
}

module.exports = { probe, extractStrings };
