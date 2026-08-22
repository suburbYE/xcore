#!/usr/bin/env node
/**
 * target_scanner.js — L1-L5 多维度扫描编排
 * Phase 4b: Native 靶心特征定位引擎主入口
 *
 * Usage: node target_scanner.js --so <path> [--fingerprints-dir <dir>] [--json]
 *
 * 流程：L1 字符串 → L2 常量 → L3 符号 → L4 指纹 → L5 CFG
 *       对 L1 命中的字符串做 L1.5 交叉引用追踪
 *       按置信度融合公式计算最终得分
 */

"use strict";

const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");

// ─── 工具路径 ───────────────────────────────────────────────────────────────
const SCRIPT_DIR = __dirname;

// ─── L1 字符串扫描（内联实现，减少进程开销） ───────────────────────────────
const L1_KEY_STRINGS = [
  "h5st", "sign", "token", "X-Gorgon", "X-Argus", "X-Ladon",
  "X-Medusa", "X-Khronos", "X-Tyhon", "X-Helios", "X-Soter",
  "HMAC", "MD5_Update", "SHA256_Update", "AES_encrypt",
  "base64_encode", "url_encode", "xxtea", "getSignature",
  "signParams", "calcMd5", "genSign", "encrypt_data"
];

function scanL1Strings(filePath) {
  const buf = fs.readFileSync(filePath);
  const MAX_SCAN = 20 * 1024 * 1024;
  const scanSize = Math.min(buf.length, MAX_SCAN);
  const scanBuf = buf.slice(0, scanSize);

  const hits = [];
  for (const s of L1_KEY_STRINGS) {
    const needle = Buffer.from(s, "utf8");
    let pos = 0;
    while (pos <= scanBuf.length - needle.length) {
      const idx = scanBuf.indexOf(needle, pos);
      if (idx === -1) break;
      hits.push({ string: s, offset: idx });
      pos = idx + 1;
    }
  }
  return hits;
}

// ─── 反伪阳性规则：L1 命中但没有位运算密集区 → L1 权重归零 ─────────────────
function validateL1WithL5(l1Hits, l5Patterns) {
  if (l1Hits.length === 0) return { valid: true, score: 0 };

  // 如果 L5 有 ror_chain / wyhash_madd / md5_round / aes_mixcols 中任意一个 → L1 有效
  const cryptPatterns = ["ror_chain_x3", "wyhash_madd_pattern", "md5_round_pattern", "aes_mixcols_pattern", "xor_mask_chain"];
  const hasCryptoPattern = l5Patterns.some(p => cryptPatterns.includes(p.name));

  if (!hasCryptoPattern && l1Hits.length > 0) {
    // L1 有 sign/token 等命中，但函数内无位运算 → 标记为 false positive
    const suspiciousStrings = l1Hits.filter(h =>
      ["h5st", "sign", "token"].some(s => h.string.includes(s))
    );
    if (suspiciousStrings.length === l1Hits.length) {
      return { valid: false, score: 0, reason: "L1 strings found but no bitwise operations detected in L5" };
    }
  }

  return { valid: true, score: Math.min(0.08, l1Hits.length * 0.01) };
}

// ─── 调用子模块 ─────────────────────────────────────────────────────────────
function runConstantScanner(soPath, fingerprintsDir) {
  const args = ["--so", soPath, "--fingerprints-dir", fingerprintsDir, "--json"];
  try {
    const out = execFileSync("node", [path.join(SCRIPT_DIR, "constant_scanner.js"), ...args], {
      encoding: "utf8",
      timeout: 120000,
      maxBuffer: 10 * 1024 * 1024
    });
    return JSON.parse(out.trim());
  } catch (e) {
    return { L2_constants: { hits: [], score: 0, error: e.message }, L3_symbols: { hits: [], score: 0 }, L4_fingerprints: { hits: [], score: 0 } };
  }
}

function runCfpMatcher(soPath) {
  try {
    const out = execFileSync("node", [path.join(SCRIPT_DIR, "cfp_matcher.js"), "--so", soPath, "--json"], {
      encoding: "utf8",
      timeout: 120000,
      maxBuffer: 10 * 1024 * 1024
    });
    return JSON.parse(out.trim());
  } catch (e) {
    return { patterns: [], score: 0, error: e.message };
  }
}

function runStringXref(soPath, strings) {
  const args = ["--so", soPath, "--strings", JSON.stringify(strings), "--json"];
  try {
    const out = execFileSync("node", [path.join(SCRIPT_DIR, "string_xref.js"), ...args], {
      encoding: "utf8",
      timeout: 120000,
      maxBuffer: 10 * 1024 * 1024
    });
    return JSON.parse(out.trim());
  } catch (e) {
    return [];
  }
}

// ─── 置信度融合公式 ─────────────────────────────────────────────────────────
function computeFusion(layers, l5Score) {
  // 加权融合：L1(0.10) + L2(0.20) + L3(0.10) + L4(0.35) + L5(0.25)
  const w1 = layers.L1_strings.score * 0.10;
  const w2 = layers.L2_constants.score * 0.20;
  const w3 = layers.L3_symbols.score * 0.10;
  const w4 = layers.L4_fingerprints.score * 0.35;
  const w5 = l5Score * 0.25;

  return Math.min(1.0, w1 + w2 + w3 + w4 + w5);
}

function computeVerdict(score) {
  if (score >= 0.60) return "annotate";
  if (score >= 0.35) return "flag";
  if (score >= 0.15) return "note";
  return "clean";
}

function inferAlgorithm(layers) {
  // 基于 L4 指纹推断
  if (layers.L4_fingerprints && layers.L4_fingerprints.hits) {
    for (const hit of layers.L4_fingerprints.hits) {
      if (hit.fingerprint && hit.fingerprint.includes("wyhash")) return "wyhash_variant";
      if (hit.fingerprint && hit.fingerprint.includes("quic")) return "quic_sbox_variant";
      if (hit.fingerprint && hit.fingerprint.includes("tea")) return "tea_xtea_family";
      if (hit.fingerprint && hit.fingerprint.includes("sm4")) return "sm4_gb32907";
      if (hit.fingerprint && hit.fingerprint.includes("crc")) return "crc32";
      if (hit.fingerprint && hit.fingerprint.includes("chacha20")) return "chacha20";
    }
  }
  // 基于 L5 CFP 模式推断（位运算密集模式优先）
  if (layers.L5_cfp && layers.L5_cfp.hits) {
    const l5Hits = layers.L5_cfp.hits;
    if (l5Hits.includes("chacha20_qr_pattern")) return "chacha20";
  }
  // 基于 L2 常量族推断
  if (layers.L2_constants && layers.L2_constants.families) {
    const fams = layers.L2_constants.families;
    if (fams.includes("wyhash")) return "wyhash_variant";
    if (fams.includes("aes")) return "aes";
    if (fams.includes("sm4")) return "sm4";
    if (fams.includes("sha256")) return "sha256";
    if (fams.includes("md5")) return "md5";
  }
  return "unknown";
}

// ─── 命令行 ─────────────────────────────────────────────────────────────────
function parseArgs() {
  const args = process.argv.slice(2);
  const opts = { so: null, fingerprintsDir: null, json: false };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--so" && i + 1 < args.length) opts.so = args[++i];
    else if (args[i] === "--fingerprints-dir" && i + 1 < args.length) opts.fingerprintsDir = args[++i];
    else if (args[i] === "--json") opts.json = true;
  }
  if (!opts.so) {
    console.error("Usage: node target_scanner.js --so <path> [--fingerprints-dir <dir>] [--json]");
    process.exit(1);
  }
  return opts;
}

// ─── 主流程 ─────────────────────────────────────────────────────────────────
async function main() {
  const opts = parseArgs();
  const fpDir = opts.fingerprintsDir || path.join(SCRIPT_DIR, "..", "..", "rules", "fingerprints", "algorithms");

  if (!opts.json) {
    console.error(`[target_scanner] Phase 4b — Native Target Scanner`);
    console.error(`[target_scanner] Target: ${opts.so}`);
    console.error(`[target_scanner] Fingerprints: ${fpDir}`);
    console.error("");
  }

  // 基本验证
  let arch = "unknown";
  try {
    const buf = fs.readFileSync(opts.so);
    const eiClass = buf[4];
    const eiData  = buf[5];
    const is64 = eiClass === 2;
    const isLE = eiData === 1;

    let eMachine;
    if (is64) {
      eMachine = isLE ? buf.readUInt16LE(18) : buf.readUInt16BE(18);
    } else {
      eMachine = isLE ? buf.readUInt16LE(18) : buf.readUInt16BE(18);
    }
    arch = eMachine === 183 ? "arm64-v8a" : eMachine === 40 ? "armeabi-v7a" : eMachine === 62 ? "x86_64" : "unknown";
  } catch (e) {
    console.error(`[target_scanner] ERROR: Cannot parse ELF: ${e.message}`);
    process.exit(1);
  }

  const layers = {
    L1_strings:      { hits: [], score: 0 },
    L2_constants:    { hits: [], score: 0 },
    L3_symbols:      { hits: [], score: 0 },
    L4_fingerprints: { hits: [], score: 0 },
    L5_cfp:          { hits: [], score: 0 },
  };

  // ── L1: 字符串扫描 ──
  if (!opts.json) console.error("[target_scanner] L1: scanning key strings...");
  const l1RawHits = scanL1Strings(opts.so);
  const l1UniqueStrings = [...new Set(l1RawHits.map(h => h.string))];

  // ── L2+L3+L4: 常量 + 符号 + 指纹 ──
  if (!opts.json) console.error("[target_scanner] L2-L4: running constant_scanner...");
  const csResult = runConstantScanner(opts.so, fpDir);
  if (csResult) {
    layers.L2_constants    = csResult.L2_constants    || { hits: [], score: 0 };
    layers.L3_symbols      = csResult.L3_symbols      || { hits: [], score: 0 };
    layers.L4_fingerprints = csResult.L4_fingerprints || { hits: [], score: 0 };
  }

  // ── L5: CFG+数据流 ──
  if (!opts.json) console.error("[target_scanner] L5: running cfp_matcher...");
  const l5Result = runCfpMatcher(opts.so);
  const l5Patterns = l5Result.patterns || [];
  const l5Score = l5Result.score || 0;
  layers.L5_cfp = {
    hits: l5Patterns.map(p => p.name),
    score: l5Score,
    details: l5Patterns
  };

  // ── L1 反伪阳性验证 ──
  const validation = validateL1WithL5(l1RawHits, l5Patterns);
  layers.L1_strings = {
    hits: l1UniqueStrings,
    score: validation.score,
    raw_count: l1RawHits.length
  };
  if (!validation.valid && !opts.json) {
    console.error(`[target_scanner] L1 anti-FP: ${validation.reason}`);
  }

  // ── L1.5: 字符串交叉引用 ──
  let xrefs = [];
  if (l1UniqueStrings.length > 0 && validation.valid) {
    if (!opts.json) console.error("[target_scanner] L1.5: running string_xref...");
    xrefs = runStringXref(opts.so, l1UniqueStrings.slice(0, 20)); // 限制 20 个以减少开销
  }

  // ── 融合评分 ──
  const finalScore = computeFusion(layers, l5Score);
  const verdict = computeVerdict(finalScore);
  const algorithm = inferAlgorithm(layers);

  // ── 组装报告 ──
  const report = {
    target: path.basename(opts.so),
    path: opts.so,
    arch,
    layers,
    xrefs,
    final_score: parseFloat(finalScore.toFixed(2)),
    verdict,
    algorithm,
    evidence_summary: {
      l1_count: layers.L1_strings.hits.length,
      l2_families: layers.L2_constants.families || [],
      l3_imports: (layers.L3_symbols.hits || []).map(h => h.symbol),
      l4_fingerprints: (layers.L4_fingerprints.hits || []).map(h => h.fingerprint),
      l5_patterns: l5Patterns.map(p => `${p.name}(${p.count})`),
      xref_count: xrefs.length
    },
    timestamp: new Date().toISOString()
  };

  // ── 输出 ──
  const output = JSON.stringify(report, null, opts.json ? 0 : 2);
  process.stdout.write(output);
  if (!opts.json) process.stdout.write("\n");
}

main().catch(e => {
  console.error(`[target_scanner] FATAL: ${e.message}`);
  process.exit(1);
});
