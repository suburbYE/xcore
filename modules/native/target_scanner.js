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
const { probe: probeOpenssl } = require("./openssl_probe.js");

// ─── 工具路径 ───────────────────────────────────────────────────────────────
const SCRIPT_DIR = __dirname;

// ─── OpenSSL 归因集（静态链入 libcrypto 会携带的算法/指纹/模式） ────────────
// 背景：zmd/ark 曾因静态链入 OpenSSL 3.1.4 libcrypto 被误判为天美 VMP/TPShell64 同源，
//       此处将 OpenSSL 覆盖范围内的特征归因到 openssl_libcrypto 并降权。
const OPENSSL_ALGO_FAMILIES = new Set(["aes", "sm4", "md5", "sha1", "sha256", "chacha20", "crc32"]);
const OPENSSL_L4_FINGERPRINTS = new Set(["sm4_fk_ck", "chacha20", "crc32_poly"]); // OpenSSL 3.x 自带 SM4/ChaCha20/CRC32 实现
const OPENSSL_L5_PATTERNS = new Set(["md5_round_pattern", "aes_mixcols_pattern", "chacha20_qr_pattern"]);
const OPENSSL_SYM_PATTERNS = [
  "HMAC_", "AES_", "SHA", "EVP_", "MD5_", "RSA_", "ECDSA_",
  "CRYPTO_", "OPENSSL_", "RAND_", "PKCS", "BN_", "BIO_", "X509_", "PEM_", "EC_", "ASN1_", "OBJ_"
];

// ─── L1 字符串扫描（内联实现，减少进程开销） ───────────────────────────────
const L1_KEY_STRINGS = [
  "h5st", "sign", "token", "X-Gorgon", "X-Argus", "X-Ladon",
  "X-Medusa", "X-Khronos", "X-Tyhon", "X-Helios", "X-Soter",
  "HMAC", "MD5_Update", "SHA256_Update", "AES_encrypt",
  "base64_encode", "url_encode", "xxtea", "getSignature",
  "signParams", "calcMd5", "genSign", "encrypt_data"
];

function scanL1Strings(filePath, maxScanSize) {
  const buf = fs.readFileSync(filePath);
  // --max-scan-size 0 = 全量扫描（不截断）
  const scanSize = (maxScanSize > 0) ? Math.min(buf.length, maxScanSize) : buf.length;
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
function runConstantScanner(soPath, fingerprintsDir, maxScanSize) {
  const args = ["--so", soPath, "--fingerprints-dir", fingerprintsDir, "--json"];
  if (maxScanSize > 0) args.push("--max-scan-size", String(maxScanSize));
  try {
    const out = execFileSync("node", [path.join(SCRIPT_DIR, "constant_scanner.js"), ...args], {
      encoding: "utf8",
      timeout: 120000,
      maxBuffer: 10 * 1024 * 1024
    });
    return JSON.parse(out.trim());
  } catch (e) {
    const err = e.message;
    return {
      L2_constants:    { hits: [], score: 0, error: err },
      L3_symbols:      { hits: [], score: 0, error: err },
      L4_fingerprints: { hits: [], score: 0, error: err },
    };
  }
}

function runCfpMatcher(soPath, maxScanSize) {
  const args = ["--so", soPath, "--json"];
  if (maxScanSize > 0) args.push("--max-scan-size", String(maxScanSize));
  try {
    const out = execFileSync("node", [path.join(SCRIPT_DIR, "cfp_matcher.js"), ...args], {
      encoding: "utf8",
      timeout: 120000,
      maxBuffer: 10 * 1024 * 1024
    });
    return JSON.parse(out.trim());
  } catch (e) {
    return { patterns: [], score: 0, error: e.message };
  }
}

function runStringXref(soPath, strings, maxScanSize) {
  const args = ["--so", soPath, "--strings", JSON.stringify(strings), "--json"];
  if (maxScanSize > 0) args.push("--max-scan-size", String(maxScanSize));
  try {
    const out = execFileSync("node", [path.join(SCRIPT_DIR, "string_xref.js"), ...args], {
      encoding: "utf8",
      timeout: 120000,
      maxBuffer: 10 * 1024 * 1024
    });
    return { xrefs: JSON.parse(out.trim()) };
  } catch (e) {
    return { xrefs: [], error: e.message };
  }
}

// ─── OpenSSL 归因降权 ───────────────────────────────────────────────────────
// 当 openssl_probe 判定目标静态链入 OpenSSL libcrypto 时，将 OpenSSL 覆盖范围内的
// L2/L3/L4/L5 特征归因到 openssl_libcrypto 并降权，避免误判为自研安全 SDK / 商业壳。
// 非 OpenSSL 覆盖范围的特征（wyhash/tea/quic/libhash_x/libcrypto_y 等）保持原分。
function applyOpensslAttribution(layers, l5Patterns, l5Score, opensslInfo) {
  const records = [];
  if (!opensslInfo || !opensslInfo.detected) return { l5Score, records };

  // ── L2：openssl 覆盖家族降权 ──
  const fams = layers.L2_constants.families || [];
  const osslFams = fams.filter(f => OPENSSL_ALGO_FAMILIES.has(f));
  const nonOsslFams = fams.filter(f => !OPENSSL_ALGO_FAMILIES.has(f));
  if (osslFams.length > 0) {
    const origScore = layers.L2_constants.score || 0;
    // 归因后：非 openssl 家族存在 → 保留 0.08；全是 openssl 家族 → 象征性 0.02
    layers.L2_constants.score = nonOsslFams.length > 0 ? 0.08 : 0.02;
    layers.L2_constants.openssl_attributed = osslFams;
    records.push({
      layer: "L2",
      detail: "families [" + osslFams.join(",") + "] attributed to OpenSSL libcrypto",
      orig_score: origScore,
      new_score: layers.L2_constants.score
    });
  }

  // ── L3：openssl API 符号归因，按剩余业务符号重算 ──
  const symHits = layers.L3_symbols.hits || [];
  const osslSyms = symHits.filter(h => OPENSSL_SYM_PATTERNS.some(p => (h.symbol || "").includes(p)));
  const bizSyms = symHits.filter(h => !OPENSSL_SYM_PATTERNS.some(p => (h.symbol || "").includes(p)));
  if (osslSyms.length > 0) {
    const origScore = layers.L3_symbols.score || 0;
    layers.L3_symbols.score = Math.min(0.10, bizSyms.length * 0.02);
    layers.L3_symbols.openssl_attributed = osslSyms.map(h => h.symbol).slice(0, 20);
    records.push({
      layer: "L3",
      detail: osslSyms.length + " symbols attributed to OpenSSL libcrypto (" + bizSyms.length + " business symbols remain)",
      orig_score: origScore,
      new_score: layers.L3_symbols.score
    });
  }

  // ── L4：openssl 覆盖指纹归因（sm4_fk_ck 来自 OpenSSL 自带 SM4） ──
  const l4Hits = layers.L4_fingerprints.hits || [];
  const osslFp = l4Hits.filter(h => OPENSSL_L4_FINGERPRINTS.has(h.fingerprint));
  const nonOsslFp = l4Hits.filter(h => !OPENSSL_L4_FINGERPRINTS.has(h.fingerprint));
  if (osslFp.length > 0) {
    const origScore = layers.L4_fingerprints.score || 0;
    layers.L4_fingerprints.score = Math.min(0.25, nonOsslFp.length * 0.25);
    layers.L4_fingerprints.openssl_attributed = osslFp.map(h => h.fingerprint);
    records.push({
      layer: "L4",
      detail: "fingerprints [" + osslFp.map(h => h.fingerprint).join(",") + "] attributed to OpenSSL libcrypto",
      orig_score: origScore,
      new_score: layers.L4_fingerprints.score
    });
  }

  // ── L5：openssl 轮函数模式降权 ──
  // md5_round / aes_mixcols / chacha20_qr 全归因（OpenSSL 静态库内必大量存在），
  // ror_chain 按 1/2 计（业务代码同样常见，不能全归）
  let newCount = 0;
  let affected = [];
  for (const p of l5Patterns) {
    if (OPENSSL_L5_PATTERNS.has(p.name)) {
      affected.push(p.name); // 全归因，不计数
    } else if (p.name === "ror_chain_x3") {
      newCount += Math.ceil(p.count / 2);
      affected.push(p.name);
    } else {
      newCount += p.count;
    }
  }
  if (affected.length > 0) {
    const newL5 = Math.min(0.20, newCount * 0.04);
    records.push({
      layer: "L5",
      detail: "patterns [" + affected.join(",") + "] downgraded (OpenSSL round functions)",
      orig_score: l5Score,
      new_score: newL5
    });
    l5Score = newL5;
  }

  return { l5Score, records };
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

function computeVerdict(score, layers) {
  if (score >= 0.60) return "annotate";
  if (score >= 0.35) return "flag";
  if (score >= 0.15) return "note";
  // Below the attribution threshold. "Found nothing" and "found something we
  // cannot attribute" are different answers and must not collapse into one:
  // kernel_drv_x.sys scores 0.05 overall while carrying 270 ror_chain_x3 hits
  // and an aes_mixcols_pattern, and reporting that as `clean` is a silent
  // false negative — the reader concludes there is nothing there.
  return countSignals(layers) > 0 ? "unknown" : "clean";
}

// Any layer that produced a hit, regardless of how little it contributed.
function countSignals(layers) {
  let n = 0;
  for (const key of Object.keys(layers || {})) {
    const layer = layers[key];
    if (!layer) continue;
    if (Array.isArray(layer.hits)) n += layer.hits.length;
    // L5 records carry the per-pattern counts; hits are added by fusion.
    if (Array.isArray(layer.details)) n += layer.details.length;
  }
  return n;
}

// L5 位运算模式 → 可命名的密码原语。只映射有确凿对应关系的模式；ror_chain_x3 /
// shift_add_combo / xor_mask_chain 是通用位混合，不足以命名具体算法，故不映射。
const L5_PRIMITIVE_HINTS = {
  chacha20_qr_pattern: "chacha20",
  aes_mixcols_pattern: "aes",
  md5_round_pattern:   "md5",
  sm3_round_pattern:   "sm3",
  sha256_round_pattern: "sha256",
};

// 实际观测到的密码原语。与「这些原语来自哪个库」是两件事：algorithm 字段曾经在
// 检出 OpenSSL 时直接填 "openssl_libcrypto (static)"，把库名写进算法字段，读者
// 因此看不到目标到底用了什么算法 —— 上一行刚命中的 AES S-box 证据被整个丢掉。
function observedCrypto(layers) {
  const found = [];
  const add = (n) => { if (n && !found.includes(n)) found.push(n); };

  const fams = (layers.L2_constants && layers.L2_constants.families) || [];
  for (const f of fams) add(f);

  const l5 = (layers.L5_cfp && layers.L5_cfp.hits) || [];
  for (const p of l5) add(L5_PRIMITIVE_HINTS[p]);

  const l4 = (layers.L4_fingerprints && layers.L4_fingerprints.hits) || [];
  for (const h of l4) {
    const fp = (h && h.fingerprint) || "";
    if (fp.includes("chacha20")) add("chacha20");
    if (fp.includes("sm4"))      add("sm4");
    if (fp.includes("sm3"))      add("sm3");
    if (fp.includes("tea"))      add("tea/xtea");
    if (fp.includes("crc"))      add("crc32");
  }
  return found;
}

function inferAlgorithm(layers, opensslInfo) {
  // OpenSSL 静态库优先：probe 为 HIGH 强度（版本串+ERR表+API串+符号表四类证据）时，
  // L4 指纹命中多为模式级误报（如 libhash_x_iv/quic_sbox_v1 在大 PE 内碰巧出现），直接归因 openssl。
  if (opensslInfo && opensslInfo.detected && opensslInfo.strength === "high") {
    // 归因给 OpenSSL，但不要把观测到的原语一起抹掉。
    const obs = observedCrypto(layers);
    return obs.length ? obs.join(" + ") : "openssl_libcrypto (static)";
  }
  if (opensslInfo && opensslInfo.detected) {
    const l4Hits = (layers.L4_fingerprints && layers.L4_fingerprints.hits) || [];
    const hasBizFingerprint = l4Hits.some(h => !OPENSSL_L4_FINGERPRINTS.has(h.fingerprint));
    if (!hasBizFingerprint) return "openssl_libcrypto (static)";
  }
  // 基于 L4 指纹推断
  if (layers.L4_fingerprints && layers.L4_fingerprints.hits) {
    for (const hit of layers.L4_fingerprints.hits) {
      if (hit.fingerprint && hit.fingerprint.includes("wyhash")) return "wyhash_variant";
      if (hit.fingerprint && hit.fingerprint.includes("quic")) return "quic_sbox_variant";
      if (hit.fingerprint && hit.fingerprint.includes("tea")) return "tea_xtea_family";
      if (hit.fingerprint && hit.fingerprint.includes("sm4")) return "sm4_gb32907";
      if (hit.fingerprint && hit.fingerprint.includes("crc")) return "crc32";
      if (hit.fingerprint && hit.fingerprint.includes("chacha20")) return "chacha20";
      if (hit.fingerprint && hit.fingerprint.includes("libhash_x")) return "libhash_x_arx_hash";
      if (hit.fingerprint && hit.fingerprint.includes("libcrypto_y")) return "boringssl_tb_sample_c";
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
  const opts = { so: null, fingerprintsDir: null, json: false, maxScanSize: 0 };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--so" && i + 1 < args.length) opts.so = args[++i];
    else if (args[i] === "--fingerprints-dir" && i + 1 < args.length) opts.fingerprintsDir = args[++i];
    else if (args[i] === "--json") opts.json = true;
    else if (args[i] === "--max-scan-size" && i + 1 < args.length) opts.maxScanSize = parseInt(args[++i], 10) || 0;
  }
  if (!opts.so) {
    console.error("Usage: node target_scanner.js --so <path> [--fingerprints-dir <dir>] [--json]");
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
    const eiClass = buf[4];
    const eiData  = buf[5];
    const isLE = eiData === 1;
    let eMachine;
    if (isLE) eMachine = buf.readUInt16LE(18);
    else eMachine = buf.readUInt16BE(18);
    if (eMachine === 183) return "arm64-v8a";
    if (eMachine === 40)  return "armeabi-v7a";
    if (eMachine === 62)  return "x86_64";
    return "unknown";
  }

  // PE: MZ 魔数 + e_lfanew 偏移处 PE\0\0 + IMAGE_FILE_HEADER.Machine
  if (buf[0] === 0x4D && buf[1] === 0x5A) { // 'M''Z'
    if (buf.length < 0x40) return "unknown";
    const e_lfanew = buf.readUInt32LE(0x3C);
    const peSig = buf.toString("latin1", e_lfanew, e_lfanew + 4);
    if (peSig !== "PE\x00\x00") return "unknown";
    const machine = buf.readUInt16LE(e_lfanew + 4);
    if (machine === 0x8664) return "x86_64";      // IMAGE_FILE_MACHINE_AMD64
    if (machine === 0x014C) return "x86";          // IMAGE_FILE_MACHINE_I386
    if (machine === 0xAA64) return "arm64-v8a";    // IMAGE_FILE_MACHINE_ARM64
    if (machine === 0x01C0) return "armeabi-v7a";  // IMAGE_FILE_MACHINE_ARM
    if (machine === 0x01C4) return "armeabi-v7a";  // IMAGE_FILE_MACHINE_ARMNT
    return "unknown";
  }

  // Mach-O: 0xfeedface / 0xfeedfacf / 0xcefaedfe / 0xcffaedfe
  if (magic === "\xfe\xed\xfa\xce" || magic === "\xfe\xed\xfa\xcf" ||
      magic === "\xce\xfa\xed\xfe" || magic === "\xcf\xfa\xed\xfe") {
    return "macho";
  }

  return "unknown";
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
    arch = detectArch(buf);
  } catch (e) {
    console.error(`[target_scanner] ERROR: Cannot parse header: ${e.message}`);
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
  const l1RawHits = scanL1Strings(opts.so, opts.maxScanSize);
  const l1UniqueStrings = [...new Set(l1RawHits.map(h => h.string))];

  // ── L2+L3+L4: 常量 + 符号 + 指纹 ──
  if (!opts.json) console.error("[target_scanner] L2-L4: running constant_scanner...");
  const csResult = runConstantScanner(opts.so, fpDir, opts.maxScanSize);
  if (csResult) {
    layers.L2_constants    = csResult.L2_constants    || { hits: [], score: 0 };
    layers.L3_symbols      = csResult.L3_symbols      || { hits: [], score: 0 };
    layers.L4_fingerprints = csResult.L4_fingerprints || { hits: [], score: 0 };
  }

  // ── L5: CFG+数据流 ──
  if (!opts.json) console.error("[target_scanner] L5: running cfp_matcher...");
  const l5Result = runCfpMatcher(opts.so, opts.maxScanSize);
  const l5Patterns = l5Result.patterns || [];
  const l5Score = l5Result.score || 0;
  layers.L5_cfp = {
    hits: l5Patterns.map(p => p.name),
    score: l5Score,
    details: l5Patterns
  };
  if (l5Result.error) layers.L5_cfp.error = l5Result.error;   // 别把子模块崩溃吞掉

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
  let xrefError = null;
  if (l1UniqueStrings.length > 0 && validation.valid) {
    if (!opts.json) console.error("[target_scanner] L1.5: running string_xref...");
    const xr = runStringXref(opts.so, l1UniqueStrings.slice(0, 20), opts.maxScanSize); // 限制 20 个以减少开销
    xrefs = Array.isArray(xr) ? xr : (xr.xrefs || []);
    xrefError = (xr && xr.error) || null;
  }

  // ── OpenSSL 静态库探测与归因降权 ──
  let opensslInfo = { detected: false, version: null, strength: null, evidence: [] };
  try {
    opensslInfo = probeOpenssl(fs.readFileSync(opts.so));
  } catch (e) {
    if (!opts.json) console.error("[target_scanner] openssl_probe failed: " + e.message);
  }
  if (opensslInfo.detected) {
    if (!opts.json) console.error("[target_scanner] OpenSSL libcrypto detected: " + (opensslInfo.version || "unknown") + " (" + opensslInfo.strength + ") — attributing OpenSSL-scope features");
  }
  const attribution = applyOpensslAttribution(layers, l5Patterns, l5Score, opensslInfo);

  // ── 融合评分 ──
  const finalScore = computeFusion(layers, attribution.l5Score);

  // 子模块崩溃时必须显式降级：全层失败得到的 0 分和「真的干净」不是一回事，
  // 静默报 clean 会造成无声漏报。
  const failedLayers = ["L2_constants", "L3_symbols", "L4_fingerprints", "L5_cfp"]
    .filter(k => layers[k] && layers[k].error);
  if (xrefError) failedLayers.push("L1.5_xrefs");

  const verdict = failedLayers.length > 0
    ? "error"
    : computeVerdict(finalScore, layers);
  if (failedLayers.length > 0) {
    console.error("[target_scanner] WARNING: " + failedLayers.length + " layer(s) failed: "
      + failedLayers.join(", ") + " — verdict downgraded to 'error' (NOT 'clean')");
    for (const k of failedLayers) {
      const src = k === "L1.5_xrefs" ? xrefError : layers[k].error;
      console.error("[target_scanner]   " + k + ": " + src);
    }
  }
  const algorithm = inferAlgorithm(layers, opensslInfo);

  // ── 组装报告 ──
  const report = {
    target: path.basename(opts.so),
    path: opts.so,
    arch,
    layers,
    xrefs,
    final_score: parseFloat(finalScore.toFixed(2)),
    verdict,
    degraded: failedLayers.length > 0,
    failed_layers: failedLayers,
    algorithm,
    // 库归因单独成字段：algorithm 回答「用了什么密码学」，library 回答「来自哪个库」。
    // openssl 对象里仍保留原始证据与降权明细。
    library: opensslInfo.detected
      ? ("openssl_libcrypto" + (opensslInfo.version ? " " + opensslInfo.version : "")
         + " (static)")
      : null,
    openssl: {
      detected: opensslInfo.detected,
      version: opensslInfo.version,
      strength: opensslInfo.strength,
      note: opensslInfo.detected
        ? "加密特征归因于静态链接的 OpenSSL libcrypto，不计入自研安全SDK/商业壳评分"
        : null,
      attributed: attribution.records
    },
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
