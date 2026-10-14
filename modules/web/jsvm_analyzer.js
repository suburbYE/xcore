#!/usr/bin/env node
/**
 * jsvm_analyzer.js - 字节码类 JSVM 运行时（_$jsvmprt）深度静态分析
 * Phase 5w: Web 分析模块 - JSVM 字节码分析
 *
 * Usage:
 *   node jsvm_analyzer.js --file <path.html|js> [--json] [--strings] [--key <n>] [--out <dir>]
 *   node jsvm_analyzer.js --dir <dir> [--json]
 *
 * 背景：某短视频平台 web 端 jsvm_runtime 的 __ac_signature 由字节码类 JSVM 运行时
 * （全局 _$jsvmprt）内联 hex 字节码解释执行。本模块把该运行时的静态拆解
 * 固化为工具链能力（对齐 wasm_analyzer 思路）：
 *   1. 定位：HTML/JS 中提取 _$jsvmprt 运行时与内联 hex 字节码
 *   2. 校验：魔数 HNOJ@?RC（JSVM 运行时身份证）
 *   3. XOR key 自动探测：0-255 全扫描 + 最长可打印段打分（样本命中 key=2）
 *   4. 字符串表还原：XOR 后按可打印流分段输出常量池
 *   5. 算法链识别：sdbm / xxtea / 自定义 base64 表 / jsvm_runtime 等特征
 *   输出：统一 JSON 报告 + 字符串表
 */

"use strict";

const fs = require("fs");
const path = require("path");

const JSVM_MAGIC = "HNOJ@?RC";
const JSVM_MAGIC_HEX = Buffer.from(JSVM_MAGIC, "ascii").toString("hex").toLowerCase(); // 484e4f4a403f5243

// 已知算法/框架特征（字符串表命中）
const ALGO_HINTS = [
  { name: "jsvm_runtime", patterns: ["jsvm_runtime"] },
  { name: "sdbm", patterns: ["sdbm", "sdbm_stable"] },
  { name: "xxtea", patterns: ["xxtea", "xtea"] },
  { name: "custom_base64", patterns: ["Dkdpgh4ZKsQB80"] },
  { name: "md5", patterns: ["md5"] },
  { name: "randomString", patterns: ["randomString"] },
];

// 环境指纹采集特征
const ENV_FINGERPRINT_HINTS = [
  "documentMode", "isIE", "isFirefox", "isSafari", "HTMLElement",
  "pushNotification", "userAgent", "platform", "screen",
];
const TIMING_HINTS = ["getTimestamp", "getTime", "Date", "performance"];

/**
 * 从 HTML/JS 文本中提取 JSVM hex 字节码
 * 模式 A：_$jsvmprt 运行时函数体内内联的 hex 字符串（以 magic hex 开头）
 * 模式 B：_$jsvmprt("hex") 调用形式传入
 */
function extractJsvmHex(text) {
  const found = [];
  // 模式 A/B 统一：先定位所有 magic hex 出现位置，再向前截取引号字符串
  let idx = 0;
  while ((idx = text.indexOf(JSVM_MAGIC_HEX, idx)) !== -1) {
    // 向前找最近的引号起始（引号在 magic 之前）
    let start = idx;
    while (start > 0 && text[start - 1] !== '"' && text[start - 1] !== "'") start--;
    if (start > 0 && (text[start - 1] === '"' || text[start - 1] === "'")) {
      start -= 1;
      const quote = text[start];
      let end = idx;
      while (end < text.length && text[end] !== quote) end++;
      if (end < text.length) {
        const raw = text.slice(start + 1, end);
        const hex = raw.replace(/[^0-9a-fA-F]/g, "");
        if (hex.length > 32 && hex.length % 2 === 0 && hex.toLowerCase().startsWith(JSVM_MAGIC_HEX)) {
          found.push({ hex, rawStart: start, rawEnd: end });
        }
      }
    }
    idx += JSVM_MAGIC_HEX.length;
  }
  return found;
}

/** hex 字符串 -> Buffer */
function hexToBuf(hex) {
  try {
    return Buffer.from(hex, "hex");
  } catch (e) {
    return null;
  }
}

// 字符串表特征词典（key 验证用：只有正确 key 才会解出真实英文常量）
const KEY_VERIFY_WORDS = [
  "object", "undefined", "function", "number", "string", "boolean",
  "window", "document", "Array", "JSON", "Math", "length", "return",
  "jsvm_runtime", "Dkdpgh4",
];

/** 用特征词典给候选 key 打分（命中数） */
function verifyKey(buf, key) {
  const dec = Buffer.alloc(buf.length);
  for (let i = 0; i < buf.length; i++) dec[i] = buf[i] ^ key;
  const text = dec.toString("latin1");
  let hits = 0;
  for (const w of KEY_VERIFY_WORDS) if (text.includes(w)) hits++;
  return hits;
}

/**
 * XOR key 探测（两阶段）：
 *   阶段1 字母数字密度：限定尾部 30%（字符串常量池通常位于字节码尾部），
 *     统计字母数字字节数，取 Top-8 候选（opcode 区大量 00 填充字节在任意
 *     key 下会变可打印符号，故仅统计 a-zA-Z0-9 防虚高）；
 *   阶段2 特征词典验证：对候选逐一解出字符串并匹配英文常量词典，命中最
 *     高者为真 key。样本验证：key=2 命中 11，其余候选 0-1。
 */
function probeKey(buf) {
  const start = Math.floor(buf.length * 0.7);
  const cands = [];
  for (let k = 0; k < 256; k++) {
    let alnum = 0;
    for (let i = start; i < buf.length; i++) {
      const c = buf[i] ^ k;
      if ((c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a)) alnum++;
    }
    cands.push({ key: k, alnum });
  }
  cands.sort((a, b) => b.alnum - a.alnum);
  const top = cands.slice(0, 8);
  let best = { key: top[0].key, alnum: top[0].alnum, verifyHits: -1, candidates: top.map(c => c.key) };
  for (const c of top) {
    const hits = verifyKey(buf, c.key);
    if (hits > best.verifyHits) { best.verifyHits = hits; best.key = c.key; best.alnum = c.alnum; }
  }
  return best;
}

/**
 * 定位字符串常量池起点：解密后从尾部反向扫描 256 字节窗口，
 * 找第一个可打印比例 > 0.5 的窗口（opcode 区比例低、字符串区高），
 * 再向前回退 32 字节缓冲，避免截断表头。
 */
function findStringTableStart(dec) {
  const N = dec.length;
  const win = 256;
  let start = 0;
  for (let i = N - win; i >= 0; i -= win) {
    let printable = 0;
    for (let j = i; j < i + win; j++) {
      const c = dec[j];
      if (c >= 0x20 && c < 0x7f) printable++;
    }
    if (printable / win > 0.5) start = i;
    else break;
  }
  return Math.max(0, start - 32);
}

/** XOR 解出字符串表（按可打印流分段，从常量池起点开始） */
function extractStrings(buf, key) {
  const dec = Buffer.alloc(buf.length);
  for (let i = 0; i < buf.length; i++) dec[i] = buf[i] ^ key;
  const start = findStringTableStart(dec);
  const out = [];
  let cur = [];
  const flush = () => { if (cur.length) { out.push(Buffer.from(cur).toString("utf8")); cur = []; } };
  for (let i = start; i < buf.length; i++) {
    const c = dec[i];
    if (c >= 0x20 && c < 0x7f) cur.push(c);
    else flush();
  }
  flush();
  return { strings: out, tableStart: start };
}

/** 在字符串表中识别算法链特征 */
function detectAlgorithms(strings) {
  const all = strings.join("\n");
  const hits = [];
  for (const h of ALGO_HINTS) {
    for (const p of h.patterns) {
      if (all.includes(p)) { hits.push({ name: h.name, matched: p }); break; }
    }
  }
  return hits;
}

/** 识别环境指纹/时间戳采集特征 */
function detectFingerprint(strings) {
  const all = strings.join("\n");
  return {
    env: ENV_FINGERPRINT_HINTS.filter(s => all.includes(s)),
    timing: TIMING_HINTS.filter(s => all.includes(s)),
  };
}

/**
 * 通用 JSVMP 探针（模式 B）：检测 webpack 内嵌式自研虚拟机（知乎 x-zse-96 型）。
 * 与某短视频平台 _$jsvmprt（hex 字节码 + magic）不同，知乎的虚拟机是：
 *   - 解释器入口形如 `X.prototype.O=function(A,C,s){...}`（O 即执行函数）
 *   - 巨型 switch 调度：`case N:this.T=this.T*k+c` / `this.T+=...`（T 为程序计数器）
 *   - 调用点 `.O(G,V,D)`（输入 / 字节码 / 输出 三参）
 *   - 版本号常量形如 `A="3.0"`
 * 静态层只做 检出 + 定位 + opcode 规模估算 + 版本提取，不做字节码还原。
 */
function detectGenericJsvm(text) {
  const hits = [];
  const entryRe = /([A-Za-z_$][\w$]*\.prototype\.O|prototype\.O)=function\(([^)]*)\)\{/g;
  let m;
  while ((m = entryRe.exec(text)) !== null) {
    const start = m.index;
    const bodyStart = m.index + m[0].length;
    const params = m[2] || "";
    // 函数体边界：从 bodyStart 做简单括号配平（最多取 200KB，避免误吞整包）
    let depth = 1, end = bodyStart;
    const cap = Math.min(text.length, bodyStart + 200000);
    for (let i = bodyStart; i < cap && depth > 0; i++) {
      const ch = text[i];
      if (ch === "{") depth++;
      else if (ch === "}") depth--;
      end = i + 1;
    }
    const body = text.slice(bodyStart, end);
    const opcodes = new Set();
    const caseRe = /case\s+(\d+):/g;
    let cm;
    while ((cm = caseRe.exec(body)) !== null) opcodes.add(parseInt(cm[1], 10));
    const dispatch = /this\.T\s*=\s*this\.T\s*[+\-*]|this\.T\s*[+\-]=|this\.T\s*=\s*[+\-]?/.test(body);
    if (opcodes.size >= 20 && dispatch) {
      const hit = {
        mode: "webpack_switch_vm",
        entry: m[1] || "prototype.O",
        params: params,
        opcodeCount: opcodes.size,
        dispatch: true,
        size: end - start,
        callSites: [],
      };
      // 三参调用点 .O(G,V,D)
      const callRe = /\.O\(([A-Za-z_$][\w$]*),([A-Za-z_$][\w$]*),([A-Za-z_$][\w$]*)\)/g;
      let c;
      while ((c = callRe.exec(text.slice(Math.max(0, start - 4000), Math.min(text.length, end + 4000)))) !== null) {
        hit.callSites.push({ input: c[1], bytecode: c[2], output: c[3] });
      }
      // 版本号：入口函数所在模块附近 `A="x.y"` / `var A="x.y"`
      const vRe = /(?:var\s+)?[A-Za-z_$][\w$]*\s*=\s*"(\d+\.\d+[^"]*)"|version\s*[:=]\s*"([^"]+)"/g;
      let v;
      const verWin = text.slice(Math.max(0, start - 3000), Math.min(text.length, end + 1000));
      while ((v = vRe.exec(verWin)) !== null) {
        hit.version = v[1] || v[2];
        break;
      }
      // 关联算法特征（模块附近 S-box / 轮函数 / md5 常量）
      const algoWin = text.slice(Math.max(0, start - 2000), end);
      hit.algorithms = [];
      if (/255&ei\[\w+\]/.test(algoWin) || />>>\s*24|0xff000000/.test(algoWin)) hit.algorithms.push("byte_bigendian_crypto");
      if (/charCodeAt/.test(algoWin)) hit.algorithms.push("string_byte_mix");
      if (/eval\(/.test(body)) hit.algorithms.push("eval_dyn_code");
      hits.push(hit);
    }
  }
  return hits;
}

/**
 * 主入口：分析单份 HTML/JS 文本
 * @param {string} text HTML/JS 源码
 * @param {string} src 来源描述（文件名/URL）
 */
function analyzeJsvmText(text, src) {
  const report = { source: src, found: 0, runtimes: [], generic: [] };
  const extractions = extractJsvmHex(text);
  report.found = extractions.length;
  report.generic = detectGenericJsvm(text);

  for (const ex of extractions) {
    const buf = hexToBuf(ex.hex);
    if (!buf) continue;
    const rt = {
      size: buf.length,
      magic: buf.length >= 8 ? buf.slice(0, 8).toString("ascii") : "",
      magicValid: buf.length >= 8 && buf.slice(0, 8).toString("ascii") === JSVM_MAGIC,
    };
    if (rt.magicValid) {
      const pk = probeKey(buf);
      rt.key = pk.key;
      rt.keyScore = { verifyHits: pk.verifyHits, alnum: pk.alnum, candidates: pk.candidates };
      const ext = extractStrings(buf, rt.key);
      rt.stringTable = { count: ext.strings.length, tableStart: ext.tableStart, strings: ext.strings };
      rt.algorithms = detectAlgorithms(ext.strings);
      rt.fingerprint = detectFingerprint(ext.strings);
    }
    report.runtimes.push(rt);
  }
  return report;
}

/** 文件入口 */
function analyzeJsvmFile(filePath) {
  const text = fs.readFileSync(filePath, "utf8");
  const report = analyzeJsvmText(text, filePath);
  report.file = filePath;
  return report;
}

function main() {
  const argv = process.argv.slice(2);
  let file = "", dir = "", out = "", json = false, strings = false;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--file") file = argv[++i] || "";
    else if (argv[i] === "--dir") dir = argv[++i] || "";
    else if (argv[i] === "--out") out = argv[++i] || "";
    else if (argv[i] === "--json") json = true;
    else if (argv[i] === "--strings") strings = true;
  }
  if (!file && !dir) {
    console.error("[!] Usage: node jsvm_analyzer.js --file <path.html|js> | --dir <dir> [--json] [--strings] [--out <dir>]");
    process.exit(1);
  }

  const files = file ? [path.resolve(file)] : fs.readdirSync(dir).filter(f => /\.(html?|js)$/i.test(f)).map(f => path.join(dir, f));
  const reports = files.map(analyzeJsvmFile);

  if (json) {
    console.log(JSON.stringify(reports, null, 2));
  } else {
    for (const r of reports) {
      console.log(`[+] ${r.file}`);
      if (r.generic && r.generic.length) {
        for (const g of r.generic) {
          console.log(`    [generic] ${g.mode}: entry=${g.entry}(${g.params}) opcodes=${g.opcodeCount} size=${g.size}`);
          if (g.version) console.log(`      version=${g.version}`);
          if (g.callSites.length) console.log(`      callSites: ${g.callSites.map(c => `.O(${c.input},${c.bytecode},${c.output})`).slice(0, 4).join(", ")}`);
          if (g.algorithms.length) console.log(`      algorithms: ${g.algorithms.join(", ")}`);
        }
      }
      if (r.found === 0 && !(r.generic && r.generic.length)) { console.log("    no jsvm runtime found"); continue; }
      for (const rt of r.runtimes) {
        if (!rt.magicValid) { console.log(`    [!] runtime at ${r.file}: bad magic "${rt.magic}"`); continue; }
        console.log(`    runtime: ${rt.size} bytes, magic=${rt.magic}, xor_key=${rt.key}`);
        console.log(`    strings: ${rt.stringTable.count} entries, verify_hits=${rt.keyScore.verifyHits}, alnum=${rt.keyScore.alnum}`);
        if (rt.stringTable.strings.length) {
          console.log(`      head: ${rt.stringTable.strings.slice(0, 12).filter(s => s).join(", ")}`);
        }
        if (rt.algorithms.length) console.log(`    algorithms: ${rt.algorithms.map(a => `${a.name}(${a.matched})`).join(", ")}`);
        if (rt.fingerprint.env.length || rt.fingerprint.timing.length) {
          console.log(`    fingerprint: env=[${rt.fingerprint.env.join(",")}] timing=[${rt.fingerprint.timing.join(",")}]`);
        }
        if (strings) {
          const outDir = path.resolve(out || ".");
          fs.mkdirSync(outDir, { recursive: true });
          const base = path.basename(r.file, path.extname(r.file));
          const sp = path.join(outDir, `${base}_jsvm_strings.txt`);
          fs.writeFileSync(sp, rt.stringTable.strings.join("\n"));
          console.log(`    strings saved: ${sp}`);
        }
      }
    }
  }
}

if (require.main === module) main();
module.exports = { analyzeJsvmText, analyzeJsvmFile, extractJsvmHex, probeKey, extractStrings, detectAlgorithms, detectGenericJsvm, JSVM_MAGIC };
