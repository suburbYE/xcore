#!/usr/bin/env node
/**
 * wasm_analyzer.js - WASM 二进制深度结构分析（v2）
 * Phase 5w: Web 分析模块 - WASM 静态分析
 *
 * Usage:
 *   node wasm_analyzer.js --file <path.wasm> [--json] [--strings]
 *   node wasm_analyzer.js --dir <dir> [--json]
 *
 * 深度解析（对齐 B 站 wasm_rsa_encrypt_bg.wasm 逆向档案思路）：
 *   1. magic/version 校验 + section 遍历
 *   2. Type 段完整还原（func type 签名 params/results）
 *   3. Import 段完整还原（module/name/kind；func 导入关联 type 签名）
 *   4. Function 段 type 索引映射（func index → type index）
 *   5. Export 段关联函数签名（导出函数直接可见完整签名，如 decrypt(i32,i32)->i32）
 *   6. 框架识别：wasm-bindgen 特征（__wbindgen_* / __wbg_* 符号，Rust 胶水层身份证）
 *   7. 反混淆特征检测：导出名混淆 / 控制流平坦化（br_table 密度）/ 导入表混淆
 *   8. 数据段可疑串扫描（sign/rsa/wbi/gorgon/argus 等）
 */

"use strict";

const fs = require("fs");
const path = require("path");

const WASM_MAGIC = Buffer.from([0x00, 0x61, 0x73, 0x6d]); // \0asm

const SECTION_NAMES = {
  0: "Custom", 1: "Type", 2: "Import", 3: "Function",
  4: "Table", 5: "Memory", 6: "Global", 7: "Export",
  8: "Start", 9: "Element", 10: "Code", 11: "Data",
  12: "DataCount", 13: "Tag",
};

const VAL_TYPES = {
  0x7f: "i32", 0x7e: "i64", 0x7d: "f32", 0x7c: "f64",
  0x70: "funcref", 0x6f: "externref",
};

const IMPORT_KINDS = { 0: "func", 1: "table", 2: "memory", 3: "global", 13: "tag" };

function uleb128(buf, off) {
  let result = 0, shift = 0, b;
  do {
    b = buf[off++];
    result |= (b & 0x7f) << shift;
    shift += 7;
  } while (b & 0x80);
  return { value: result >>> 0, next: off };
}

function parseSections(buf) {
  const sections = [];
  let off = 8; // skip magic + version
  while (off < buf.length) {
    const id = buf[off++];
    const size = uleb128(buf, off); off = size.next;
    const end = off + size.value;
    sections.push({ id, name: SECTION_NAMES[id] || `Unknown(${id})`, size: size.value, start: off, end: end > buf.length ? buf.length : end });
    off = end;
  }
  return sections;
}

function extractStrings(buf, minLen = 6) {
  const out = [];
  let cur = [], start = -1;
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i];
    if (b >= 0x20 && b < 0x7f) { if (cur.length === 0) start = i; cur.push(b); }
    else {
      if (cur.length >= minLen) out.push({ offset: start, text: Buffer.from(cur).toString("latin1") });
      cur = [];
    }
  }
  if (cur.length >= minLen) out.push({ offset: start, text: Buffer.from(cur).toString("latin1") });
  return out;
}

function sigToString(t) {
  if (!t) return "?";
  return `(${t.params.join(", ")}) -> ${t.results.length ? t.results.join(", ") : "void"}`;
}

// ---------- 深度解析子段 ----------

/** Type 段：func type 签名完整还原 */
function parseTypeSection(buf, sec) {
  const types = [];
  let off = sec.start;
  const count = uleb128(buf, off); off = count.next;
  for (let i = 0; i < count.value && off < sec.end; i++) {
    const form = buf[off++];
    if (form !== 0x60) { types.push({ error: `unknown form 0x${form.toString(16)}` }); break; }
    const pc = uleb128(buf, off); off = pc.next;
    const params = [];
    for (let j = 0; j < pc.value && off < sec.end; j++) params.push(VAL_TYPES[buf[off++]] || `0x${buf[off - 1].toString(16)}`);
    const rc = uleb128(buf, off); off = rc.next;
    const results = [];
    for (let j = 0; j < rc.value && off < sec.end; j++) results.push(VAL_TYPES[buf[off++]] || `0x${buf[off - 1].toString(16)}`);
    types.push({ params, results });
  }
  return types;
}

function parseLimits(buf, off) {
  const flags = buf[off++];
  const min = uleb128(buf, off); off = min.next;
  const limits = { min: min.value };
  if (flags & 0x01) { const max = uleb128(buf, off); off = max.next; limits.max = max.value; }
  if (flags & 0x02) { const max = uleb128(buf, off); off = max.next; limits.max = max.value; limits.shared = true; }
  return { limits, next: off };
}

/** Import 段：module/name/kind 完整还原，func 导入关联 type 签名 */
function parseImportSection(buf, sec, types) {
  const imports = [];
  let off = sec.start;
  const count = uleb128(buf, off); off = count.next;
  for (let i = 0; i < count.value && off < sec.end; i++) {
    const ml = uleb128(buf, off); off = ml.next;
    const module = buf.subarray(off, off + ml.value).toString("latin1"); off += ml.value;
    const nl = uleb128(buf, off); off = nl.next;
    const name = buf.subarray(off, off + nl.value).toString("latin1"); off += nl.value;
    const kind = buf[off++];
    const item = { module, name, kind: IMPORT_KINDS[kind] || kind };
    if (kind === 0) { // func：type index 关联签名
      const ti = uleb128(buf, off); off = ti.next;
      item.typeIndex = ti.value;
      item.signature = sigToString(types[ti.value]);
    } else if (kind === 1) { // table：elemtype + limits
      const et = buf[off++];
      item.elemType = VAL_TYPES[et] || `0x${et.toString(16)}`;
      const lim = parseLimits(buf, off); off = lim.next;
      item.limits = lim.limits;
    } else if (kind === 2) { // memory：limits
      const lim = parseLimits(buf, off); off = lim.next;
      item.limits = lim.limits;
    } else if (kind === 3) { // global：valtype + mut
      const vt = buf[off++];
      item.valueType = VAL_TYPES[vt] || `0x${vt.toString(16)}`;
      item.mutable = buf[off++] === 1;
    } else { // tag(13) 等：attr + type index
      off++;
      const ti = uleb128(buf, off); off = ti.next;
      item.typeIndex = ti.value;
      item.signature = sigToString(types[ti.value]);
    }
    imports.push(item);
  }
  return imports;
}

/** Function 段：func → type 索引映射 */
function parseFunctionSection(buf, sec) {
  const typeIndices = [];
  let off = sec.start;
  const count = uleb128(buf, off); off = count.next;
  for (let i = 0; i < count.value && off < sec.end; i++) {
    const ti = uleb128(buf, off); off = ti.next;
    typeIndices.push(ti.value);
  }
  return typeIndices;
}

/** Code 段轻量控制流统计：block/loop/if/br_table 计数（CFG 平坦化启发式） */
function analyzeCodeSection(buf, sec) {
  let off = sec.start;
  const count = uleb128(buf, off); off = count.next;
  let funcs = 0, blocks = 0, loops = 0, ifs = 0, brTables = 0, instrs = 0;
  for (let i = 0; i < count.value && off < sec.end; i++) {
    funcs++;
    const bodySize = uleb128(buf, off); off = bodySize.next;
    const bodyEnd = off + bodySize.value;
    if (bodyEnd > sec.end) break;
    const ldc = uleb128(buf, off); off = ldc.next; // local decls
    for (let j = 0; j < ldc.value && off < bodyEnd; j++) {
      const nc = uleb128(buf, off); off = nc.next;
      off += nc.value; // skip valtypes
    }
    while (off < bodyEnd) {
      const op = buf[off++];
      instrs++;
      if (op === 0x02) blocks++;
      else if (op === 0x03) loops++;
      else if (op === 0x04) ifs++;
      else if (op === 0x0e) brTables++;
      off = skipImmediates(buf, off, op, bodyEnd);
    }
    off = bodyEnd;
  }
  return { funcs, blocks, loops, ifs, brTables, instrs };
}

/** 指令立即数粗跳过（按 opcode 类别；前缀指令保守处理，启发式统计可接受） */
function skipImmediates(buf, off, op, end) {
  const need = (n) => { off += n; return off > end ? end : off; };
  if (op === 0x02 || op === 0x03 || op === 0x04 || op === 0x0c || op === 0x0d || op === 0x10) { // block/loop/if/br/br_if/call
    const v = uleb128(buf, off); return v.next;
  }
  if (op === 0x0e) { // br_table：vec labels + default
    const n = uleb128(buf, off); off = n.next;
    for (let i = 0; i < n.value && off < end; i++) { const l = uleb128(buf, off); off = l.next; }
    const d = uleb128(buf, off); return d.next;
  }
  if (op === 0x11) { // call_indirect：type idx + table idx
    const t = uleb128(buf, off); off = t.next;
    off++;
    return off;
  }
  if (op >= 0x20 && op <= 0x26) { // local.get/set/tee, global.get/set, table.get/set
    const v = uleb128(buf, off); return v.next;
  }
  if (op >= 0x28 && op <= 0x3e) { // load/store 系列：memarg(flags, offset)
    const f = uleb128(buf, off); off = f.next;
    const o = uleb128(buf, off); return o.next;
  }
  if (op === 0x3f || op === 0x40) return need(1); // memory.size/grow
  if (op === 0x41) { const v = uleb128(buf, off); return v.next; } // i32.const
  if (op === 0x42) { const v = uleb128(buf, off); return v.next; } // i64.const (粗)
  if (op === 0x43) return need(4); // f32.const
  if (op === 0x44) return need(8); // f64.const
  if (op === 0xd0) return need(1); // ref.null
  if (op === 0xd2) { const v = uleb128(buf, off); return v.next; } // ref.func
  if (op === 0xfc || op === 0xfd || op === 0xfe) { // 前缀指令（sat/vector/atomic）
    const sub = uleb128(buf, off); off = sub.next;
    if (op === 0xfd) { // SIMD：多数有 memarg 或 lane 立即数，粗跳 1
      return off + 1 > end ? end : off + 1;
    }
    if (op === 0xfe) { // atomic：memarg
      const f = uleb128(buf, off); off = f.next;
      const o = uleb128(buf, off); return o.next;
    }
    return off;
  }
  if (op === 0xfb) { // GC 前缀
    const sub = uleb128(buf, off); off = sub.next;
    return off + 1 > end ? end : off + 1;
  }
  return off; // 无立即数
}

// ---------- 框架与反混淆检测 ----------

function detectFramework(imports, exports) {
  const names = [
    ...imports.map(i => `${i.module}.${i.name}`),
    ...exports.map(e => e.name),
  ];
  const wbindgen = names.filter(n => n.includes("__wbindgen_"));
  const wbg = names.filter(n => /__wbg_[0-9a-f_]+/.test(n));
  if (wbindgen.length || wbg.length) {
    return {
      name: "rust-wasm-bindgen",
      wbindgenSymbols: wbindgen.slice(0, 20),
      wbgBridgeCount: wbg.length,
      note: "Rust wasm-bindgen 胶水层：__wbindgen_* 为内存分配/序列化回调，__wbg_* 为宿主 API 桥（带 hash 后缀为框架自动命名）",
    };
  }
  return null;
}

function detectObfuscation(report, codeStats) {
  const obf = {};

  // 导出名混淆：Rust wasm-bindgen 默认保留语义化导出名；大量 hash/数字/超长随机名 → 手工混淆
  const names = report.exports.map(e => e.name);
  if (names.length) {
    const hashish = names.filter(n => /^[0-9a-fA-F]{16,}$/.test(n) || /^_[0-9]+$/.test(n) || (n.length >= 24 && /[0-9a-f]{8,}/.test(n)));
    const short = names.filter(n => n.length <= 2 && /^[a-zA-Z0-9_]+$/.test(n));
    const ratio = hashish.length / names.length;
    if (ratio > 0.3 || (short.length && short.length / names.length > 0.5)) {
      obf.exportNameObfuscated = true;
      obf.exportNameObfuscationRatio = Number(ratio.toFixed(2));
    }
  }

  // 控制流平坦化：br_table 密度（分发器模式）
  if (codeStats.brTables > 0) {
    const ctrl = codeStats.brTables + codeStats.blocks + codeStats.loops + codeStats.ifs;
    const ratio = ctrl ? codeStats.brTables / ctrl : 0;
    obf.brTableStats = codeStats;
    if (codeStats.brTables >= 30 && ratio > 0.15) {
      obf.flatControlFlow = true;
      obf.flatControlFlowRatio = Number(ratio.toFixed(2));
    }
  }

  // 导入表混淆：module/name 被替换为无意义短名
  if (report.imports.length) {
    const imNames = report.imports.map(i => i.name);
    const shortIm = imNames.filter(n => n.length <= 2);
    if (shortIm.length && shortIm.length / imNames.length > 0.5) {
      obf.importTableObfuscated = true;
      obf.importTableObfuscationRatio = Number((shortIm.length / imNames.length).toFixed(2));
    }
  }

  return Object.keys(obf).length ? obf : null;
}

// ---------- 主分析 ----------

const SUSPICIOUS_STRINGS = [
  "sign", "token", "hmac", "md5", "sha256", "aes", "rsa", "crypto",
  "encrypt", "decrypt", "key", "nonce", "salt", "chacha", "sm4",
  "base64", "xxtea", "gorgon", "argus", "soter", "wbi",
];

function analyzeWasm(filePath) {
  const buf = fs.readFileSync(filePath);
  const report = { file: filePath, size: buf.length, valid: false, sections: [], imports: [], exports: [], customNames: [], suspicious: [] };

  if (buf.length < 8 || !buf.subarray(0, 4).equals(WASM_MAGIC)) {
    report.error = "not a wasm binary (magic mismatch)";
    return report;
  }
  const version = buf.readUInt32LE(4);
  report.valid = true;
  report.version = version;

  const sections = parseSections(buf);
  report.sections = sections.map(s => ({ id: s.id, name: s.name, size: s.size }));

  // Type 段
  const typeSec = sections.find(s => s.id === 1);
  const types = typeSec ? parseTypeSection(buf, typeSec) : [];
  report.types = types;

  // Import 段
  const impSec = sections.find(s => s.id === 2);
  report.imports = impSec ? parseImportSection(buf, impSec, types) : [];

  // Function 段
  const funcSec = sections.find(s => s.id === 3);
  const functionTypes = funcSec ? parseFunctionSection(buf, funcSec) : [];
  report.functionTypes = functionTypes;

  // func index 空间 = func 导入 + 本地函数（同序编号）
  const funcSpace = [];
  for (const im of report.imports) if (im.kind === "func") funcSpace.push(im.typeIndex);
  for (const ti of functionTypes) funcSpace.push(ti);

  // Export 段：读 index 并关联签名
  const expSec = sections.find(s => s.id === 7);
  if (expSec) {
    let off = expSec.start;
    const count = uleb128(buf, off); off = count.next;
    for (let i = 0; i < count.value && off < expSec.end; i++) {
      const nl = uleb128(buf, off); off = nl.next;
      const name = buf.subarray(off, off + nl.value).toString("latin1"); off += nl.value;
      const kind = buf[off++];
      const idx = uleb128(buf, off); off = idx.next;
      const item = { name, kind: IMPORT_KINDS[kind] || kind, index: idx.value };
      if (kind === 0 && funcSpace[idx.value] !== undefined && types[funcSpace[idx.value]]) {
        item.signature = sigToString(types[funcSpace[idx.value]]);
      }
      report.exports.push(item);
    }
  }

  // Custom sections (id=0) - name 段
  for (const s of sections.filter(s => s.id === 0)) {
    const str = extractStrings(buf.subarray(s.start, s.end), 4).map(x => x.text);
    report.customNames.push(...str);
  }

  // 数据段字符串
  const dataSec = sections.find(s => s.id === 11);
  if (dataSec) {
    report.dataStrings = extractStrings(buf.subarray(dataSec.start, dataSec.end), 6).map(x => ({ offset: dataSec.start + x.offset, text: x.text }));
    for (const s of report.dataStrings) {
      const low = s.text.toLowerCase();
      if (SUSPICIOUS_STRINGS.some(k => low.includes(k))) {
        report.suspicious.push({ offset: s.offset, text: s.text.slice(0, 120) });
      }
    }
  }

  // Code 段控制流统计
  const codeSec = sections.find(s => s.id === 10);
  const codeStats = codeSec ? analyzeCodeSection(buf, codeSec) : null;
  if (codeStats) report.codeStats = codeStats;

  // 框架识别 + 反混淆检测
  report.framework = detectFramework(report.imports, report.exports);
  report.obfuscation = detectObfuscation(report, codeStats || { brTables: 0, blocks: 0, loops: 0, ifs: 0 });

  return report;
}

function main() {
  const argv = process.argv.slice(2);
  let file = "", dir = "", json = false;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--file") file = argv[++i] || "";
    else if (argv[i] === "--dir") dir = argv[++i] || "";
    else if (argv[i] === "--json") json = true;
  }
  if (!file && !dir) {
    console.error("[!] Usage: node wasm_analyzer.js --file <path.wasm> | --dir <dir> [--json]");
    process.exit(1);
  }

  const files = file ? [path.resolve(file)] : fs.readdirSync(dir).filter(f => f.endsWith(".wasm")).map(f => path.join(dir, f));
  const reports = files.map(analyzeWasm);

  if (json) {
    console.log(JSON.stringify(reports, null, 2));
  } else {
    for (const r of reports) {
      if (!r.valid) { console.log(`[!] ${r.file}: ${r.error}`); continue; }
      console.log(`[+] ${r.file} (${r.size} bytes, version ${r.version})`);
      console.log(`    sections: ${r.sections.map(s => s.name).join(", ")}`);
      if (r.types.length) console.log(`    types(${r.types.length}): ${r.types.slice(0, 6).map(t => sigToString(t)).join(" | ")}${r.types.length > 6 ? " ..." : ""}`);
      if (r.imports.length) {
        console.log(`    imports(${r.imports.length}):`);
        for (const i of r.imports.slice(0, 8)) console.log(`      ${i.module}.${i.name} [${i.kind}${i.signature ? " " + i.signature : ""}${i.limits ? " " + JSON.stringify(i.limits) : ""}]`);
      }
      if (r.exports.length) {
        console.log(`    exports(${r.exports.length}):`);
        for (const e of r.exports.slice(0, 16)) console.log(`      ${e.name}:${e.kind}#${e.index}${e.signature ? "  " + e.signature : ""}`);
      }
      if (r.framework) {
        console.log(`    framework : ${r.framework.name} (wbindgen=${r.framework.wbindgenSymbols.length}, __wbg_=${r.framework.wbgBridgeCount})`);
      }
      if (r.obfuscation) {
        const parts = [];
        if (r.obfuscation.exportNameObfuscated) parts.push(`exportNameObfuscated(${r.obfuscation.exportNameObfuscationRatio})`);
        if (r.obfuscation.flatControlFlow) parts.push(`flatControlFlow(${r.obfuscation.flatControlFlowRatio})`);
        if (r.obfuscation.importTableObfuscated) parts.push(`importTableObfuscated(${r.obfuscation.importTableObfuscationRatio})`);
        if (parts.length) console.log(`    obfuscation: ${parts.join(", ")}`);
      }
      if (r.codeStats) console.log(`    code stats : ${r.codeStats.funcs} funcs, ${r.codeStats.instrs} instrs, br_table=${r.codeStats.brTables}, blocks=${r.codeStats.blocks}, loops=${r.codeStats.loops}, ifs=${r.codeStats.ifs}`);
      if (r.suspicious.length) {
        console.log(`    suspicious(${r.suspicious.length}):`);
        for (const s of r.suspicious.slice(0, 10)) console.log(`      @${s.offset}: ${s.text}`);
      }
    }
  }
}

if (require.main === module) main();
module.exports = { analyzeWasm, parseSections, extractStrings };
