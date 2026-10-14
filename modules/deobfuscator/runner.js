#!/usr/bin/env node
/**
 * xcore runner.js — VM Sandbox with catch-all Proxy + Trace collection
 * Usage: node runner.js --input <target.js> [--inst] [--freeze] [--json] [--trace-out <path>]
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');

// ─── CLI ──────────────────────────────────────────────────
function parseArgs(args) {
  const cfg = { input: null, traceOut: null, entry: null, inst: false, freeze: false, json: false };
  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--input':     cfg.input    = args[++i]; break;
      case '--trace-out': cfg.traceOut = args[++i]; break;
      case '--entry':     cfg.entry    = args[++i]; break;
      case '--inst':      cfg.inst     = true; break;
      case '--freeze':    cfg.freeze   = true; break;
      case '--json':      cfg.json     = true; break;
    }
  }
  if (!cfg.input) { console.error('ERROR: --input <file> required'); process.exit(1); }
  cfg.input = path.resolve(cfg.input);
  return cfg;
}

// ─── Proxy Builder ────────────────────────────────────────
// 兜底 mock 打标记：window/document 是 catch-all Proxy，任意属性取值都会返回
// 一个 mock 函数。若不区分，入口存在性判断会恒为真（历史上就是这样误报的）。
const MOCK = Symbol.for('xcore.sandbox.mock');

function mkProxy(name, defaults = {}) {
  return new Proxy(Object.assign({}, defaults), {
    get(t, p) {
      if (p in t) return t[p];
      if (typeof p === 'string' && p !== 'then' && p !== Symbol.toPrimitive) {
        if (p.endsWith('_')) return undefined;
        const mock = () => {}; mock[MOCK] = true; t[p] = mock; return mock;
      }
      return undefined;
    },
    set(t, p, v) { t[p] = v; return true; },
    has() { return true; },
  });
}

// ─── 入口解析 ─────────────────────────────────────────────
// 支持 "window.ParamsSign.sign" / "target" / "globalThis.foo.bar" 等写法。
// 返回 { fn, receiver }；入口不存在返回 null（不是错误，由调用方决定语义）。
function resolveEntry(root, expr) {
  const parts = String(expr || '').split('.').map(s => s.trim()).filter(Boolean);
  if (parts.length && (parts[0] === 'sandbox' || parts[0] === 'globalThis')) parts.shift();
  if (!parts.length) return null;

  const chain = [root];
  let i = 0;
  for (; i < parts.length; i++) {
    const cur = chain[chain.length - 1];
    if (cur == null) break;
    let next;
    try { next = cur[parts[i]]; } catch (e) { break; }
    if (next == null) break;
    if (next[MOCK] === true) break;                       // 撞到兜底 mock → 脚本未定义该入口
    if (typeof next !== 'function' && typeof next !== 'object') { chain.push(next); i++; break; }
    chain.push(next);
  }
  const remaining = parts.slice(i);
  const last  = chain[chain.length - 1];
  const owner = chain.length >= 2 ? chain[chain.length - 2] : root;
  if (last == null || last[MOCK] === true) return null;

  // 完整路径即为可调用入口：receiver 取上一层（方法调用语义）
  if (remaining.length === 0) {
    return typeof last === 'function' ? { fn: last, receiver: owner } : null;
  }

  // 形如 A.B：B 多半是 A 的实例方法（京东 ParamsSign.sign 即此类），先 new 再取
  if (remaining.length === 1 && typeof last === 'function') {
    const names = [remaining[0], remaining[0] + 'Sync'];   // 兼容 JD 的 sign / signSync 双入口
    try {
      const inst = new last();
      if (inst != null) {
        for (const n of names) {
          if (typeof inst[n] === 'function') return { fn: inst[n], receiver: inst };
        }
      }
    } catch (e) { /* 不是构造函数 → 退回去试静态方法 */ }
    for (const n of names) {
      const stat = last[n];
      if (typeof stat === 'function' && stat[MOCK] !== true) return { fn: stat, receiver: last };
    }
  }
  return null;
}

// ─── Main ─────────────────────────────────────────────────
function main() {
  const cfg = parseArgs(process.argv.slice(2));
  const code = fs.readFileSync(cfg.input, 'utf-8');

  const sandbox = {
    setTimeout: (cb) => { try { if (typeof cb === 'function') cb(); } catch(e) {} return 1; },
    setInterval: () => 1, clearTimeout: () => {}, clearInterval: () => {},
    window: mkProxy('window', {}),
    document: mkProxy('document', { cookie: '', createElement: () => mkProxy('e'), querySelector: () => null, head: mkProxy('head'), body: mkProxy('body') }),
    navigator: mkProxy('navigator', { userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36', languages: ['zh-CN','zh'], platform: 'Win32', webdriver: false, plugins: mkProxy('plugins'), hardwareConcurrency: 8, cookieEnabled: true }),
    screen: { width: 1920, height: 1080, colorDepth: 24 },
    crypto, Math, Date, ArrayBuffer,
    Uint8Array, Int8Array, Uint16Array, Int16Array, Uint32Array, Int32Array,
    Float32Array, Float64Array,
    TextEncoder: class { encode(s) { return Buffer.from(s); } },
    TextDecoder: class { decode(b) { return Buffer.from(b).toString(); } },
    btoa: s => Buffer.from(s).toString('base64'),
    atob: s => Buffer.from(s, 'base64').toString(),
    XMLHttpRequest: class { open(){} send(){} },
    Image: class { constructor() { setTimeout(() => this.onload && this.onload(), 0); } },
    Element: mkProxy('Element'), Node: mkProxy('Node'),
    HTMLElement: mkProxy('HTMLElement'), EventTarget: mkProxy('EventTarget'),
    __TRACE_LOG__: cfg.inst ? [] : undefined,
  };

  const ctx = vm.createContext(sandbox);

  if (cfg.inst) {
    vm.runInContext(`globalThis.__trace=function(t,i){__TRACE_LOG__.push((t<<16)|i)};`, ctx);
  }

  if (cfg.freeze) {
    vm.runInContext(`Date.now=()=>1700000000000;Date.prototype.getTime=()=>1700000000000;Math.random=()=>0.123456789;`, ctx);
  }

  // Execute
  let execError = null;
  try { vm.runInContext(code, ctx, { filename: path.basename(cfg.input) }); }
  catch(e) { execError = { message: e.message, stack: (e.stack||'').split('\n').slice(0,5).join(' | ') }; }

  // Sign / entry invocation
  let h5st = null, entryError = null, entryFound = false;
  const entryExpr = cfg.entry || 'window.ParamsSign.sign';
  try {
    const resolved = resolveEntry(sandbox, entryExpr);
    if (resolved) {
      entryFound = true;
      const r = resolved.fn.call(resolved.receiver, { test: 1 });
      if (r && typeof r === 'object') h5st = r.h5st || null;
    }
  } catch(e) { entryError = { message: e.message, stack: (e.stack||'').split('\n').slice(0,5).join(' | ') }; }

  // Trace
  let traceSummary = null;
  if (cfg.inst && sandbox.__TRACE_LOG__ && sandbox.__TRACE_LOG__.length > 0) {
    const raw = sandbox.__TRACE_LOG__;
    const seq = [], freq = {};
    for (const v of raw) { const id = v & 0xFFFF; seq.push(id); freq[id] = (freq[id]||0)+1; }
    const top20 = Object.entries(freq).sort((a,b)=>b[1]-a[1]).slice(0,20).map(([id,c])=>({ id:+id, count:c }));
    traceSummary = { total_traces: raw.length, unique_cases: Object.keys(freq).length, top_20: top20 };

    const traceOut = cfg.traceOut || path.join(path.dirname(cfg.input), 'trace_report.json');
    fs.writeFileSync(traceOut, JSON.stringify({ total_traces: raw.length, unique_cases: Object.keys(freq).length, case_sequence: seq, case_frequency: freq, top_20: top20 }, null, 2));
  }

  const report = {
    status: execError ? 'script_error' : (entryError ? 'entry_error' : 'ok'),
    entry_expr: entryExpr, entry_found: entryFound,
    input_file: cfg.input, file_size: code.length,
    freeze: cfg.freeze, inst: cfg.inst,
    exec_error: execError, entry_error: entryError, h5st,
    trace: traceSummary,
  };

  if (cfg.json) console.log(JSON.stringify(report));
  else {
    console.log(`[runner] ${cfg.input}  Status: ${report.status}  Size: ${code.length}B`);
    if (!entryFound && !entryError) console.log(`  entry not found: ${entryExpr} (no traces will be produced)`);
    if (h5st) console.log(`  h5st: ${h5st.substring(0,80)}...`);
    if (traceSummary) console.log(`  Trace: ${traceSummary.total_traces} steps, ${traceSummary.unique_cases} unique`);
  }
}
main();
