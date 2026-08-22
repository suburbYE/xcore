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
  const cfg = { input: null, traceOut: null, inst: false, freeze: false, json: false };
  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--input':     cfg.input    = args[++i]; break;
      case '--trace-out': cfg.traceOut = args[++i]; break;
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
function mkProxy(name, defaults = {}) {
  return new Proxy(Object.assign({}, defaults), {
    get(t, p) {
      if (p in t) return t[p];
      if (typeof p === 'string' && p !== 'then' && p !== Symbol.toPrimitive) {
        if (p.endsWith('_')) return undefined;
        const mock = () => {}; t[p] = mock; return mock;
      }
      return undefined;
    },
    set(t, p, v) { t[p] = v; return true; },
    has() { return true; },
  });
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

  // Sign
  let h5st = null, entryError = null;
  if (!execError && sandbox.window.ParamsSign) {
    try {
      const inst = new sandbox.window.ParamsSign();
      const r = inst.signSync ? inst.signSync({ test: 1 }) : inst.sign({ test: 1 });
      if (r && typeof r === 'object') h5st = r.h5st || null;
    } catch(e) { entryError = { message: e.message, stack: (e.stack||'').split('\n').slice(0,5).join(' | ') }; }
  }

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
    input_file: cfg.input, file_size: code.length,
    freeze: cfg.freeze, inst: cfg.inst,
    exec_error: execError, entry_error: entryError, h5st,
    trace: traceSummary,
  };

  if (cfg.json) console.log(JSON.stringify(report));
  else {
    console.log(`[runner] ${cfg.input}  Status: ${report.status}  Size: ${code.length}B`);
    if (h5st) console.log(`  h5st: ${h5st.substring(0,80)}...`);
    if (traceSummary) console.log(`  Trace: ${traceSummary.total_traces} steps, ${traceSummary.unique_cases} unique`);
  }
}
main();
