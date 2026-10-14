#!/usr/bin/env node
/**
 * pipeline_web.js - Web 分析全链路编排
 * Phase 5w: Web 分析模块 - 一键流水线
 *
 * Usage:
 *   node pipeline_web.js --url <https://...> --out <dir> [--depth <n>] [--json]
 *   node pipeline_web.js --html <local.html> --out <dir> [--json]
 *
 * 流程：
 *   Stage 1: web_fetcher 抓取页面 + 提取脚本/端点
 *   Stage 2: api_probe 对抓到的 JS/HTML 做签名/参数探测
 *   Stage 3: wasm_analyzer 对抓到的 .wasm 做结构分析
 *   输出：统一 JSON 报告 + 文件落盘清单
 */

"use strict";

const fs = require("fs");
const path = require("path");
const { fetchBinary, analyzeHtml } = require("./web_fetcher.js");
const { probeText } = require("./api_probe.js");
const { analyzeWasm } = require("./wasm_analyzer.js");
const { analyzeJsvmText } = require("./jsvm_analyzer.js");

function parseArgs(argv) {
  const args = { url: "", html: "", out: "", depth: 1, json: false };
  for (let i = 0; i < argv.length; i++) {
    switch (argv[i]) {
      case "--url": args.url = argv[++i] || ""; break;
      case "--html": args.html = argv[++i] || ""; break;
      case "--out": args.out = argv[++i] || ""; break;
      case "--depth": args.depth = parseInt(argv[++i], 10) || 1; break;
      case "--json": args.json = true; break;
    }
  }
  return args;
}

/**
 * 本地 HTML 模式下把 <script src> 的原始引用解析成磁盘路径。
 * 远程引用（http/https/协议相对）返回 null，交给 fetchBinary 处理。
 * `/static/app.js` 这类站点绝对路径按 HTML 所在目录解析——文件系统里没有
 * 「web 根」的概念，按 URL 语义会得到 file:///C:/static/app.js 这种废路径。
 */
function resolveLocalScript(rawSrc, htmlDir) {
  const s = String(rawSrc || "").trim();
  if (!s) return null;
  if (/^[a-z][a-z0-9+.-]*:/i.test(s)) return null; // http: https: data: file: ...
  if (s.startsWith("//")) return null;             // 协议相对 → 远程
  const clean = s.split("?")[0].split("#")[0];
  if (!clean) return null;
  return path.resolve(htmlDir, clean.replace(/^[/\\]+/, ""));
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.url && !args.html) {
    console.error("[!] Usage: node pipeline_web.js --url <url> | --html <path> --out <dir> [--depth <n>] [--json]");
    process.exit(1);
  }
  // 默认落到 <project_root>/temp/web_out，绝不用 cwd（否则会把 index.html 扔进项目根目录）
  const outDir = path.resolve(args.out || path.join(__dirname, "..", "..", "temp", "web_out"));
  fs.mkdirSync(outDir, { recursive: true });

  const report = { startedAt: new Date().toISOString(), source: args.url || args.html, stages: {}, artifacts: [] };

  // Stage 1: fetch
  let htmlText, baseUrl, localHtml;
  if (args.url) {
    const res = await fetchBinary(args.url);
    baseUrl = res.url || args.url;
    const buf = res.body;
    // 保存原始抓取结果
    const ext = path.extname(new URL(baseUrl).pathname).toLowerCase();
    if (ext === ".wasm" || ext === ".js") {
      const fp = path.join(outDir, path.basename(new URL(baseUrl).pathname));
      fs.writeFileSync(fp, buf);
      report.artifacts.push(fp);
      // 资源类直接进入对应分析
      if (ext === ".wasm") {
        report.stages.wasm = analyzeWasm(fp);
      } else {
        report.stages.probe = probeText(buf.toString("utf8"), fp);
      }
      report.artifacts = [...new Set(report.artifacts)];
      console.log(JSON.stringify(report, null, 2));
      return;
    }
    htmlText = buf.toString("utf8");
  } else {
    htmlText = fs.readFileSync(args.html, "utf8");
    baseUrl = "file://" + path.resolve(args.html).replace(/\\/g, "/");
    localHtml = path.resolve(args.html);
  }

  // 仅 URL 模式留档：本地 HTML 已存在于磁盘，再复制一份既无意义又会污染 outDir
  if (args.url) {
    const htmlPath = path.join(outDir, "index.html");
    fs.writeFileSync(htmlPath, htmlText);
    report.artifacts.push(htmlPath);
  }

  const parsed = analyzeHtml(htmlText, baseUrl);
  report.stages.fetch = { scripts: parsed.scripts, inlineScripts: parsed.inlineScripts.length, endpoints: parsed.endpoints, forms: parsed.forms };

  // Stage 2: 对页面内联脚本做 api_probe + jsvm 分析
  const allJs = [...parsed.inlineScripts];
  const hits = [];
  const jsvmReports = [];
  for (const js of allJs) {
    hits.push(...probeText(js, "inline:<page>"));
    const jr = analyzeJsvmText(js, "inline:<page>");
    if (jr.found || (jr.generic && jr.generic.length)) jsvmReports.push(...jr.runtimes.map(rt => ({ source: jr.source, ...rt })), ...(jr.generic || []).map(g => ({ source: jr.source, mode: g.mode, opcodeCount: g.opcodeCount, version: g.version })));
  }
  report.stages.jsvm = { runtimes: jsvmReports.length, details: jsvmReports };
  // Stage 3: 外链脚本 + wasm 分析
  // 本地模式读磁盘（相对 HTML 目录解析），URL 模式才走网络
  const wasmReports = [];
  const htmlDir = localHtml ? path.dirname(localHtml) : null;
  for (let i = 0; i < parsed.scripts.length; i++) {
    const s = parsed.scripts[i];
    const rawSrc = (parsed.rawScripts || [])[i] || s;
    const isWasm = /\.wasm(\?|$)/.test(localHtml ? rawSrc : s);
    try {
      let jsText = null, wasmPath = null, label = s;

      if (localHtml) {
        const lp = resolveLocalScript(rawSrc, htmlDir);
        if (!lp) throw new Error(`remote reference in local HTML mode: ${rawSrc}`);
        if (!fs.existsSync(lp)) throw new Error(`local script not found: ${lp}`);
        label = lp;
        if (isWasm) wasmPath = lp;
        else jsText = fs.readFileSync(lp, "utf8");
      } else {
        const res = await fetchBinary(s);
        const fp = path.join(outDir, path.basename(new URL(s).pathname) || (isWasm ? "resource.wasm" : "script.js"));
        fs.writeFileSync(fp, res.body);
        report.artifacts.push(fp);
        label = fp;
        if (isWasm) wasmPath = fp;
        else jsText = res.body.toString("utf8");
      }

      if (isWasm) {
        wasmReports.push({ url: s, ...analyzeWasm(wasmPath) });
      } else {
        hits.push(...probeText(jsText, label));
        const jr = analyzeJsvmText(jsText, label);
        if (jr.found || (jr.generic && jr.generic.length)) jsvmReports.push(...jr.runtimes.map(rt => ({ source: jr.source, ...rt })), ...(jr.generic || []).map(g => ({ source: jr.source, mode: g.mode, opcodeCount: g.opcodeCount, version: g.version })));
      }
    } catch (e) {
      report.stages.fetch.failedScripts = report.stages.fetch.failedScripts || [];
      report.stages.fetch.failedScripts.push({ url: s, error: e.message });
    }
  }
  report.stages.probe = { files: parsed.scripts.length + 1, hits };
  report.stages.wasm = wasmReports;
  report.artifacts = [...new Set(report.artifacts)];
  report.stages.jsvm.runtimes = jsvmReports.length;
  report.stages.jsvm.details = jsvmReports;

  const out = args.json ? JSON.stringify(report, null, 2) : (() => {
    const lines = [];
    lines.push(`[+] pipeline done: ${args.url || args.html}`);
    lines.push(`    endpoints: ${parsed.endpoints.length}, probe hits: ${hits.length}, wasm: ${wasmReports.length}, jsvm: ${jsvmReports.length}`);
    if (parsed.endpoints.length) lines.push("    endpoints: " + parsed.endpoints.slice(0, 15).join(", "));
    if (hits.length) {
      lines.push("    top hits:");
      for (const h of hits.slice(0, 10)) lines.push(`      ${h.file}:${h.line} [${h.kinds.join(",")}] ${h.code}`);
    }
    for (const w of wasmReports) lines.push(`    wasm: ${w.url} sections=[${w.sections.map(s => s.name).join(",")}] exports=${w.exports.length}`);
    for (const j of jsvmReports) {
      if (j.mode) lines.push(`    jsvm: ${j.source} [${j.mode}] opcodes=${j.opcodeCount}${j.version ? ` version=${j.version}` : ""}`);
      else lines.push(`    jsvm: ${j.source} ${j.size}B magic=${j.magic} xor_key=${j.key} strings=${j.stringTable.count} algos=[${j.algorithms.map(a => a.name).join(",")}]`);
    }
    lines.push(`    artifacts: ${report.artifacts.join(", ")}`);
    return lines.join("\n");
  })();
  console.log(out);
}

if (require.main === module) main();
module.exports = {};
