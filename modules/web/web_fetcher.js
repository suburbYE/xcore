#!/usr/bin/env node
/**
 * web_fetcher.js - Web 页面抓取与结构分析
 * Phase 5w: Web 分析模块 - 采集端
 *
 * Usage:
 *   node web_fetcher.js --url <https://...> [--out <dir>] [--depth <n>] [--json]
 *   node web_fetcher.js --file <local.html> [--out <dir>] [--json]
 *
 * 流程：
 *   1. 抓取目标 URL（HTML/JS/WASM 通用下载）
 *   2. 解析 HTML：提取 <script src> 外链、内联脚本、表单端点、隐藏字段
 *   3. 按 --depth 递归抓取子资源（默认 1：仅页面自身）
 *   4. 输出资源清单 + 端点发现结果
 */

"use strict";

const fs = require("fs");
const path = require("path");
const http = require("http");
const https = require("https");
const { URL } = require("url");

const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36";
const RESOURCE_EXTS = new Set([".js", ".wasm", ".css", ".json"]);

// ─── CLI 解析 ────────────────────────────────────────────────
function parseArgs(argv) {
  const args = { url: "", file: "", out: "", depth: 1, json: false };
  for (let i = 0; i < argv.length; i++) {
    switch (argv[i]) {
      case "--url": args.url = argv[++i] || ""; break;
      case "--file": args.file = argv[++i] || ""; break;
      case "--out": args.out = argv[++i] || ""; break;
      case "--depth": args.depth = parseInt(argv[++i], 10) || 1; break;
      case "--json": args.json = true; break;
    }
  }
  return args;
}

// ─── HTTP 抓取（带 UA / 重定向 / 超时）────────────────────
function fetchBinary(urlStr, timeoutMs = 20000, redirects = 5) {
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(urlStr); } catch (e) { return reject(new Error("invalid url")); }
    const mod = u.protocol === "https:" ? https : http;
    const req = mod.get(u, {
      headers: {
        "User-Agent": UA,
        "Accept": "*/*",
        "Accept-Language": "zh-CN,zh;q=0.9",
      },
      timeout: timeoutMs,
    }, (res) => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && redirects > 0 && res.headers.location) {
        res.resume();
        return resolve(fetchBinary(new URL(res.headers.location, u).href, timeoutMs, redirects - 1));
      }
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode}`));
      }
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ url: res.url || urlStr, status: res.statusCode, contentType: res.headers["content-type"] || "", body: Buffer.concat(chunks) }));
    });
    req.on("timeout", () => { req.destroy(new Error("timeout")); });
    req.on("error", reject);
  });
}

// ─── HTML 结构分析 ─────────────────────────────────────────
function analyzeHtml(html, baseUrl) {
  const out = { scripts: [], rawScripts: [], inlineScripts: [], forms: [], links: [], endpoints: [] };
  // 先整标签匹配，再从属性区提取 src，避免非贪婪跳过带其他属性的 script 标签
  const scriptRe = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
  let m;
  while ((m = scriptRe.exec(html)) !== null) {
    const srcM = /src\s*=\s*["']([^"']+)["']/i.exec(m[1]);
    if (srcM) {
      // scripts 保留绝对 URL（网络模式用）；rawScripts 保留原样引用（本地模式还原磁盘路径用）。
      // 两者同成功同失败，索引一一对应。
      try {
        out.scripts.push(new URL(srcM[1], baseUrl).href);
        out.rawScripts.push(srcM[1]);
      } catch (e) { /* ignore */ }
    } else if (m[2] && m[2].trim()) {
      out.inlineScripts.push(m[2].trim());
    }
  }
  const formRe = /<form\b[^>]*action\s*=\s*["']([^"']*)["'][^>]*>/gi;
  while ((m = formRe.exec(html)) !== null) {
    out.forms.push({ action: new URL(m[1], baseUrl).href, fields: [] });
    const fieldRe = /<input\b[^>]*name\s*=\s*["']([^"']+)["']/g;
    let f;
    while ((f = fieldRe.exec(html.slice(m.index, html.indexOf("</form>", m.index) > -1 ? html.indexOf("</form>", m.index) : html.length)))) {
      out.forms[out.forms.length - 1].fields.push(f[1]);
    }
  }
  const linkRe = /<link\b[^>]*href\s*=\s*["']([^"']+)["']/gi;
  while ((m = linkRe.exec(html)) !== null) {
    try { out.links.push(new URL(m[1], baseUrl).href); } catch (e) { /* ignore */ }
  }
  // 端点启发式：API 路径 / 签名路径
  const epRe = /["'](\/(?:api|v\d|ajax|gateway|rest|sdk)[^"'\s?]*)["']/gi;
  while ((m = epRe.exec(html)) !== null) {
    if (!out.endpoints.includes(m[1])) out.endpoints.push(m[1]);
  }
  return out;
}

// ─── 主流程 ────────────────────────────────────────────────
async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.url && !args.file) {
    console.error("[!] Usage: node web_fetcher.js --url <url> | --file <path> [--out <dir>] [--depth <n>] [--json]");
    process.exit(1);
  }
  const outDir = path.resolve(args.out || ".");
  fs.mkdirSync(outDir, { recursive: true });

  const report = { source: args.url || args.file, fetchedAt: new Date().toISOString(), resources: [], endpoints: [] };

  try {
    let htmlBuf, finalUrl;
    if (args.url) {
      const res = await fetchBinary(args.url);
      htmlBuf = res.body;
      finalUrl = res.url || args.url;
      const ext = path.extname(new URL(finalUrl).pathname).toLowerCase();
      if (ext === ".js" || ext === ".wasm" || (RESOURCE_EXTS.has(ext) && !ext)) {
        // 非 HTML 资源直接落盘
        const name = path.basename(new URL(finalUrl).pathname) || "resource.bin";
        const fp = path.join(outDir, name);
        fs.writeFileSync(fp, htmlBuf);
        report.resources.push({ url: finalUrl, savedTo: fp, bytes: htmlBuf.length, type: res.contentType });
        if (args.json) {
          console.log(JSON.stringify(report, null, 2));
        } else {
          console.log(`[+] ${finalUrl} -> ${fp} (${htmlBuf.length} bytes)`);
        }
        return;
      }
      htmlBuf = htmlBuf.toString("utf8");
      const htmlPath = path.join(outDir, "index.html");
      fs.writeFileSync(htmlPath, htmlBuf);
      report.resources.push({ url: finalUrl, savedTo: htmlPath, bytes: htmlBuf.length, type: res.contentType });

      const parsed = analyzeHtml(htmlBuf, finalUrl);
      for (const s of parsed.scripts) {
        report.endpoints.push(s);
        if (args.depth > 1) {
          try {
            const sres = await fetchBinary(s);
            const sp = path.join(outDir, path.basename(new URL(s).pathname) || "script.js");
            fs.writeFileSync(sp, sres.body);
            report.resources.push({ url: s, savedTo: sp, bytes: sres.body.length, type: sres.contentType });
          } catch (e) {
            report.resources.push({ url: s, error: e.message });
          }
        }
      }
      report.endpoints.push(...parsed.endpoints);
      report.forms = parsed.forms;
      report.links = parsed.links.slice(0, 50);
    } else {
      htmlBuf = fs.readFileSync(args.file, "utf8");
      finalUrl = "file://" + path.resolve(args.file).replace(/\\/g, "/");
      const parsed = analyzeHtml(htmlBuf, finalUrl);
      // 本地模式下相对链接不做 URL 归一（保留原始 href 即可）
      report.resources.push({ local: args.file, bytes: htmlBuf.length });
      report.endpoints.push(...parsed.endpoints);
      report.forms = parsed.forms;
      report.links = parsed.links.filter(l => !l.startsWith("file://")).slice(0, 50);
    }

    if (args.json) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      console.log(`[+] fetched: ${finalUrl}`);
      console.log(`[+] resources: ${report.resources.length}, endpoints: ${report.endpoints.length}`);
      if (report.endpoints.length) {
        console.log("    endpoints:");
        for (const ep of report.endpoints.slice(0, 20)) console.log("      " + ep);
      }
    }
  } catch (e) {
    console.error(`[!] fetch failed: ${e.message}`);
    process.exit(1);
  }
}

if (require.main === module) main();
module.exports = { fetchBinary, analyzeHtml, parseArgs };
