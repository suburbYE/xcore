#!/usr/bin/env node
/**
 * pipeline_native.js — Phase 4c: Full Pipeline (4a → 4b → 4c)
 *
 * One-shot command to go from APK → Shell Classification → .so Extraction →
 * Target Scanning → Probe Script Generation.
 *
 * Usage:
 *   node pipeline_native.js --apk <path> [--output-dir <dir>] [--spawn]
 */

"use strict";

const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");

const SCRIPT_DIR = __dirname;
const NODE = process.execPath;

// ─── Parse arguments ─────────────────────────────────────────────────────────
function parseArgs() {
  const args = process.argv.slice(2);
  const opts = { apk: null, outputDir: null, spawn: false };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--apk" && i + 1 < args.length) opts.apk = args[++i];
    else if (args[i] === "--output-dir" && i + 1 < args.length) opts.outputDir = args[++i];
    else if (args[i] === "--spawn") opts.spawn = true;
  }
  if (!opts.apk) {
    console.error("Usage: node pipeline_native.js --apk <path> [--output-dir <dir>] [--spawn]");
    process.exit(1);
  }
  return opts;
}

// ─── Stage 1: Shell Classification (Phase 4a) ────────────────────────────────
function runClassifier(apkPath, outputDir) {
  console.error("[pipeline] Stage 1/4: Shell classification (Phase 4a)...");

  const args = ["--apk", apkPath, "--mode", "active", "--json"];
  let out;
  try {
    out = execFileSync(NODE, [path.join(SCRIPT_DIR, "shell_classifier.js"), ...args], {
      encoding: "utf8",
      timeout: 120000,
      maxBuffer: 10 * 1024 * 1024
    });
  } catch (e) {
    // shell_classifier exits non-zero on heavy_shell; output is still valid
    out = (e.stdout || "") + (e.stderr || "");
    if (!out.trim()) throw e;
  }

  // Parse JSON from output
  const cleaned = out.replace(/\r/g, "");
  const braceStart = cleaned.indexOf("{");
  if (braceStart === -1) {
    console.error("[pipeline] ERROR: shell_classifier output is not valid JSON");
    console.error(cleaned.substring(0, 500));
    return null;
  }

  let depth = 0;
  let braceEnd = -1;
  for (let i = braceStart; i < cleaned.length; i++) {
    if (cleaned[i] === "{") depth++;
    else if (cleaned[i] === "}") { depth--; if (depth === 0) { braceEnd = i; break; } }
  }

  if (braceEnd === -1) {
    console.error("[pipeline] ERROR: Unmatched JSON braces");
    return null;
  }

  const jsonStr = cleaned.substring(braceStart, braceEnd + 1);
  const result = JSON.parse(jsonStr);

  // Save classify result
  const classifyPath = path.join(outputDir, "classify_result.json");
  fs.mkdirSync(outputDir, { recursive: true });
  fs.writeFileSync(classifyPath, jsonStr, "utf8");

  console.error("[pipeline]   Shell: " + (result.shell && result.shell.name) || "unknown");
  console.error("[pipeline]   Class: " + (result.recommendation || "unknown"));
  console.error("[pipeline]   Saved: " + classifyPath);

  return result;
}

// ─── Stage 2: Extract .so files from APK ─────────────────────────────────────
function extractSos(apkPath, outputDir) {
  console.error("[pipeline] Stage 2/4: Extracting .so files...");

  const libsDir = path.join(outputDir, "libs");
  fs.mkdirSync(libsDir, { recursive: true });

  let extracted = [];

  // Primary: adm-zip (fast, pure JS)
  try {
    const AdmZip = require("adm-zip");
    const zip = new AdmZip(apkPath);
    const entries = zip.getEntries();
    for (const entry of entries) {
      const entryName = entry.entryName;
      if (entryName.endsWith(".so") && !entryName.startsWith("META-INF")) {
        const soName = path.basename(entryName);
        const destPath = path.join(libsDir, soName);
        if (!fs.existsSync(destPath)) {
          fs.writeFileSync(destPath, entry.getData());
        }
        extracted.push(destPath);
      }
    }
  } catch (admErr) {
    console.error("[pipeline]   WARNING: adm-zip failed: " + admErr.message + " — trying PowerShell fallback");

    // PowerShell fallback using .ps1 temp script
    const { execFileSync: efs } = require("child_process");
    try {
      const psListPath = path.join(outputDir, "_list_so.ps1");
      const psList = [
        'Add-Type -AssemblyName System.IO.Compression.FileSystem',
        '$z = [System.IO.Compression.ZipFile]::OpenRead("' + apkPath.replace(/\\/g, "\\\\") + '")',
        'foreach ($e in $z.Entries) { if ($e.FullName -match "\\\\.so$") { Write-Output $e.FullName } }',
        '$z.Dispose()'
      ].join('\n');
      fs.writeFileSync(psListPath, psList, "utf8");

      const listOut = efs("powershell", ["-NoProfile", "-File", psListPath], {
        encoding: "utf8", timeout: 60000, maxBuffer: 10 * 1024 * 1024
      });
      fs.unlinkSync(psListPath);

      const soPaths = listOut.split(/\r?\n/).filter(s => s.trim().endsWith(".so"));
      for (const soEntry of soPaths) {
        const cleanEntry = soEntry.trim();
        const soName = path.basename(cleanEntry);
        const destPath = path.join(libsDir, soName);

        const psExtractPath = path.join(outputDir, "_extract_so.ps1");
        const psExtract = [
          'Add-Type -AssemblyName System.IO.Compression.FileSystem',
          '$z = [System.IO.Compression.ZipFile]::OpenRead("' + apkPath.replace(/\\/g, "\\\\") + '")',
          '$e = $z.GetEntry("' + cleanEntry.replace(/\\/g, "/") + '")',
          'if ($e) { $s = $e.Open(); $fs = [System.IO.File]::Create("' + destPath.replace(/\\/g, "\\\\") + '"); $s.CopyTo($fs); $fs.Close(); $s.Close(); Write-Output "OK" } else { Write-Output "MISSING" }',
          '$z.Dispose()'
        ].join('\n');
        fs.writeFileSync(psExtractPath, psExtract, "utf8");

        try {
          efs("powershell", ["-NoProfile", "-File", psExtractPath], {
            encoding: "utf8", timeout: 120000, maxBuffer: 100 * 1024 * 1024
          });
          extracted.push(destPath);
        } catch (extractErr) {
          console.error("[pipeline]   WARNING: Failed to extract " + soName + ": " + extractErr.message);
        }
        try { fs.unlinkSync(psExtractPath); } catch (_) {}
      }
    } catch (psErr) {
      console.error("[pipeline]   ERROR: PowerShell fallback also failed: " + psErr.message);
    }
  }

  console.error("[pipeline]   Extracted " + extracted.length + " .so files to " + libsDir);
  return extracted;
}

// ─── Stage 3: Target Scanning (Phase 4b) ─────────────────────────────────────
function runTargetScanner(soPaths, outputDir) {
  console.error("[pipeline] Stage 3/4: Target scanning (Phase 4b)...");

  const scanDir = path.join(outputDir, "scan_results");
  fs.mkdirSync(scanDir, { recursive: true });

  const results = [];
  for (const soPath of soPaths) {
    const soName = path.basename(soPath);
    console.error("[pipeline]   Scanning " + soName + "...");

    try {
      const out = execFileSync(NODE, [
        path.join(SCRIPT_DIR, "target_scanner.js"),
        "--so", soPath,
        "--json"
      ], {
        encoding: "utf8",
        timeout: 300000,
        maxBuffer: 10 * 1024 * 1024
      });

      let jsonStr = out.trim();
      // Clean up any stderr noise before JSON
      const braceStart = jsonStr.indexOf("{");
      if (braceStart > 0) jsonStr = jsonStr.substring(braceStart);
      if (braceStart === -1) {
        console.error("[pipeline]   WARNING: " + soName + " returned no JSON");
        continue;
      }

      const scanResult = JSON.parse(jsonStr);
      const outPath = path.join(scanDir, soName.replace(/\.so$/, ".json"));
      fs.writeFileSync(outPath, jsonStr, "utf8");

      console.error("[pipeline]     Score: " + scanResult.final_score + "  Verdict: " + scanResult.verdict);
      results.push({ soPath, soName, scanResult, jsonPath: outPath });
    } catch (e) {
      console.error("[pipeline]   ERROR scanning " + soName + ": " + e.message);
    }
  }

  return results;
}

// ─── Stage 4: Probe Generation (Phase 4c) ────────────────────────────────────
function runProbeGenerator(scanResults, outputDir, spawnMode) {
  console.error("[pipeline] Stage 4/4: Probe generation (Phase 4c)...");

  const probeDir = path.join(outputDir, "probes");
  fs.mkdirSync(probeDir, { recursive: true });

  const generated = [];

  for (const sr of scanResults) {
    // Only generate probes for .so with score >= 0.4
    if (sr.scanResult.final_score < 0.4) {
      console.error("[pipeline]   Skipping " + sr.soName + " (score " + sr.scanResult.final_score + " < 0.4)");
      continue;
    }

    const probeName = "probe_" + sr.soName.replace(/\.so$/, ".js");
    const probePath = path.join(probeDir, probeName);
    const targetLib = sr.soName;

    const args = [
      path.join(SCRIPT_DIR, "probe_generator.js"),
      "--scan-result", sr.jsonPath,
      "--out", probePath,
      "--target-lib", targetLib
    ];
    if (spawnMode) args.push("--spawn");

    try {
      execFileSync(NODE, args, {
        encoding: "utf8",
        timeout: 60000,
        maxBuffer: 10 * 1024 * 1024
      });
      generated.push({ soName: sr.soName, probeName, probePath, score: sr.scanResult.final_score });
    } catch (e) {
      console.error("[pipeline]   ERROR generating probe for " + sr.soName + ": " + e.message);
    }
  }

  console.error("[pipeline]   Generated " + generated.length + " probe scripts in " + probeDir);
  return generated;
}

// ─── Summary ─────────────────────────────────────────────────────────────────
function writeSummary(classifyResult, scanResults, probeResults, outputDir) {
  const summary = {
    pipeline: "xcore Phase 4c v0.18.0",
    timestamp: new Date().toISOString(),
    input_apk: path.basename(process.argv.find((a, i) => a === "--apk" && process.argv[i + 1]) ? process.argv[process.argv.indexOf("--apk") + 1] : "?"),
    shell: {
      name: (classifyResult && classifyResult.shell && classifyResult.shell.name) || "unknown",
      class: (classifyResult && classifyResult.recommendation) || "unknown",
      confidence: (classifyResult && classifyResult.shell && classifyResult.shell.confidence) || "none"
    },
    targets_scanned: scanResults.length,
    probes_generated: probeResults.length,
    so_targets: scanResults.map(sr => ({
      name: sr.soName,
      score: sr.scanResult.final_score,
      verdict: sr.scanResult.verdict,
      algorithm: sr.scanResult.algorithm || "unknown"
    })),
    probes: probeResults.map(pr => ({
      so: pr.soName,
      script: pr.probeName,
      score: pr.score
    }))
  };

  const summaryPath = path.join(outputDir, "summary.json");
  fs.writeFileSync(summaryPath, JSON.stringify(summary, null, 2), "utf8");

  return summary;
}

// ─── Main ────────────────────────────────────────────────────────────────────
function main() {
  const opts = parseArgs();
  const outputDir = opts.outputDir || path.join(path.dirname(opts.apk), "xcore_pipeline_output");

  console.error("══════════════════════════════════════");
  console.error(" xcore Phase 4c Native Pipeline");
  console.error(" APK: " + opts.apk);
  console.error(" Output: " + outputDir);
  console.error(" Spawn: " + (opts.spawn ? "YES" : "NO"));
  console.error("══════════════════════════════════════\n");

  // Stage 1: Classify
  const classifyResult = runClassifier(opts.apk, outputDir);
  if (!classifyResult) {
    console.error("[pipeline] ABORTED: Shell classification failed");
    process.exit(1);
  }

  const rec = classifyResult.recommendation || "";
  if (rec === "heavy_shell" || rec === "unknown") {
    console.error("\n[pipeline] WARNING: Shell type is '" + rec + "'. .so extraction may not be available.");
    console.error("[pipeline] Proceeding with best-effort extraction anyway.\n");
  }

  // Stage 2: Extract .so
  const soPaths = extractSos(opts.apk, outputDir);
  if (soPaths.length === 0) {
    console.error("[pipeline] ABORTED: No .so files extracted from APK");
    // Still output summary
    const summary = writeSummary(classifyResult, [], [], outputDir);
    console.error("\n[pipeline] Summary: " + path.join(outputDir, "summary.json"));
    process.exit(2);
  }

  // Stage 3: Scan
  const scanResults = runTargetScanner(soPaths, outputDir);

  // Stage 4: Generate probes
  const probeResults = runProbeGenerator(scanResults, outputDir, opts.spawn);

  // Write summary
  const summary = writeSummary(classifyResult, scanResults, probeResults, outputDir);

  // Final output
  console.log(JSON.stringify({
    status: "complete",
    output_dir: outputDir,
    shell: summary.shell,
    targets_scanned: summary.targets_scanned,
    probes_generated: summary.probes_generated,
    summary_file: path.join(outputDir, "summary.json")
  }, null, 2));
}

main();
