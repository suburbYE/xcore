/**
 * Phase 3a: Target Scoring Engine
 * 
 * Usage: node scorer.js <directory_path>
 * 
 * Scores all .js files in a directory for crypto/obfuscation relevance.
 * Files with score < 30 are filtered out.
 * Outputs JSON array to stdout, sorted by score descending.
 */

const fs = require('fs');
const path = require('path');

// ─── Weights ─────────────────────────────────────────────
const WL2      = 0.40;
const WEntropy = 0.30;
const WKW      = 0.20;
const WSize    = 0.10;

// ─── Keywords ────────────────────────────────────────────
const KEYWORDS = [
  'sign', 'encrypt', 'h5st', '_$sdnmd', 'ParamsSign',
  'token', 'TK', 'fingerprint', 'fp', 'digest',
  'hmac', 'sha256', 'md5'
];

// ─── Helpers ─────────────────────────────────────────────

/** Count nested call expressions via regex: f(g(h(...))) patterns */
function computeSL2(code) {
  const pattern = /\w+\(\s*\w+\s*\(/g;
  const matches = code.match(pattern);
  if (!matches) return 0;
  // Normalize: divide by total lines to get density (0-1 range, cap at 1)
  const lines = code.split('\n').length;
  const density = matches.length / Math.max(lines, 1);
  return Math.min(density, 1.0);
}

/** Compute coefficient of variation for array literal lengths */
function computeSEntropy(code) {
  // Find all var xxx = [...]; or let xxx = [...]; or xxx = [...];
  const arrayPattern = /(?:var|let|const)\s+\w+\s*=\s*\[([^\]]*)\]/g;
  const lengths = [];
  let m;
  while ((m = arrayPattern.exec(code)) !== null) {
    const inner = m[1].trim();
    if (inner === '') {
      lengths.push(0);
    } else {
      // Count elements by splitting on commas (naive but sufficient)
      lengths.push(inner.split(',').length);
    }
  }
  if (lengths.length < 2) return 0;
  const mean = lengths.reduce((a, b) => a + b, 0) / lengths.length;
  if (mean === 0) return 0;
  const variance = lengths.reduce((s, v) => s + (v - mean) ** 2, 0) / lengths.length;
  const stddev = Math.sqrt(variance);
  const cv = stddev / mean;
  // Map CV to 0-1: CV of 2.0+ maps to 1.0
  return Math.min(cv / 2.0, 1.0);
}

/** Compute keyword hit rate */
function computeSKW(code) {
  const codeLower = code.toLowerCase();
  const found = new Set();
  for (const kw of KEYWORDS) {
    if (codeLower.includes(kw.toLowerCase())) {
      found.add(kw.toLowerCase());
    }
  }
  // Each unique keyword hit adds 0.05, max 1.0
  return Math.min(found.size * 0.05, 1.0);
}

/** Compute normalized file size penalty */
function computePSize(fileSizeBytes) {
  // 100KB+ → 1.0, 10KB以下 → 0, 中间线性
  const kb = fileSizeBytes / 1024;
  if (kb >= 100) return 1.0;
  if (kb <= 10) return 0.0;
  return (kb - 10) / 90; // linear between 10KB and 100KB
}

/** Score a single file */
function scoreFile(filePath) {
  try {
    const stat = fs.statSync(filePath);
    if (stat.size < 1024) return null; // ignore < 1KB

    const code = fs.readFileSync(filePath, 'utf-8');
    const SL2 = computeSL2(code);
    const SEntropy = computeSEntropy(code);
    const SKW = computeSKW(code);
    const PSize = computePSize(stat.size);
    const score = WL2 * SL2 + WEntropy * SEntropy + WKW * SKW - WSize * PSize;

    return {
      file: filePath,
      SL2: Math.round(SL2 * 1000) / 1000,
      SEntropy: Math.round(SEntropy * 1000) / 1000,
      SKW: Math.round(SKW * 1000) / 1000,
      PSize: Math.round(PSize * 1000) / 1000,
      score: Math.round(score * 1000) / 1000
    };
  } catch (err) {
    // Skip files that can't be read
    return null;
  }
}

/** Recursively list all .js files in directory */
function listJSFiles(dirPath) {
  const results = [];
  try {
    const entries = fs.readdirSync(dirPath, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry.name);
      if (entry.isDirectory()) {
        results.push(...listJSFiles(fullPath));
      } else if (entry.isFile() && entry.name.endsWith('.js')) {
        results.push(fullPath);
      }
    }
  } catch (err) {
    // skip inaccessible directories
  }
  return results;
}

// ─── Main ─────────────────────────────────────────────────

function main() {
  const args = process.argv.slice(2);
  if (args.length < 1) {
    console.error('Usage: node scorer.js <directory_path>');
    process.exit(1);
  }

  const dirPath = args[0];
  if (!fs.existsSync(dirPath) || !fs.statSync(dirPath).isDirectory()) {
    console.error(`Error: '${dirPath}' is not a valid directory`);
    process.exit(1);
  }

  const files = listJSFiles(dirPath);
  const scored = [];

  for (const file of files) {
    const result = scoreFile(file);
    if (result !== null && result.score >= 0.30) {
      scored.push(result);
    }
  }

  // Sort by score descending
  scored.sort((a, b) => b.score - a.score);

  if (scored.length === 0) {
    console.error('[ERROR] No valid crypto algorithm file identified (score < 0.30)');
  }

  console.log(JSON.stringify(scored, null, 2));
}

main();
