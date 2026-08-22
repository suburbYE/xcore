#!/usr/bin/env node
/**
 * xcore flatten.js — State-machine to linear CFG reconstruction
 *
 * Usage:
 *   node flatten.js --input <original.js> --trace <trace_report.json> --output <flat.js> [--json]
 *
 * --input  : path to original obfuscated JS (same file used for instrument/runner)
 * --trace  : path to trace_report.json (from runner with --inst)
 * --output : path for flattened output JS
 * --json   : emit JSON stats to stdout
 */

const fs = require('fs');

// ─── CLI Parsing ──────────────────────────────────────────
function parseArgs(args) {
  const cfg = { input: null, trace: null, output: null, json: false };
  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--input':  cfg.input  = args[++i]; break;
      case '--trace':  cfg.trace  = args[++i]; break;
      case '--output': cfg.output = args[++i]; break;
      case '--json':   cfg.json   = true; break;
      default: break;
    }
  }
  if (!cfg.input) { console.error('ERROR: --input <file> required'); process.exit(1); }
  if (!cfg.trace) { console.error('ERROR: --trace <file> required'); process.exit(1); }
  if (!cfg.output) {
    cfg.output = cfg.input.replace(/\.js$/, '_unflattened.js');
  }
  return cfg;
}

// ─── RLE Compression ──────────────────────────────────────
function rle(seq) {
  const result = [];
  let i = 0;
  while (i < seq.length) {
    let run = 1;
    while (i + run < seq.length && seq[i + run] === seq[i]) run++;
    result.push({ val: seq[i], count: run });
    i += run;
  }
  return result;
}

// ─── Sliding window repeat detection ──────────────────────
function findRepeats(seq, minWindow, maxWindow, minRepeats) {
  const repeats = [];
  for (let w = minWindow; w <= maxWindow; w++) {
    const seen = new Map(); // stringified slice → [{ start, end }]
    for (let i = 0; i + w <= seq.length; i++) {
      const slice = seq.slice(i, i + w);
      const key = slice.join(',');
      if (!seen.has(key)) seen.set(key, []);
      seen.get(key).push({ start: i, end: i + w });
    }
    for (const [key, occurrences] of seen) {
      if (occurrences.length >= minRepeats) {
        // Filter non-overlapping occurrences
        const nonOverlap = [occurrences[0]];
        for (let o = 1; o < occurrences.length; o++) {
          if (occurrences[o].start >= nonOverlap[nonOverlap.length - 1].end) {
            nonOverlap.push(occurrences[o]);
          }
        }
        if (nonOverlap.length >= minRepeats) {
          repeats.push({ pattern: key.split(',').map(Number), window: w, count: nonOverlap.length, occurrences: nonOverlap });
        }
      }
    }
  }
  // Sort by (window * count) descending, take largest patterns
  repeats.sort((a, b) => (b.window * b.count) - (a.window * a.count));
  return repeats;
}

// ─── Main ─────────────────────────────────────────────────
function main() {
  const cfg = parseArgs(process.argv.slice(2));

  const code = fs.readFileSync(cfg.input, 'utf-8');
  const traceData = JSON.parse(fs.readFileSync(cfg.trace, 'utf-8'));
  const seq = traceData.case_sequence;
  const usedCases = new Set(seq);

  // Locate the _$sdnmd function
  const sig = '_$PI.prototype._$sdnmd=function(_$Pd){';
  const idx = code.indexOf(sig);
  if (idx === -1) {
    // Auto-detect: find any function with for(;;){switch}
    console.error('ERROR: could not locate signature function');
    process.exit(1);
  }

  const bs = idx + sig.length - 1;
  let d = 1, be = bs + 1;
  while (d > 0) {
    if (code[be] === '{') d++;
    else if (code[be] === '}') d--;
    be++;
  }
  be--;

  const body = code.slice(bs + 1, be);

  // Extract case blocks
  const blocks = {};
  const caseRe = /case\s+(\d+):/g;
  const ranges = [];
  let m;
  while ((m = caseRe.exec(body)) !== null) {
    const caseId = parseInt(m[1]);
    // Find the next case statement or end of switch to determine block end
    const nextCaseRe = /case\s+\d+:|default:|break\s*;/g;
    nextCaseRe.lastIndex = m.index + m[0].length;

    // Scan for next case/default or break
    let endPos = body.length;

    // Strategy: find the corresponding break or next case
    let depth = 0;
    let scanPos = m.index + m[0].length;
    while (scanPos < body.length) {
      const ch = body[scanPos];
      if (ch === '{') depth++;
      else if (ch === '}') depth--;
      else if (ch === 'b' && depth === 0) {
        if (body.substring(scanPos, scanPos + 6) === 'break;') {
          endPos = scanPos + 6;
          break;
        }
      } else if (depth === 0 && body[scanPos] === 'c' && body.substring(scanPos, scanPos + 5) === 'case ') {
        // Next case statement at same depth
        endPos = scanPos;
        break;
      }
      scanPos++;
    }

    ranges.push({
      caseId,
      start: m.index + m[0].length,
      end: endPos,
    });
    blocks[caseId] = body.substring(m.index + m[0].length, endPos);
  }

  // Build linear body from trace sequence
  const rleSeq = rle(seq);
  const repeats = findRepeats(seq, 2, 20, 3);

  // Mark repeated regions
  const loopRegions = new Set();
  if (repeats.length > 0) {
    const topRepeat = repeats[0];
    for (const occ of topRepeat.occurrences) {
      for (let i = occ.start; i < occ.end; i++) {
        loopRegions.add(i);
      }
    }
  }

  // Reconstruct: iterate trace sequence, emit case blocks
  let lastCase = -1;
  let loopDepth = 0;
  const outputLines = [];

  for (let i = 0; i < seq.length; i++) {
    const caseId = seq[i];
    if (!blocks[caseId]) continue;

    const inLoop = loopRegions.has(i);
    const nextInLoop = (i + 1 < seq.length) && loopRegions.has(i + 1);

    // Enter loop
    if (inLoop && !loopRegions.has(i - 1)) {
      outputLines.push(`// ── loop (${repeats[0]?.window || '?'} cases) ──`);
      outputLines.push(`for(let _i=0;_i<${repeats[0]?.count || 3};_i++){`);
      loopDepth++;
    }

    // Emit case block
    let block = blocks[caseId];
    // Strip __trace line from block
    block = block.replace(/__trace\(\s*0\s*,\s*\d+\s*\)\s*;?\s*/g, '');

    outputLines.push(`  // case ${caseId}`);
    outputLines.push(`  ${block.trim()}`);

    // Exit loop
    if (!nextInLoop && loopDepth > 0) {
      outputLines.push(`}`);
      loopDepth--;
    }
  }

  // Build output: preamble + linear body + epilogue
  const preamble = code.slice(0, idx) + sig + '\n';
  const epilogue = code.slice(be);

  const flatCode = preamble + outputLines.join('\n') + '\n' + epilogue;

  fs.writeFileSync(cfg.output, flatCode, 'utf-8');

  const stats = {
    input_file: cfg.input,
    trace_file: cfg.trace,
    output_file: cfg.output,
    trace_steps: seq.length,
    unique_cases: usedCases.size,
    total_cases_available: Object.keys(blocks).length,
    rle_segments: rleSeq.length,
    loops_detected: repeats.length > 0 ? 1 : 0,
    output_size: flatCode.length,
  };

  if (cfg.json) {
    console.log(JSON.stringify(stats));
  } else {
    console.log(`[flatten] ${cfg.input} → ${cfg.output}`);
    console.log(`  Trace: ${seq.length} steps → RLE: ${rleSeq.length} segments`);
    console.log(`  Cases: ${usedCases.size} unique / ${Object.keys(blocks).length} total`);
    console.log(`  Loops folded: ${repeats.length > 0 ? 1 : 0}`);
    console.log(`  Output: ${flatCode.length} B`);
  }
}

main();
