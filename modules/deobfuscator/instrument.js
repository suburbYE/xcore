#!/usr/bin/env node
/**
 * xcore instrument.js — CLI-standardized AST instrumentation for obfuscated JS
 *
 * Usage:
 *   node instrument.js --input <target.js> --output <out.js> [--json]
 *
 * --input   : path to obfuscated JS source
 * --output  : path for instrumented output (default: <input>_inst.js)
 * --json    : emit JSON stats to stdout (otherwise prints human-readable)
 */

const fs = require('fs');
const path = require('path');
const acorn = require('acorn');

// ─── CLI Parsing ──────────────────────────────────────────
function parseArgs(args) {
  const cfg = { input: null, output: null, json: false };
  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--input':  cfg.input  = args[++i]; break;
      case '--output': cfg.output = args[++i]; break;
      case '--json':   cfg.json   = true; break;
      default: break;
    }
  }
  if (!cfg.input) {
    console.error('ERROR: --input <file> is required');
    process.exit(1);
  }
  if (!cfg.output) {
    cfg.output = cfg.input.replace(/\.js$/, '_inst.js');
  }
  return cfg;
}

// ─── Main ──────────────────────────────────────────────────
function main() {
  const cfg = parseArgs(process.argv.slice(2));

  const code = fs.readFileSync(cfg.input, 'utf-8');

  const ast = acorn.parse(code, {
    ecmaVersion: 2022,
    sourceType: 'script',
    locations: true,
    ranges: true,
    allowReturnOutsideFunction: true,
  });

  // Collect patches: { pos, text }
  const patches = [];

  // Walk AST
  function walk(node, parent) {
    if (!node || typeof node !== 'object') return;
    if (Array.isArray(node)) { node.forEach(n => walk(n, parent)); return; }

    // Find labeled for(;;){switch} state machines
    if (node.type === 'LabeledStatement' &&
        node.body &&
        node.body.type === 'ForStatement' &&
        node.body.body &&
        node.body.body.type === 'BlockStatement') {

      const forStmt = node.body;
      const block = forStmt.body;

      // Check if block contains a switch statement
      const hasSwitch = block.body.some(stmt =>
        stmt.type === 'SwitchStatement'
      );
      if (!hasSwitch) return;

      // Found a state machine. Instrument each case in the switch.
      for (const stmt of block.body) {
        if (stmt.type !== 'SwitchStatement') continue;
        for (const c of stmt.cases) {
          if (!c.test) continue; // default case
          // Get position after the colon (start of consequent list)
          if (c.consequent.length === 0) continue;

          let insertPos;
          if (c.consequent[0].range) {
            insertPos = c.consequent[0].range[0];
          } else if (c.consequent[0].start !== undefined) {
            insertPos = c.consequent[0].start;
          } else {
            // Fallback: approximate after colon
            const src = code.slice(c.range[0], c.range[1]);
            const colonIdx = src.indexOf(':');
            if (colonIdx === -1) continue;
            insertPos = c.range[0] + colonIdx + 1;
          }

          let caseVal;
          if (c.test.type === 'Literal') {
            caseVal = c.test.value;
          } else if (c.test.type === 'UnaryExpression' && c.test.operator === '-') {
            caseVal = -c.test.argument.value;
          } else {
            caseVal = '?';
          }

          patches.push({
            pos: insertPos,
            text: `__trace(0,${caseVal});`
          });
        }
      }
    }

    // Recurse
    for (const key of Object.keys(node)) {
      if (key === 'parent') continue;
      walk(node[key], node);
    }
  }

  walk(ast, null);

  // Sort patches by position (ascending), apply in reverse order
  patches.sort((a, b) => b.pos - a.pos);

  let out = code;
  for (const p of patches) {
    out = out.slice(0, p.pos) + p.text + out.slice(p.pos);
  }

  // Collect unique labels
  const patchedLabels = new Set();

  function collectLabels(node) {
    if (!node || typeof node !== 'object') return;
    if (Array.isArray(node)) { node.forEach(collectLabels); return; }
    if (node.type === 'LabeledStatement' &&
        node.body && node.body.type === 'ForStatement') {
      patchedLabels.add(node.label.name);
    }
    for (const key of Object.keys(node)) {
      if (key !== 'parent') collectLabels(node[key]);
    }
  }
  collectLabels(ast);

  // Write output
  fs.writeFileSync(cfg.output, out, 'utf-8');

  const stats = {
    input_file: cfg.input,
    output_file: cfg.output,
    input_size: code.length,
    output_size: out.length,
    patches: patches.length,
    state_machines_detected: patchedLabels.size,
    state_machine_labels: [...patchedLabels].sort(),
  };

  if (cfg.json) {
    console.log(JSON.stringify(stats));
  } else {
    console.log(`[instrument] ${cfg.input} → ${cfg.output}`);
    console.log(`  Input: ${code.length} B → Output: ${out.length} B`);
    console.log(`  Patches: ${patches.length} traces injected`);
    console.log(`  State machines: ${patchedLabels.size} (${[...patchedLabels].join(', ')})`);
  }
}

main();
