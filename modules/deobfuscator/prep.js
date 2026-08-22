/**
 * Phase 3b: LLM-Prep Pre-Deobfuscation
 * 
 * Usage:
 *   node prep.js --sliced <sliced.js> --unflattened <unflattened.js> --pc-map <pc_mapping.json>
 * 
 * Two-stage transformation:
 *   L1a: PC(N) static replacement (resolve PC calls via pre-extracted mapping)
 *   L1b: Array index static evaluation (resolve _xxx[n] where n is literal)
 *   L2:  Stack semantic comment header (no actual transformation)
 * 
 * Output: clean.js (written to same directory as sliced file)
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const acorn = require('acorn');

// ─── CLI Args ──────────────────────────────────────────────

function parseArgs() {
  const args = process.argv.slice(2);
  const cfg = { sliced: null, unflattened: null, pcMap: null };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--sliced' && i + 1 < args.length) cfg.sliced = args[++i];
    if (args[i] === '--unflattened' && i + 1 < args.length) cfg.unflattened = args[++i];
    if (args[i] === '--pc-map' && i + 1 < args.length) cfg.pcMap = args[++i];
  }
  if (!cfg.sliced || !cfg.unflattened || !cfg.pcMap) {
    console.error('Usage: node prep.js --sliced <sliced.js> --unflattened <unflattened.js> --pc-map <pc_mapping.json>');
    process.exit(1);
  }
  return cfg;
}

// ─── VM Sandbox: Extract PC mapping ────────────────────────

function buildPCMapping(unflattenedPath) {
  const code = fs.readFileSync(unflattenedPath, 'utf-8');
  const mapping = {};

  // Create a sandbox that captures PC calls
  const sandbox = {
    PC: function (arg) {
      // PC function in original code maps numbers to strings
      // We intercept it to build the mapping table
      mapping[String(arg)] = undefined; // placeholder
      return function actualPC(n) {
        // The real PC lookup — we can't actually execute it,
        // but we can try to capture return values
        return undefined;
      };
    },
    console: console,
  };

  try {
    const script = new vm.Script(code);
    const ctx = vm.createContext(sandbox);
    script.runInContext(ctx, { timeout: 5000 });
  } catch (err) {
    // Expected: unflattened code will likely throw when not fully executed
    // We only care about the PC function definition
  }

  // Try a different approach: scan for PC function definition patterns
  // PC("0x2ac") pattern typically resolves via a lookup table
  // Try to extract the table from the unflattened code
  const pcTablePattern = /var\s+_(\w+)\s*=\s*\[([\s\S]*?)\];/;
  const tableMatches = [];
  const globalPattern = /var\s+(_\w+)\s*=\s*\[([\s\S]*?)\];/g;
  let m;
  while ((m = globalPattern.exec(code)) !== null) {
    tableMatches.push({ name: m[1], content: m[2] });
  }

  // Try to find the PC function definition
  const pcFuncPattern = /function\s+PC\s*\(\s*(\w+)\s*\)/;
  const pcMatch = code.match(pcFuncPattern);

  // Second approach: directly inject PC table evaluation
  // Find large string arrays and use them as the lookup table
  const sandbox2 = {
    result: null,
    _tables: {},
    console: console,
  };

  // Extract all var _xxx = [...] and store in sandbox
  const arrayDefPattern = /var\s+(_\w+)\s*=\s*(\[[\s\S]*?\]);/g;
  let arrayMatch;
  const arrayExtractions = [];
  while ((arrayMatch = arrayDefPattern.exec(code)) !== null) {
    const name = arrayMatch[1];
    const arrayLiteral = arrayMatch[2];
    try {
      const evaluated = vm.runInNewContext(arrayLiteral, {});
      sandbox2._tables[name] = evaluated;
    } catch (e) {
      // skip unparseable arrays
    }
  }

  // Now find PC function and trace its return values
  // PC is typically: function PC(n) { return _xxxx[n]; }
  // Or: function PC(n) { return _xxxx[n - offset]; }
  let pcTableName = null;
  let pcOffset = 0;

  const pcDefPattern = /function\s+PC\s*\(\s*(\w+)\s*\)\s*\{\s*return\s+(_\w+)\s*\[\s*\1\s*(?:-\s*(\d+))?\s*\]/;
  const pcDefMatch = code.match(pcDefPattern);
  if (pcDefMatch) {
    pcTableName = pcDefMatch[2];
    pcOffset = parseInt(pcDefMatch[3] || '0', 10);
  } else {
    // Try simpler pattern: return _xxx[n]
    const simplePcPattern = /function\s+PC\s*\(\s*(\w+)\s*\)\s*\{\s*return\s+(_\w+)\s*\[\s*\1\s*\]/;
    const simpleMatch = code.match(simplePcPattern);
    if (simpleMatch) {
      pcTableName = simpleMatch[2];
    }
  }

  if (pcTableName && sandbox2._tables[pcTableName]) {
    const table = sandbox2._tables[pcTableName];
    for (let i = 0; i < table.length; i++) {
      mapping[String(i + pcOffset)] = table[i];
    }
  }

  // Also try to directly eval PC calls from the code
  // PC("0x2ac") — the argument might be a hex number
  if (Object.keys(mapping).length === 0) {
    const pcCallPattern = /PC\s*\(\s*["']?(0x[\da-fA-F]+|\d+)["']?\s*\)/g;
    const pcCalls = [];
    let pcCallMatch;
    while ((pcCallMatch = pcCallPattern.exec(code)) !== null) {
      pcCalls.push(pcCallMatch[1]);
    }

    // For each potential index, try to evaluate in context
    // Build a more complete sandbox with all discovered tables
    const sandbox3 = {
      PC: function (idx) {
        const numIdx = typeof idx === 'string' ?
          (idx.startsWith('0x') ? parseInt(idx, 16) : parseInt(idx, 10)) :
          idx;
        // Try all known tables
        for (const [name, table] of Object.entries(sandbox2._tables)) {
          if (numIdx >= 0 && numIdx < table.length) {
            return table[numIdx];
          }
        }
        return undefined;
      },
    };
    Object.assign(sandbox3, sandbox2._tables);

    // Execute the code to let PC calls resolve
    try {
      const script3 = new vm.Script(code);
      const ctx3 = vm.createContext(sandbox3);
      script3.runInContext(ctx3, { timeout: 5000 });
    } catch (e) {
      // Expected to fail, PC calls may have been resolved
    }

    // Re-check: did PC resolve anything via console or return values?
  }

  return mapping;
}

// ─── L1a: PC(N) Static Replacement ────────────────────────

function replacePCCalls(code, pcMapping) {
  // Match PC("0x2ac") or PC(123) or PC(0x2ac)
  return code.replace(/PC\s*\(\s*["']?(0x[\da-fA-F]+|\d+)["']?\s*\)/g, (match, idxStr) => {
    const idx = idxStr.startsWith('0x') ? parseInt(idxStr, 16) : parseInt(idxStr, 10);
    const key = String(idx);
    if (pcMapping[key] !== undefined && typeof pcMapping[key] === 'string') {
      return JSON.stringify(pcMapping[key]);
    }
    // Try offset variants
    for (const [k, v] of Object.entries(pcMapping)) {
      if (parseInt(k) === idx && typeof v === 'string') {
        return JSON.stringify(v);
      }
    }
    return match; // keep original if not found
  });
}

// ─── L1b: Array Index Static Evaluation ───────────────────

function replaceArrayIndex(code, pcMapping) {
  // Parse AST
  let ast;
  try {
    ast = acorn.parse(code, { ecmaVersion: 2020, locations: true });
  } catch (e) {
    console.error('[prep] AST parse error:', e.message);
    return code;
  }

  const replacements = [];

  // Walk AST to find MemberExpression with literal numeric property
  function walk(node) {
    if (!node || typeof node !== 'object') return;

    if (node.type === 'MemberExpression' &&
        node.computed === true &&
        node.property &&
        node.property.type === 'Literal' &&
        typeof node.property.value === 'number' &&
        node.object &&
        node.object.type === 'Identifier') {

      const arrayName = node.object.name;
      const index = node.property.value;

      // Check if we have this array in the mapping
      // The mapping keys are string indices; we need to look up by array name
      // pcMapping structure: { "0": "str0", "1": "str1", ... }
      // But we also need per-array mappings from the unflattened code

      if (pcMapping._arrays && pcMapping._arrays[arrayName]) {
        const arr = pcMapping._arrays[arrayName];
        if (index >= 0 && index < arr.length && typeof arr[index] === 'string') {
          replacements.push({
            start: node.start,
            end: node.end,
            replacement: JSON.stringify(arr[index])
          });
        }
      }
    }

    // Recurse
    for (const key of Object.keys(node)) {
      if (key === 'loc' || key === 'start' || key === 'end') continue;
      const child = node[key];
      if (Array.isArray(child)) {
        for (const c of child) walk(c);
      } else if (child && typeof child === 'object' && child.type) {
        walk(child);
      }
    }
  }

  walk(ast);

  // Apply replacements in reverse order (to preserve offsets)
  replacements.sort((a, b) => b.start - a.start);
  let result = code;
  for (const r of replacements) {
    result = result.slice(0, r.start) + r.replacement + result.slice(r.end);
  }

  return result;
}

// ─── Build extended mapping (arrays from unflattened) ──────

function buildArrayMapping(unflattenedPath) {
  const code = fs.readFileSync(unflattenedPath, 'utf-8');
  const arrays = {};

  const arrayDefPattern = /var\s+(_\w+)\s*=\s*(\[[\s\S]*?\]);/g;
  let m;
  while ((m = arrayDefPattern.exec(code)) !== null) {
    const name = m[1];
    const literal = m[2];
    try {
      const evaluated = vm.runInNewContext(literal, {});
      arrays[name] = evaluated;
    } catch (e) {
      // skip
    }
  }

  return arrays;
}

// ─── L2: Stack semantic comment ───────────────────────────

const STACK_SEMANTIC_HEADER = `/*
 * ═══════════════════════════════════════════════════════════
 * STACK MACHINE SEMANTICS (for LLM transpilation reference)
 * ═══════════════════════════════════════════════════════════
 *
 * This code originates from a stack-based VM obfuscator.
 * Key variables and their roles:
 *
 *   s  — operand stack (Array). Operations:
 *        s.push(val)    — push value onto stack
 *        s.pop()        — pop top value
 *        s[s.length-N]  — access N-th from top (1-indexed)
 *
 *   u  — opcode array (already resolved to readable strings).
 *        Indexed by n (program counter), e.g., u[n++].
 *
 *   n  — program counter, increments after each opcode fetch.
 *
 * Common case patterns:
 *   case 5:  push current Date (Date.now())
 *   case 8:  binary operations like:
 *            j.call(s, s[s.length-3], s.pop())
 *            means: op(s[-3], s.pop()), result stays on stack
 *   case 12: ternary / conditional
 *   case 94: push this[resolvedString]
 *   case 96: push PC (function reference)
 *
 * When transpiling to Python:
 *   - Replace all stack pushes/pops with direct variable assignments
 *   - params['timestamp'] replaces Date.now()
 *   - params['random'] replaces Math.random()
 *   - The function must be self-contained, imports: hashlib, base64
 * ═══════════════════════════════════════════════════════════
 */
`;

// ─── Main ──────────────────────────────────────────────────

function main() {
  const cfg = parseArgs();

  console.error('[prep] Reading sliced:', cfg.sliced);
  console.error('[prep] Reading unflattened:', cfg.unflattened);
  console.error('[prep] Reading PC map:', cfg.pcMap);

  // Load PC mapping from pre-extracted JSON
  const pcMapping = JSON.parse(fs.readFileSync(cfg.pcMap, 'utf-8'));
  console.error('[prep] PC mapping entries:', Object.keys(pcMapping).length);

  // Build array mapping
  const arrayMapping = buildArrayMapping(cfg.unflattened);
  console.error('[prep] Array tables found:', Object.keys(arrayMapping).length);

  // Combine mappings
  pcMapping._arrays = arrayMapping;

  // Read sliced code
  let slicedCode = fs.readFileSync(cfg.sliced, 'utf-8');

  // L1a: Replace PC calls
  slicedCode = replacePCCalls(slicedCode, pcMapping);
  console.error('[prep] L1a: PC replacement done');

  // L1b: Replace array index literal accesses
  slicedCode = replaceArrayIndex(slicedCode, pcMapping);
  console.error('[prep] L1b: Array index evaluation done');

  // L2: Stack semantic header (prepend)
  slicedCode = STACK_SEMANTIC_HEADER + '\n' + slicedCode;
  console.error('[prep] L2: Stack semantic header prepended');

  // Write output
  const outDir = path.dirname(cfg.sliced);
  const outPath = path.join(outDir, 'clean.js');
  fs.writeFileSync(outPath, slicedCode, 'utf-8');

  console.error('[prep] Output written to:', outPath);
  console.log(JSON.stringify({
    status: 'ok',
    input: cfg.sliced,
    output: outPath,
    pc_entries: Object.keys(pcMapping).length,
    array_tables: Object.keys(arrayMapping).length
  }));
}

main();
