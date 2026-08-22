#!/usr/bin/env node
/**
 * emitter.js — xcore Phase 4b: dead-case elimination from flatten analysis
 *
 * Strategy (consistent with v8 verified approach):
 *   Use C++ flatten engine's alive-case set to strip dead cases from the original JS,
 *   keeping the for(;;){switch} framework intact. This produces a structurally identical
 *   file minus 50%+ dead branches, which passes h5st equivalence.
 *
 *   For loops detected by the C++ engine are annotated as comments for manual review.
 *
 * Input:  --input <original.js> --flatten <flatten.json> --output <unflattened.js>
 */

const fs = require('fs');
const args = process.argv.slice(2);
const ga = (f) => { const i = args.indexOf(f); return i >= 0 ? args[i+1] : null; };

const INPUT   = ga('--input');
const FLATTEN = ga('--flatten');
const OUTPUT  = ga('--output');

if (!INPUT || !FLATTEN || !OUTPUT) {
    console.error('Usage: node emitter.js --input <original.js> --flatten <flatten.json> --output <unflattened.js>');
    process.exit(1);
}

const code = fs.readFileSync(INPUT, 'utf-8');
const flat = JSON.parse(fs.readFileSync(FLATTEN, 'utf-8'));

// Build alive case set from linearized trace
const aliveSet = new Set();
for (const v of flat.linearized) aliveSet.add(v);

let output = code;

// In each for(;;){switch(u[n++]){...}}, strip case blocks whose id is NOT in aliveSet
// Match: case NUMBER: ... (break; or continue lXX; or default:)
const smRegex = /(for\(;;\)\{switch\(u\[n\+\+\]\)\{)([\s\S]*?)(\}\s*\})/g;

output = code.replace(smRegex, (match, prefix, body, suffix) => {
    // Split into case blocks
    const caseRe = /(case\s+(\d+):[\s\S]*?)(?=case\s+\d+:|default:|$)/g;
    let newBody = '';
    let mm;
    while ((mm = caseRe.exec(body)) !== null) {
        const full = mm[1];
        const cid  = parseInt(mm[2]);
        if (aliveSet.has(cid)) {
            newBody += full;
        }
    }
    // Keep default clause if present
    const defMatch = body.match(/(default\s*:[\s\S]*)/);
    if (defMatch) {
        newBody += defMatch[0];
    }
    return prefix + newBody + suffix;
});

// Annotate detected loops as comments at top of file
if (flat.loops && flat.loops.length > 0) {
    let header = '/* Detected loops from xcore flatten engine:\n';
    for (const lp of flat.loops) {
        header += ` *   [${lp.start}..${lp.start + lp.length * lp.repeats}] repeat ${lp.repeats}x length ${lp.length}\n`;
    }
    header += ' */\n';
    output = header + output;
}

const stats = {
    input_file: INPUT,
    flatten_file: FLATTEN,
    output_file: OUTPUT,
    output_size: output.length,
    alive_cases: aliveSet.size,
    total_linearized: flat.linearized.length,
    status: 'ok'
};

fs.writeFileSync(OUTPUT, output, 'utf-8');
process.stdout.write(JSON.stringify(stats) + '\n');
