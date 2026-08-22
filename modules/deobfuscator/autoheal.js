/**
 * Phase 3c & 3d: Auto-Healing Validation + Prompt Generation
 * 
 * Subcommands:
 *   node autoheal.js verify  --python <sign_sdk.py> --runner <runner.js> --unflattened <unflattened.js>
 *   node autoheal.js heal    --python <sign_sdk.py> --runner <runner.js> --unflattened <unflattened.js> [--max-retries 3]
 * 
 * verify:  Runs Python sign_sdk.py and Node runner.js with frozen params, compares outputs.
 * heal:    Runs verify in a loop, generating repair prompts on mismatch.
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// ─── Constants ──────────────────────────────────────────────

const FREEZE_PARAMS = JSON.stringify({
  timestamp: 1700000000000,
  random: 0.123456789
});

const LLM_PROMPT_TEMPLATE = `You are a JavaScript-to-Python transpiler specializing in deobfuscated stack-machine code.

TASK: Translate the following JavaScript into a self-contained Python function:

def generate_signature(params):
    """
    Returns: string (the computed signature, equivalent to JS h5st output)
    params: dict with keys {timestamp, random, ...} — use these instead of Date.now()/Math.random()
    """
    # YOUR CODE HERE

RULES:
- Output ONLY the Python function, no markdown fences, no explanations
- There is NO Network, NO DOM access — just pure computation
- PC("0x2ac") has been resolved to readable strings already
- The code uses a stack-based VM pattern:
  * s: operand stack (list), s.push() / s.pop() / s[s.length-N]
  * u: opcode array (already resolved strings)
  * case 8: binary operations like j.call(s, s[s.length-3], s.pop()) means "op(s[-3], s[-2])"
  * case 5: push current Date
  * Each case does one small stack operation
- Replace all stack operations with direct variable assignments
- params['timestamp'] replaces Date.now()
- params['random'] replaces Math.random()
- The function must be completely self-contained with NO imports except: import hashlib, import base64

INPUT CODE:
{clean_js_content}`;

// ─── CLI Arg Parsing ───────────────────────────────────────

function parseArgs() {
  const args = process.argv.slice(2);
  const cfg = {
    subcommand: args[0] || '',
    python: null,
    runner: null,
    unflattened: null,
    maxRetries: 3,
    sliced: null  // for heal prompts
  };

  for (let i = 1; i < args.length; i++) {
    if (args[i] === '--python' && i + 1 < args.length) cfg.python = args[++i];
    else if (args[i] === '--runner' && i + 1 < args.length) cfg.runner = args[++i];
    else if (args[i] === '--unflattened' && i + 1 < args.length) cfg.unflattened = args[++i];
    else if (args[i] === '--max-retries' && i + 1 < args.length) cfg.maxRetries = parseInt(args[++i], 10);
    else if (args[i] === '--sliced' && i + 1 < args.length) cfg.sliced = args[++i];
  }

  return cfg;
}

// ─── Verify Subcommand ─────────────────────────────────────

function runPython(pythonPath, params) {
  try {
    const tmpDir = path.dirname(pythonPath);
    const tmpParamsFile = path.join(tmpDir, '.freeze_params.json');
    fs.writeFileSync(tmpParamsFile, params, 'utf-8');

    // Create a wrapper that imports sign_sdk and calls generate_signature
    const wrapperCode = `
import sys, json
sys.path.insert(0, r'${path.dirname(pythonPath).replace(/\\/g, '\\\\')}')
import importlib.util
spec = importlib.util.spec_from_file_location("sign_sdk", r"${pythonPath.replace(/\\/g, '\\\\')}")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
with open(r"${tmpParamsFile.replace(/\\/g, '\\\\')}", 'r') as f:
    params = json.load(f)
result = mod.generate_signature(params)
print(result)
`;

    const tmpWrapper = path.join(path.dirname(pythonPath), '.verify_wrapper.py');
    fs.writeFileSync(tmpWrapper, wrapperCode, 'utf-8');

    const stdout = execSync(`python "${tmpWrapper}"`, {
      encoding: 'utf-8',
      timeout: 30000,
      cwd: path.dirname(pythonPath)
    });

    // Cleanup
    try { fs.unlinkSync(tmpWrapper); } catch (e) {}
    try { fs.unlinkSync(tmpParamsFile); } catch (e) {}

    return { success: true, output: stdout.trim() };
  } catch (err) {
    return {
      success: false,
      output: '',
      error: err.stderr ? err.stderr.toString().substring(0, 500) : err.message
    };
  }
}

function runNode(unflattenedPath, runnerPath) {
  try {
    const result = execSync(
      `node "${runnerPath}" --input "${unflattenedPath}" --freeze`,
      { encoding: 'utf-8', timeout: 30000, stdio: 'pipe' }
    );

    // Extract h5st from combined output (stdout + stderr merged)
    const output = String(result);
    const lines = output.split('\n');
    for (const line of lines) {
      if (line.includes('h5st:') || line.includes('h5st=')) {
        const parts = line.split(/h5st[:=]/);
        if (parts.length > 1) return { success: true, output: parts[1].trim() };
      }
    }

    return { success: true, output: output.trim() };
  } catch (err) {
    // Runner may write warnings to stderr; still try to extract h5st from combined output
    const output = [String(err.stdout || ''), String(err.stderr || '')].join('\n');
    const lines = output.split('\n');
    for (const line of lines) {
      if (line.includes('h5st:') || line.includes('h5st=')) {
        const parts = line.split(/h5st[:=]/);
        if (parts.length > 1) return { success: true, output: parts[1].trim() };
      }
    }
    return {
      success: false,
      output: '',
      error: err.stderr ? err.stderr.toString().substring(0, 500) : err.message
    };
  }
}

function verify(cfg) {
  console.log('[verify] Running Python sign_sdk.py...');
  const pyResult = runPython(cfg.python, FREEZE_PARAMS);

  console.log('[verify] Running Node runner.js...');
  const jsResult = runNode(cfg.unflattened, cfg.runner);

  if (!pyResult.success) {
    return {
      match: false,
      js_output: jsResult.output,
      py_output: '',
      error: `Python execution failed: ${pyResult.error}`
    };
  }

  if (!jsResult.success) {
    return {
      match: false,
      js_output: '',
      py_output: pyResult.output,
      error: `Node execution failed: ${jsResult.error}`
    };
  }

  const match = pyResult.output === jsResult.output;

  let diff = '';
  if (!match) {
    const maxLen = Math.max(pyResult.output.length, jsResult.output.length);
    let firstDiff = 0;
    while (firstDiff < maxLen &&
           pyResult.output[firstDiff] === jsResult.output[firstDiff]) {
      firstDiff++;
    }
    diff = `First difference at byte ${firstDiff}: ` +
           `JS='${jsResult.output.substring(firstDiff, firstDiff + 20)}' ` +
           `PY='${pyResult.output.substring(firstDiff, firstDiff + 20)}'`;
  }

  return {
    match,
    js_output: jsResult.output,
    py_output: pyResult.output,
    diff,
    error: ''
  };
}

// ─── Prompt Generation ──────────────────────────────────────

function generateInitialPrompt(cleanJsPath) {
  const cleanContent = fs.readFileSync(cleanJsPath, 'utf-8');
  return LLM_PROMPT_TEMPLATE.replace('{clean_js_content}', cleanContent);
}

function generateHealPrompt(cfg, retryNum, lastPyCode, verifyResult) {
  let prompt = `REPAIR ATTEMPT #${retryNum}: The Python translation below produced incorrect output.

EXPECTED OUTPUT (from Node.js):
${verifyResult.js_output.substring(0, 200)}

ACTUAL OUTPUT (from Python):
${verifyResult.py_output.substring(0, 200)}

DIFFERENCE:
${verifyResult.diff}

${verifyResult.error ? 'ERROR:\n' + verifyResult.error + '\n' : ''}

YOUR PREVIOUS PYTHON CODE:
\`\`\`python
${lastPyCode}
\`\`\`

Please fix the Python code so that it produces the exact same output as the JavaScript version.
Output ONLY the corrected Python function, no markdown fences, no explanations.
Make sure to handle edge cases: string type conversions, integer overflow, character encoding, etc.`;

  return prompt;
}

// ─── Subcommand Handlers ────────────────────────────────────

function cmdVerify(cfg) {
  if (!cfg.python || !cfg.runner || !cfg.unflattened) {
    console.error('Usage: node autoheal.js verify --python <path> --runner <path> --unflattened <path>');
    process.exit(1);
  }

  const result = verify(cfg);
  console.log(JSON.stringify(result, null, 2));

  if (result.match) {
    console.log('[PASS] Outputs match exactly.');
    process.exit(0);
  } else {
    console.log('[FAIL] Outputs do not match.');
    process.exit(1);
  }
}

function cmdHeal(cfg) {
  if (!cfg.python || !cfg.runner || !cfg.unflattened) {
    console.error('Usage: node autoheal.js heal --python <path> --runner <path> --unflattened <path> [--sliced <path>] [--max-retries 3]');
    process.exit(1);
  }

  const maxRetries = cfg.maxRetries || 3;
  const outDir = path.join(path.dirname(cfg.unflattened), '..');
  const tempDir = path.join(outDir, 'temp');
  try { fs.mkdirSync(tempDir, { recursive: true }); } catch (e) {}

  // If sliced is provided, generate initial prompt
  if (cfg.sliced) {
    const cleanPath = cfg.sliced;
    const initialPrompt = generateInitialPrompt(cleanPath);
    const promptPath = path.join(tempDir, 'llm_prompt.txt');
    fs.writeFileSync(promptPath, initialPrompt, 'utf-8');
    console.log(`[heal] Initial LLM prompt written to: ${promptPath}`);
    console.log('[heal] Please use this prompt with an LLM to generate sign_sdk.py');
    console.log(`[heal] Then run: node autoheal.js verify --python "${cfg.python}" --runner "${cfg.runner}" --unflattened "${cfg.unflattened}"`);
    return;
  }

  console.log('[heal] Starting auto-healing loop...\n');

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    console.log(`[heal] === Attempt ${attempt}/${maxRetries} ===`);

    const result = verify(cfg);

    if (result.match) {
      console.log('[PASS] Exact byte-match achieved!');
      console.log(`  Output: ${result.js_output.substring(0, 80)}...`);
      process.exit(0);
    }

    console.log(`[RETRY ${attempt}/${maxRetries}] Mismatch detected.`);

    if (!result.error) {
      console.log(`  JS: ${result.js_output.substring(0, 60)}...`);
      console.log(`  PY: ${result.py_output.substring(0, 60)}...`);
      if (result.diff) console.log(`  ${result.diff}`);
    } else {
      console.log(`  Error: ${result.error}`);
    }

    // Read current Python code for repair prompt
    let currentPyCode = '';
    try {
      currentPyCode = fs.readFileSync(cfg.python, 'utf-8');
    } catch (e) {
      currentPyCode = '(could not read Python file)';
    }

    // Generate repair prompt
    const healPrompt = generateHealPrompt(cfg, attempt, currentPyCode, result);
    const healPromptPath = path.join(tempDir, `heal_prompt_${attempt}.txt`);
    fs.writeFileSync(healPromptPath, healPrompt, 'utf-8');

    console.log(`[heal] Repair prompt written to: ${healPromptPath}`);

    if (attempt < maxRetries) {
      console.log('[heal] Please feed this prompt to an LLM, generate a new sign_sdk.py,');
      console.log(`[heal] overwrite: ${cfg.python}`);
      console.log('[heal] Then press Enter to retry verification...\n');

      // Wait for user to fix and press Enter
      // In automated mode, we'd just retry; here we pause
      try {
        // Use stdin to wait for user
        const readline = require('readline');
        const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
        // Simple sync wait is not possible in Node without external packages,
        // so we write status and exit, letting user manually re-run
        console.log('[heal] Auto-pause: re-run "node autoheal.js heal ..." after fixing.');
        console.log('[heal] Or use verify subcommand to check:');
        console.log(`  node autoheal.js verify --python "${cfg.python}" --runner "${cfg.runner}" --unflattened "${cfg.unflattened}"`);
        process.exit(0);
        rl.close();
      } catch (e) {
        process.exit(0);
      }
    }
  }

  console.log(`\n[heal] Maximum retries (${maxRetries}) reached.`);
  console.log('[heal] Manual intervention required.');
  process.exit(1);
}

// ─── Main ────────────────────────────────────────────────────

function main() {
  const cfg = parseArgs();

  switch (cfg.subcommand) {
    case 'verify':
      cmdVerify(cfg);
      break;
    case 'heal':
      cmdHeal(cfg);
      break;
    default:
      console.error('Usage:');
      console.error('  node autoheal.js verify  --python <path> --runner <path> --unflattened <path>');
      console.error('  node autoheal.js heal    --python <path> --runner <path> --unflattened <path> [--sliced <path>] [--max-retries 3]');
      process.exit(1);
  }
}

main();
