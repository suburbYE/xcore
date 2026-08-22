#!/usr/bin/env node
/**
 * jni_probe.js — Phase 4c: Static Scan → Frida Dynamic Probe
 *
 * Converts Phase 4b static scan results into executable Frida JavaScript.
 * Generated script can be used directly with: frida -U -l probe.js com.target.app
 *
 * Usage:
 *   node jni_probe.js --target <so_name> --xrefs <xrefs_json> [--out <frida_script.js>] [--spawn]
 */

"use strict";

const fs = require("fs");
const path = require("path");

// ─── Parse arguments ─────────────────────────────────────────────────────────
function parseArgs() {
  const args = process.argv.slice(2);
  const opts = { target: null, xrefs: null, out: null, spawn: false };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--target" && i + 1 < args.length) opts.target = args[++i];
    else if (args[i] === "--xrefs" && i + 1 < args.length) opts.xrefs = args[++i];
    else if (args[i] === "--out" && i + 1 < args.length) opts.out = args[++i];
    else if (args[i] === "--spawn") opts.spawn = true;
  }
  if (!opts.target || !opts.xrefs) {
    console.error("Usage: node jni_probe.js --target <so_name> --xrefs <xrefs_json> [--out <frida_script.js>] [--spawn]");
    process.exit(1);
  }
  return opts;
}

// ─── Load and parse xrefs ────────────────────────────────────────────────────
function loadXrefData(jsonPath) {
  const raw = fs.readFileSync(jsonPath, "utf8");
  const data = JSON.parse(raw);

  // Extract xrefs array
  const xrefs = data.xrefs || [];
  const layers = data.layers || {};
  const l1Strings = (layers.L1_strings && layers.L1_strings.hits) || [];
  const l3Hits = (layers.L3_symbols && layers.L3_symbols.hits) || [];
  const l5Details = (layers.L5_cfp && layers.L5_cfp.details) || [];
  const l5Hits = (layers.L5_cfp && layers.L5_cfp.hits) || [];

  // Build key_rvas from xrefs: string_addr -> [rva, func_name]
  const keyRVAs = [];
  for (const x of xrefs) {
    if (x.rva !== undefined && x.rva !== null) {
      keyRVAs.push({
        label: (x.string || "xref") + "_ref",
        rva: x.rva,
        size: x.size || 64,
        trigger: "call_on_enter",
        func: x.func || "unknown"
      });
    }
  }

  // Extract L3 symbols for crypto hooks
  const cryptoNames = ["SHA256_Update", "SHA256_Init", "SHA256_Final",
                       "HMAC_Update", "HMAC_Init", "HMAC_Final",
                       "MD5_Update", "AES_encrypt", "AES_decrypt",
                       "EVP_EncryptInit", "EVP_DecryptInit"];
  const cryptoHooks = [];
  for (const h of l3Hits) {
    const sym = h.symbol || h;
    if (cryptoNames.some(c => sym.includes(c))) {
      cryptoHooks.push({ name: sym, log_args: [0, 1, 2] });
    }
  }

  // Extract L5 CFP locations for immediate hex dump
  const l5Probes = [];
  for (const p of l5Details) {
    const locations = p.locations || [];
    for (let j = 0; j < Math.min(locations.length, 3); j++) {
      l5Probes.push({
        label: (p.name || "cfp") + "_" + (j + 1),
        rva: locations[j],
        size: 128,
        trigger: "immediate"
      });
    }
  }

  // Top L1 strings for class_name filter
  const topStrings = l1Strings.slice(0, 5).map(s => {
    if (typeof s === "string") return s;
    return s.string || s;
  });

  return { xrefs, keyRVAs, cryptoHooks, l5Probes, topStrings, data };
}

// ─── Frida template: Module 1 — RegisterNatives Interceptor ──────────────────
function buildModule1(targetLib, topStrings) {
  const filterExpr = topStrings.length > 0
    ? topStrings.map(s => 'class_name.indexOf("' + s.replace(/"/g, '\\"') + '") !== -1').join(" ||\n                       ")
    : "true";

  return (
    '// ═══ Module 1: JNI RegisterNatives Interceptor ═══\n' +
    '(function() {\n' +
    '    var target_lib = "' + targetLib + '";\n' +
    '    \n' +
    '    var RegisterNatives = Module.findExportByName(null, "RegisterNatives");\n' +
    '    if (RegisterNatives) {\n' +
    '        Interceptor.attach(RegisterNatives, {\n' +
    '            onEnter: function(args) {\n' +
    '                var env = args[0];\n' +
    '                var class_name_ptr = args[1];\n' +
    '                var methods_ptr = args[2];\n' +
    '                var num_methods = args[3].toInt32();\n' +
    '                \n' +
    '                var class_name = Java.vm.tryGetEnv().getStringUtfChars(class_name_ptr, null).readCString();\n' +
    '                if (' + filterExpr + ') {\n' +
    '                    console.log("[RegisterNatives] class=" + class_name + " methods=" + num_methods);\n' +
    '                    for (var i = 0; i < num_methods; i++) {\n' +
    '                        var method = methods_ptr.add(i * Process.pointerSize * 3);\n' +
    '                        var name = method.readPointer().readCString();\n' +
    '                        var sig = method.add(Process.pointerSize).readPointer().readCString();\n' +
    '                        var fn = method.add(Process.pointerSize * 2).readPointer();\n' +
    '                        console.log("  [" + i + "] " + name + sig + " => " + fn);\n' +
    '                    }\n' +
    '                }\n' +
    '            }\n' +
    '        });\n' +
    '        console.log("[*] RegisterNatives hook installed");\n' +
    '    }\n' +
    '})();\n\n'
  );
}

// ─── Frida template: Module 2 — Key RVA Hex Dump ────────────────────────────
function buildModule2(targetLib, keyRVAs, l5Probes) {
  const allProbes = [...keyRVAs];
  // Merge L5 probes (avoid duplicates by RVA)
  const seenRVAs = new Set(keyRVAs.map(p => p.rva));
  for (const p of l5Probes) {
    if (!seenRVAs.has(p.rva)) {
      allProbes.push(p);
      seenRVAs.add(p.rva);
    }
  }

  const probeJSON = JSON.stringify(allProbes.map(p => ({
    label: p.label,
    rva: p.rva,
    size: p.size || 64,
    trigger: p.trigger || "call_on_enter"
  })), null, 8).replace(/"([^"]+)":/g, "$1:");

  return (
    '// ═══ Module 2: Key RVA Hex Dump ═══\n' +
    '(function() {\n' +
    '    var target_lib = "' + targetLib + '";\n' +
    '    var probes = ' + probeJSON + ';\n' +
    '    \n' +
    '    function dump_hex(label, addr, size) {\n' +
    '        console.log("════ HEXDUMP [" + label + "] @ " + addr + " ═══");\n' +
    '        var bytes = addr.readByteArray(size);\n' +
    '        if (!bytes) {\n' +
    '            console.log("  (null bytes)");\n' +
    '            return;\n' +
    '        }\n' +
    '        console.log(hexdump(bytes, { offset: 0, length: size, header: true, ansi: false }));\n' +
    '    }\n' +
    '    \n' +
    '    function install_probes(mod, list) {\n' +
    '        console.log("[*] " + target_lib + " base=" + mod.base + " size=" + mod.size);\n' +
    '        list.forEach(function(p) {\n' +
    '            var addr = mod.base.add(p.rva);\n' +
    '            if (p.trigger === "immediate") {\n' +
    '                dump_hex(p.label, addr, p.size);\n' +
    '            } else if (p.trigger === "call_on_enter") {\n' +
    '                Interceptor.attach(addr, {\n' +
    '                    onEnter: function(args) {\n' +
    '                        dump_hex(p.label, mod.base.add(p.rva), p.size);\n' +
    '                    }\n' +
    '                });\n' +
    '                console.log("[*] Hook installed: " + p.label + " @ " + addr);\n' +
    '            } else if (p.trigger === "call_on_leave") {\n' +
    '                Interceptor.attach(addr, {\n' +
    '                    onLeave: function(retval) {\n' +
    '                        dump_hex(p.label, mod.base.add(p.rva), p.size);\n' +
    '                    }\n' +
    '                });\n' +
    '                console.log("[*] Hook installed: " + p.label + " @ " + addr);\n' +
    '            }\n' +
    '        });\n' +
    '    }\n' +
    '    \n' +
    '    var module = Process.findModuleByName(target_lib);\n' +
    '    if (!module) {\n' +
    '        console.log("[!] " + target_lib + " not loaded yet, waiting...");\n' +
    '        var done = false;\n' +
    '        Interceptor.attach(Module.findExportByName(null, "dlopen"), {\n' +
    '            onEnter: function(args) {\n' +
    '                this.path = args[0].readCString();\n' +
    '            },\n' +
    '            onLeave: function(retval) {\n' +
    '                if (this.path && this.path.indexOf(target_lib) !== -1 && !done) {\n' +
    '                    done = true;\n' +
    '                    module = Process.findModuleByName(target_lib);\n' +
    '                    install_probes(module, probes);\n' +
    '                }\n' +
    '            }\n' +
    '        });\n' +
    '    } else {\n' +
    '        install_probes(module, probes);\n' +
    '    }\n' +
    '})();\n\n'
  );
}

// ─── Frida template: Module 3 — Crypto Function Argument Logger ──────────────
function buildModule3(targetLib, cryptoHooks) {
  if (cryptoHooks.length === 0) return "";

  const hooksJSON = JSON.stringify(cryptoHooks.map(h => ({
    name: h.name,
    log_args: h.log_args
  })), null, 8).replace(/"([^"]+)":/g, "$1:");

  return (
    '// ═══ Module 3: Crypto Function Argument Logger ═══\n' +
    '(function() {\n' +
    '    var target_lib = "' + targetLib + '";\n' +
    '    var crypto_hooks = ' + hooksJSON + ';\n' +
    '    \n' +
    '    crypto_hooks.forEach(function(h) {\n' +
    '        var addr = Module.findExportByName(target_lib, h.name);\n' +
    '        if (addr) {\n' +
    '            Interceptor.attach(addr, {\n' +
    '                onEnter: function(args) {\n' +
    '                    var dumpLen = Math.min(32, args[2] ? args[2].toInt32() : 32);\n' +
    '                    var dataStr = "(null)";\n' +
    '                    if (args[1] && dumpLen > 0) {\n' +
    '                        try { dataStr = hexdump(args[1].readByteArray(dumpLen), {offset:0, length:dumpLen, header:false}); }\n' +
    '                        catch(e) { dataStr = "(read error)"; }\n' +
    '                    }\n' +
    '                    console.log("[CRYPTO] " + h.name + "(" +\n' +
    '                        "ctx=" + args[0] + ", " +\n' +
    '                        "data=" + dataStr + ", " +\n' +
    '                        "len=" + (args[2] || 0) + ")");\n' +
    '                }\n' +
    '            });\n' +
    '            console.log("[*] Crypto hook: " + h.name);\n' +
    '        }\n' +
    '    });\n' +
    '})();\n\n'
  );
}

// ─── Frida template: Module 4 — Spawn mode extras ────────────────────────────
function buildModule4() {
  return (
    '// ═══ Module 4: Spawn-mode early hooks & anti-detect ═══\n' +
    '(function() {\n' +
    '    // Catch crashes gracefully\n' +
    '    Process.setExceptionHandler(function(details) {\n' +
    '        console.log("[!] Exception: " + details.type + " at " + details.address +\n' +
    '                    " context=" + JSON.stringify(details.context));\n' +
    '        return false; // forward to next handler\n' +
    '    });\n' +
    '    \n' +
    '    // Early .so load hook via android_dlopen_ext\n' +
    '    var dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");\n' +
    '    if (dlopen_ext) {\n' +
    '        Interceptor.attach(dlopen_ext, {\n' +
    '            onEnter: function(args) {\n' +
    '                this.path = args[0] ? args[0].readCString() : "";\n' +
    '            },\n' +
    '            onLeave: function(retval) {\n' +
    '                if (this.path && this.path.indexOf("frida") === -1) {\n' +
    '                    console.log("[dlopen_ext] " + this.path);\n' +
    '                }\n' +
    '            }\n' +
    '        });\n' +
    '        console.log("[*] android_dlopen_ext hook installed");\n' +
    '    }\n' +
    '    \n' +
    '    console.log("[*] Spawn mode: early hooks active");\n' +
    '})();\n\n'
  );
}

// ─── Build complete script ───────────────────────────────────────────────────
function buildScript(targetLib, keyRVAs, cryptoHooks, l5Probes, topStrings, spawnMode) {
  const timestamp = new Date().toISOString().replace("T", " ").substring(0, 19);

  let header = (
    "// Auto-generated by xcore Phase 4c v0.18.0\n" +
    "// Target: " + targetLib + "\n" +
    "// Generated: " + timestamp + "\n" +
    "//\n" +
    "// Usage:\n" +
    "//   Attach:  frida -U com.target.app -l this_script.js\n" +
    "//   Spawn:   frida -U -f com.target.app -l this_script.js --no-pause\n" +
    "\n" +
    "'use strict';\n\n"
  );

  let body = "";

  if (spawnMode) {
    body += buildModule4();
  }

  body += buildModule1(targetLib, topStrings);
  body += buildModule2(targetLib, keyRVAs, l5Probes);

  if (cryptoHooks.length > 0) {
    body += buildModule3(targetLib, cryptoHooks);
  }

  if (!spawnMode) {
    body += buildModule4(); // always include crash handler
  }

  body += (
    "// ═══ Summary ═══\n" +
    "console.log(\"\\n===========================================\");\n" +
    'console.log(" xcore Phase 4c Probe Active");\n' +
    'console.log(" Target: ' + targetLib + '");\n' +
    'console.log(" RVA hooks: ' + keyRVAs.length + ' (incl. CFP probes)");\n' +
    'console.log(" Crypto hooks: ' + cryptoHooks.length + '");\n' +
    'console.log(" Spawn mode: ' + (spawnMode ? "YES" : "NO") + '");\n' +
    "console.log(\"===========================================\\n\");\n"
  );

  return header + body;
}

// ─── Main ────────────────────────────────────────────────────────────────────
function main() {
  const opts = parseArgs();
  const { keyRVAs, cryptoHooks, l5Probes, topStrings } = loadXrefData(opts.xrefs);

  const script = buildScript(opts.target, keyRVAs, cryptoHooks, l5Probes, topStrings, opts.spawn);

  if (opts.out) {
    fs.mkdirSync(path.dirname(opts.out), { recursive: true });
    fs.writeFileSync(opts.out, script, "utf8");
  } else {
    process.stdout.write(script);
  }

  // Stats to stderr
  const onEnterCount = keyRVAs.filter(p => p.trigger === "call_on_enter").length;
  const onLeaveCount = keyRVAs.filter(p => p.trigger === "call_on_leave").length;
  const immediateCount = keyRVAs.filter(p => p.trigger === "immediate").length + l5Probes.length;

  if (opts.out) {
    console.error("[Phase 4c] Probe script generated: " + opts.out);
    console.error("  - " + keyRVAs.length + " RVA hooks (" + onEnterCount + " on_enter, " + onLeaveCount + " on_leave, " + immediateCount + " immediate)");
    console.error("  - " + cryptoHooks.length + " crypto function hooks");
    console.error("  - RegisterNatives interceptor");
    console.error("  - dlopen waiter: YES");
    console.error("  - Spawn mode: " + (opts.spawn ? "YES" : "NO"));
  }
}

main();
