/**
 * shell_classifier.js — APK 壳分类与脱壳引擎 (Phase 4a)
 *
 * 用法：
 *   node shell_classifier.js --apk <path> [--mode passive] [--json]
 *
 * 流程：
 *   1. 解压 APK（ZIP）到临时目录
 *   2. 解析 AndroidManifest.xml → Application 类名
 *   3. 对比已知壳的 Application 替换模式
 *   4. 扫描 lib/ .so 文件匹配壳加固特征
 *   5. 检查 assets/ 壳配置文件
 *   6. 综合打分，输出分类结果
 *
 * 输出：
 *   JSON 格式，包含壳名称、置信度、证据链、后续步骤推荐
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync } = require('child_process');
const dexParser = require('./dex_parser');
const shellDB = require('./shell_db');
const fridaPreset = require('./frida_preset');

// ═══════════════════════════════════════════════════════
// CLI 参数解析
// ═══════════════════════════════════════════════════════

function parseArgs() {
    const args = process.argv.slice(2);
    const cfg = {
        apkPath: null,
        mode: 'active',     // active | passive
        json: false,
        outputDir: null
    };

    for (let i = 0; i < args.length; i++) {
        switch (args[i]) {
            case '--apk':
                cfg.apkPath = args[++i] || null;
                break;
            case '--mode':
                cfg.mode = args[++i] || 'active';
                break;
            case '--json':
                cfg.json = true;
                break;
            case '--output':
                cfg.outputDir = args[++i] || null;
                break;
            case '--help':
            case '-h':
                printUsage();
                process.exit(0);
        }
    }

    if (!cfg.apkPath) {
        console.error('Error: --apk <path> is required');
        printUsage();
        process.exit(1);
    }

    if (!fs.existsSync(cfg.apkPath)) {
        console.error('Error: APK file not found:', cfg.apkPath);
        process.exit(1);
    }

    return cfg;
}

function printUsage() {
    console.log([
        'shell_classifier.js — APK Shell Classification Engine',
        '',
        'Usage:',
        '  node shell_classifier.js --apk <path> [--mode passive] [--json] [--output <dir>]',
        '',
        'Options:',
        '  --apk <path>      Path to the APK file to analyze',
        '  --mode <mode>     Analysis mode: active (default) or passive',
        '                     passive = static analysis only, no runtime hooks',
        '  --json             Output result as JSON only (no verbose logging)',
        '  --output <dir>     Output directory for generated Frida scripts',
        '',
        'Shell classification levels:',
        '  clean       No shell detected → proceed to Phase 4b (quick kill)',
        '  light_shell Light obfuscation / single-layer DEX encryption',
        '  heavy_shell Heavy shell (VMP / multi-layer) → Frida memory dump',
        '  unknown     No known fingerprint matched',
        '',
        'Examples:',
        '  node shell_classifier.js --apk app.apk --json',
        '  node shell_classifier.js --apk app.apk --mode passive --output ./output'
    ].join('\n'));
}

// ═══════════════════════════════════════════════════════
// 临时目录管理
// ═══════════════════════════════════════════════════════

function createTempDir() {
    const tmpRoot = path.join(os.tmpdir(), 'xcore_shell_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8));
    fs.mkdirSync(tmpRoot, { recursive: true });
    return tmpRoot;
}

function cleanupTempDir(dir) {
    try {
        if (fs.existsSync(dir)) {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    } catch (e) {
        console.error('[cleanup] Warning: could not remove temp dir:', dir, e.message);
    }
}

// ═══════════════════════════════════════════════════════
// DEX 结构快速检查（轻壳 vs 重壳判断）
// ═══════════════════════════════════════════════════════

/**
 * 快速检查 classes.dex 头部是否有效
 * 如果主 DEX 头部损坏/加密 → 必定是重壳
 */
function checkDexHeaders(apkPath) {
    const tmpDir = createTempDir();
    const results = {
        validDexCount: 0,
        invalidDexCount: 0,
        details: []
    };

    try {
        // 提取 classes.dex
        const psCmd = 'powershell -NoProfile -Command "'
            + 'Add-Type -AssemblyName System.IO.Compression.FileSystem;'
            + '$zip=[System.IO.Compression.ZipFile]::OpenRead(\'' + apkPath.replace(/'/g, "''") + '\');'
            + '$entries=$zip.Entries|Where-Object{$_.Name -match \'^classes\\d*\\.dex$\'};'
            + 'foreach($e in $entries){'
            + '  $outPath=\'' + tmpDir.replace(/\\/g, '\\\\') + '\\\\\'+$e.Name;'
            + '  $s=$e.Open();$ms=New-Object System.IO.MemoryStream;$s.CopyTo($ms);'
            + '  [System.IO.File]::WriteAllBytes($outPath,$ms.ToArray());$s.Close();$ms.Close();'
            + '  Write-Output $e.Name'
            + '};'
            + '$zip.Dispose()"';

        const out = execSync(psCmd, { encoding: 'utf-8', stdio: 'pipe' });
        const dexFiles = out.split(/\r?\n/).filter(l => l.trim());

        for (const dexName of dexFiles) {
            const dexPath = path.join(tmpDir, dexName);
            if (!fs.existsSync(dexPath)) continue;

            const buf = fs.readFileSync(dexPath);
            const detail = { file: dexName, size: buf.length, valid: false, magic: null };

            if (buf.length >= 8) {
                const magic = buf.toString('ascii', 0, 8);
                detail.magic = magic;

                // 标准 DEX 魔数
                if (magic.startsWith('dex\n')) {
                    detail.valid = true;
                    results.validDexCount++;
                }
                // Android 9+：035 和 037 版本的纯 dex 魔数
                else if (magic === 'dex\n035\x00' || magic === 'dex\n037\x00' || magic === 'dex\n038\x00' || magic === 'dex\n039\x00') {
                    detail.valid = true;
                    results.validDexCount++;
                } else {
                    detail.valid = false;
                    results.invalidDexCount++;
                    detail.reason = 'Non-standard DEX magic: ' + JSON.stringify(magic.slice(0, 4));
                }
            } else {
                detail.reason = 'File too small (< 8 bytes)';
                results.invalidDexCount++;
            }

            results.details.push(detail);
        }

        // 如果没有 DEX，但 APK 大小正常 → 大概率加固
        if (dexFiles.length === 0) {
            results.invalidDexCount = 99; // 标记为无 DEX
        }

    } catch (e) {
        results.error = e.message;
    }

    cleanupTempDir(tmpDir);
    return results;
}

// ═══════════════════════════════════════════════════════
// VMP 启发式检测
// ═══════════════════════════════════════════════════════

function detectVmpHeuristic(evidence) {
    const libs = (evidence.native_libs || []).map(l => l.toLowerCase());
    const indicators = [];

    // VMP 特征 1：同时存在 libdvm.so 和 libart.so（非标准行为）
    const hasDvm = libs.some(l => l.includes('libdvm.so'));
    const hasArt = libs.some(l => l.includes('libart.so'));
    if (hasDvm && hasArt) {
        indicators.push({
            type: 'vmp_indicator',
            detail: 'Both libdvm.so and libart.so present (VMP runtime replacement pattern)'
        });
    }

    // VMP 特征 2：存在 VMP 相关 so
    const vmpLibs = ['libvmpshield', 'libavmp', 'libvmp', 'libijm', 'libnqshield'];
    for (const vmpPat of vmpLibs) {
        if (libs.some(l => l.includes(vmpPat))) {
            indicators.push({
                type: 'vmp_indicator',
                detail: 'VMP-related .so found matching: ' + vmpPat
            });
        }
    }

    // VMP 特征 3：Application 类被替换为非标准包名（不含常见壳前缀）
    const appClass = (evidence.application_class || '').toLowerCase();
    const knownShellPrefixes = ['stub', 'proxy', 'wrapper', 'shell', 'secneo', 'protect', 'guard'];
    const hasKnownPrefix = knownShellPrefixes.some(p => appClass.includes(p));
    if (appClass && !hasKnownPrefix && (
        appClass.includes('application') ||
        appClass.includes('entry') ||
        appClass.split('.').length > 4
    )) {
        indicators.push({
            type: 'vmp_indicator',
            detail: 'Unusual Application class with deep package hierarchy: ' + appClass
        });
    }

    return indicators;
}

// ═══════════════════════════════════════════════════════
// 主分类流程
// ═══════════════════════════════════════════════════════

function classify(apkPath, mode) {
    const evidence = {
        apk_path: apkPath,
        application_class: null,
        entry_activity: null,
        permissions: [],
        package_name: null,
        native_libs: [],
        asset_files: [],
        dex_info: null,
        vmp_indicators: []
    };

    // Step 1: 解析 AndroidManifest
    const manifest = dexParser.parseManifest(apkPath);
    evidence.application_class = manifest.application_class || null;
    evidence.entry_activity = manifest.entry_activity || null;
    evidence.permissions = manifest.permissions || [];
    evidence.package_name = manifest.package_name || null;

    // Step 2: 获取 .so 文件列表
    evidence.native_libs = dexParser.getNativeLibs(apkPath);

    // Step 3: 获取 assets 文件列表
    evidence.asset_files = dexParser.listAssets(apkPath);

    // Step 4: 检查 DEX 头部
    evidence.dex_info = checkDexHeaders(apkPath);

    // Step 5: VMP 启发式检测
    evidence.vmp_indicators = detectVmpHeuristic(evidence);

    // Step 6: 指纹匹配
    const matches = shellDB.match(evidence);

    // Step 7: 判定分类
    const result = buildResult(apkPath, evidence, matches, mode);

    return { evidence, result };
}

/**
 * 根据匹配结果构建最终分类
 */
function buildResult(apkPath, evidence, matches, mode) {
    let shell = { name: 'unknown', confidence: 'none', evidence: [], recommendation: 'unknown' };
    let recommendation = 'unknown';
    let nextStep = 'manual_analysis';

    // 判断是否有壳
    const dexValid = (evidence.dex_info && evidence.dex_info.validDexCount > 0);
    const dexInvalid = (evidence.dex_info && evidence.dex_info.invalidDexCount > 0);
    const noDex = (evidence.dex_info && evidence.dex_info.invalidDexCount >= 99);
    const hasMatches = matches.length > 0;
    const vmpDetected = evidence.vmp_indicators.length > 0;

    if (hasMatches) {
        // 匹配到已知壳
        const top = matches[0];
        shell = {
            name: top.name + (top.version ? ' v' + top.version : ''),
            confidence: top.confidence,
            evidence: top.evidence,
            recommendation: top.recommendation
        };

        if (top.confidence === 'high') {
            if (top.recommendation === 'light_shell') {
                recommendation = 'light_shell';
                nextStep = 'quick_kill_direct';
            } else {
                recommendation = 'heavy_shell';
                nextStep = mode === 'passive' ? 'manual_analysis' : 'frida_dump';
            }
        } else {
            recommendation = 'heavy_shell';
            nextStep = mode === 'passive' ? 'manual_analysis' : 'frida_dump';
        }

    } else if (noDex) {
        // 无 DEX 但有 APK → 高度怀疑是重壳
        shell = {
            name: 'suspected_heavy_shell',
            confidence: 'medium',
            evidence: [{ type: 'dex_analysis', detail: 'No classes.dex found in APK; likely heavily packed' }],
            recommendation: 'heavy_shell'
        };
        recommendation = 'heavy_shell';
        nextStep = mode === 'passive' ? 'manual_analysis' : 'frida_dump';

    } else if (dexInvalid && !dexValid) {
        // DEX 全部损坏/加密
        shell = {
            name: 'encrypted_dex',
            confidence: 'high',
            evidence: [{ type: 'dex_analysis', detail: 'All DEX files have non-standard magic bytes; likely encrypted' }],
            recommendation: 'heavy_shell'
        };
        recommendation = 'heavy_shell';
        nextStep = mode === 'passive' ? 'manual_analysis' : 'frida_dump';

    } else if (vmpDetected) {
        // VMP 检测命中
        shell = {
            name: 'vmp_suspected',
            confidence: 'medium',
            evidence: evidence.vmp_indicators,
            recommendation: 'heavy_shell'
        };
        recommendation = 'heavy_shell';
        nextStep = mode === 'passive' ? 'manual_analysis' : 'frida_dump';

    } else if (!vmpDetected && !dexInvalid && evidence.application_class) {
        // 有 Application 类但不在已知壳中 → 可能是未知轻壳或混淆
        const hasSuspiciousLibs = (evidence.native_libs || []).some(l =>
            l.toLowerCase().includes('protect') ||
            l.toLowerCase().includes('guard') ||
            l.toLowerCase().includes('shield') ||
            l.toLowerCase().includes('encrypt')
        );

        if (hasSuspiciousLibs) {
            shell = {
                name: 'unknown_shell',
                confidence: 'low',
                evidence: [{ type: 'heuristic', detail: 'Suspicious native libraries found but no known fingerprint match' }],
                recommendation: 'light_shell'
            };
            recommendation = 'light_shell';
            nextStep = 'manual_analysis';
        } else {
            shell = {
                name: 'clean',
                confidence: 'high',
                evidence: [{ type: 'dex_analysis', detail: 'DEX valid, no known shell fingerprint matched' }],
                recommendation: 'clean'
            };
            recommendation = 'clean';
            nextStep = 'phase_4b_quick_kill';
        }

    } else {
        // 完全无特征 → clean
        shell = {
            name: 'clean',
            confidence: 'high',
            evidence: [{ type: 'dex_analysis', detail: 'No shell indicators detected' }],
            recommendation: 'clean'
        };
        recommendation = 'clean';
        nextStep = 'phase_4b_quick_kill';
    }

    return {
        apk: apkPath,
        package_name: evidence.package_name || 'unknown',
        shell: shell,
        recommendation: recommendation,
        next_step: nextStep,
        dex_status: {
            valid: evidence.dex_info ? evidence.dex_info.validDexCount : 0,
            invalid: evidence.dex_info ? evidence.dex_info.invalidDexCount : 0,
            details: evidence.dex_info ? evidence.dex_info.details : []
        },
        matches: matches.slice(0, 5).map(m => ({
            name: m.name,
            confidence: m.confidence,
            score: m.score
        })),
        mode: mode,
        timestamp: new Date().toISOString()
    };
}

// ═══════════════════════════════════════════════════════
// Frida 脚本生成
// ═══════════════════════════════════════════════════════

function generateFridaScript(result, outputDir) {
    const shellName = result.shell ? result.shell.name : 'unknown';
    const pkg = result.package_name || 'com.example.app';

    const fridaResult = fridaPreset.generate({
        shellName: shellName,
        packageName: pkg,
        outputDir: outputDir || path.join(__dirname, '..', '..', 'output')
    });

    // 确保输出目录存在
    const dir = path.dirname(fridaResult.path);
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }

    fs.writeFileSync(fridaResult.path, fridaResult.script, 'utf-8');
    return fridaResult;
}

// ═══════════════════════════════════════════════════════
// 入口
// ═══════════════════════════════════════════════════════

function main() {
    const cfg = parseArgs();

    // 加载指纹库
    const fingerprintDir = path.join(__dirname, '..', '..', 'rules', 'fingerprints', 'shells');
    shellDB.loadFingerprints(fingerprintDir);

    if (!cfg.json) {
        console.error('[shell_classifier] Analyzing:', cfg.apkPath);
        console.error('[shell_classifier] Mode:', cfg.mode);
    }

    const { evidence, result } = classify(cfg.apkPath, cfg.mode);

    // 生成 Frida 脚本（仅主动模式且需要 dump）
    let fridaInfo = null;
    if (cfg.mode !== 'passive' && result.next_step === 'frida_dump') {
        try {
            fridaInfo = generateFridaScript(result, cfg.outputDir);
            result.frida_script = fridaInfo.path;
            result.frida_spawn_cmd = fridaInfo.spawnCmd;
            result.frida_attach_cmd = fridaInfo.attachCmd;
        } catch (e) {
            result.frida_script_error = e.message;
        }
    }

    // 输出 JSON
    const output = JSON.stringify(result, null, 2);
    console.log(output);

    // 根据结果决定退出码
    if (result.recommendation === 'clean') {
        process.exit(0);
    } else if (result.recommendation === 'light_shell') {
        process.exit(2);
    } else {
        process.exit(3);
    }
}

// 直接运行时执行
if (require.main === module) {
    main();
}

module.exports = { classify, generateFridaScript };
