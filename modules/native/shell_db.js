/**
 * shell_db.js — 壳特征数据库查询
 *
 * 加载 rules/fingerprints/shells/ 下所有 *.json 指纹文件，
 * 提供 match() 方法对证据列表进行匹配打分。
 */

const fs = require('fs');
const path = require('path');

let fingerprints = [];
let loaded = false;

/**
 * 加载所有指纹文件
 * @param {string|null} dir - 指纹目录路径，默认 ../rules/fingerprints/shells
 */
function loadFingerprints(dir) {
    if (!dir) {
        dir = path.join(__dirname, '..', '..', 'rules', 'fingerprints', 'shells');
    }

    fingerprints = [];

    if (!fs.existsSync(dir)) {
        console.error('[shell_db] Fingerprint directory not found:', dir);
        return;
    }

    const files = fs.readdirSync(dir).filter(f => f.endsWith('.json') && f !== 'manifest.json');

    for (const file of files) {
        try {
            const data = fs.readFileSync(path.join(dir, file), 'utf-8');
            const fp = JSON.parse(data);
            if (fp.name && fp.application_classes) {
                fingerprints.push(fp);
            }
        } catch (e) {
            console.error('[shell_db] Failed to load fingerprint:', file, e.message);
        }
    }

    loaded = true;
    console.error('[shell_db] Loaded', fingerprints.length, 'fingerprints');
}

/**
 * 根据证据列表匹配已知壳
 *
 * @param {object} evidence - 收集到的证据
 * @param {string|null} evidence.application_class - AndroidManifest 中的 Application 类名
 * @param {string[]} evidence.native_libs - lib/ 下的 .so 文件名列表
 * @param {string[]} evidence.asset_files - assets/ 下的文件列表
 * @param {string} evidence.package_name - 包名（可选）
 *
 * @returns {object[]} 匹配结果数组，按置信度降序排列
 */
function match(evidence) {
    if (!loaded) loadFingerprints();

    const results = [];
    const appClass = evidence.application_class || '';
    const libs = (evidence.native_libs || []).map(l => path.basename(l, '.so').toLowerCase());
    const assets = (evidence.asset_files || []).map(a => a.toLowerCase());
    const pkg = (evidence.package_name || '').toLowerCase();

    for (const fp of fingerprints) {
        const matches = [];
        let score = 0;
        const weight = fp.confidence_weight || 1.0;

        // 1. Application 类名匹配
        if (fp.application_classes && fp.application_classes.length > 0) {
            for (const cls of fp.application_classes) {
                if (appClass.includes(cls) || cls.includes(appClass)) {
                    matches.push({ type: 'application_class', detail: cls });
                    score += 3 * weight;
                    break;
                }
            }
        }

        // 2. Native .so 匹配
        if (fp.native_libs && fp.native_libs.length > 0) {
            let libScore = 0;
            for (const libPat of fp.native_libs) {
                const pat = libPat.toLowerCase().replace('.so', '');
                for (const lib of libs) {
                    if (lib.includes(pat) || pat.includes(lib)) {
                        matches.push({ type: 'native_lib', detail: libPat });
                        libScore += 2;
                    }
                }
            }
            score += libScore * weight;
        }

        // 3. Assets 模式匹配
        if (fp.asset_patterns && fp.asset_patterns.length > 0) {
            let assetScore = 0;
            for (const pat of fp.asset_patterns) {
                const p = pat.toLowerCase();
                for (const a of assets) {
                    if (a.includes(p)) {
                        matches.push({ type: 'asset_file', detail: a });
                        assetScore += 1;
                    }
                }
            }
            score += assetScore * weight;
        }

        // 4. DEX 模式匹配（如果有）
        if (fp.dex_patterns && fp.dex_patterns.length > 0) {
            let dexScore = 0;
            for (const dp of fp.dex_patterns) {
                const p = dp.toLowerCase();
                if (appClass.includes(p) || pkg.includes(p)) {
                    matches.push({ type: 'dex_pattern', detail: dp });
                    dexScore += 1;
                }
            }
            score += dexScore * weight;
        }

        // 5. 包名模式匹配（针对壳厂商的包名特征）
        if (fp.package_patterns && fp.package_patterns.length > 0) {
            for (const pp of fp.package_patterns) {
                if (pkg.includes(pp.toLowerCase())) {
                    matches.push({ type: 'package_pattern', detail: pp });
                    score += 2 * weight;
                }
            }
        }

        if (score > 0) {
            results.push({
                name: fp.name,
                version: fp.version || 'unknown',
                score: score,
                confidence: score >= 5 ? 'high' : (score >= 3 ? 'medium' : 'low'),
                evidence: matches,
                recommendation: fp.recommendation || 'heavy_shell'
            });
        }
    }

    // 按分数降序排列
    results.sort((a, b) => b.score - a.score);

    return results;
}

/**
 * 获取所有已知壳名称列表
 */
function listShells() {
    if (!loaded) loadFingerprints();
    return fingerprints.map(fp => ({
        name: fp.name,
        version: fp.version || 'unknown',
        recommendation: fp.recommendation || 'heavy_shell'
    }));
}

module.exports = { loadFingerprints, match, listShells };
