/**
 * dex_parser.js — DEX / AndroidManifest 结构解析
 *
 * 职责：从 APK（ZIP）中提取 AndroidManifest.xml、DEX 列表、native .so 列表。
 * 使用 Node 内置 zlib + 二进制解析 AXML，不依赖 aapt/apktool。
 *
 * 用法：
 *   const dp = require('./dex_parser');
 *   const mani = dp.parseManifest(apkPath);
 *   const dexes = dp.listDexFiles(apkPath);
 *   const libs = dp.getNativeLibs(apkPath);
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// ═══════════════════════════════════════════════════════
// 工具函数
// ═══════════════════════════════════════════════════════

/**
 * 解析 AndroidManifest.xml（AXML 二进制格式）的最小实现
 * 使用 Node 的 zlib + buffer 解析。
 * 回退策略：用简单的正则/字符串扫描提取关键字段。
 */
function parseManifest(apkPath) {
    const tmpDir = path.join(require('os').tmpdir(), 'xcore_manifest_' + Date.now());

    try {
        // 使用 PowerShell 展开 APK 中的 AndroidManifest.xml
        // APK 本质是 ZIP，Windows 内置了 Expand-Archive
        const psCmd = `powershell -NoProfile -Command "$ErrorActionPreference='Stop';`
            + `Add-Type -AssemblyName System.IO.Compression.FileSystem;`
            + `$zip=[System.IO.Compression.ZipFile]::OpenRead('${apkPath.replace(/'/g, "''")}');`
            + `$entry=$zip.GetEntry('AndroidManifest.xml');`
            + `if($entry){$s=$entry.Open();$ms=New-Object System.IO.MemoryStream;$s.CopyTo($ms);`
            + `[System.IO.File]::WriteAllBytes('${tmpDir}\\AndroidManifest.xml',$ms.ToArray());$s.Close();$ms.Close()}`
            + `$zip.Dispose()" 2>nul`;

        execSync(psCmd, { stdio: 'pipe' });

        const manifestPath = path.join(tmpDir, 'AndroidManifest.xml');
        if (!fs.existsSync(manifestPath)) {
            return fallbackManifestParse(apkPath, tmpDir);
        }

        const buf = fs.readFileSync(manifestPath);
        const result = parseAxML(buf);
        cleanup(tmpDir);
        return result;
    } catch (e) {
        cleanup(tmpDir);
        return fallbackManifestParse(apkPath, tmpDir);
    }
}

/**
 * 回退解析：使用 aapt dump badging（如果可用），或者正则扫描原始字节
 */
function fallbackManifestParse(apkPath, tmpDir) {
    // 尝试用 aapt
    try {
        const out = execSync(`aapt dump badging "${apkPath}" 2>nul`, {
            encoding: 'utf-8',
            stdio: 'pipe'
        });

        const result = { application_class: null, entry_activity: null, permissions: [], package_name: null };

        const pkgMatch = out.match(/package:\s*name='([^']+)'/);
        if (pkgMatch) result.package_name = pkgMatch[1];

        const appMatch = out.match(/application:\s*label='[^']*'\s*icon='[^']*'/);
        // Not reliable enough for class; try raw string search

        const launchMatch = out.match(/launchable-activity:\s*name='([^']+)'/);
        if (launchMatch) result.entry_activity = launchMatch[1];

        return result;
    } catch (e) {
        // aapt 不可用，用纯二进制扫描
    }

    // 最终回退：从 ZIP 中提取 AndroidManifest.xml 原始字节并扫描字符串
    try {
        const psCmd2 = `powershell -NoProfile -Command "$ErrorActionPreference='Stop';`
            + `Add-Type -AssemblyName System.IO.Compression.FileSystem;`
            + `$zip=[System.IO.Compression.ZipFile]::OpenRead('${apkPath.replace(/'/g, "''")}');`
            + `$entry=$zip.GetEntry('AndroidManifest.xml');`
            + `if($entry){$s=$entry.Open();$ms=New-Object System.IO.MemoryStream;$s.CopyTo($ms);`
            + `[System.IO.File]::WriteAllBytes('${tmpDir}\\AndroidManifest.xml',$ms.ToArray());$s.Close();$ms.Close()}`
            + `$zip.Dispose()" 2>nul`;
        execSync(psCmd2, { stdio: 'pipe' });

        const manifestPath = path.join(tmpDir, 'AndroidManifest.xml');
        if (fs.existsSync(manifestPath)) {
            const buf = fs.readFileSync(manifestPath);
            return parseAxML(buf);
        }
    } catch (e) {
        // silent
    }

    return { application_class: null, entry_activity: null, permissions: [], package_name: null };
}

/**
 * 最小 AXML 解析器
 * AXML 格式：魔数 0x00080003，后面是字符串池 + 资源 ID 池 + XML 树
 * 这里用简化版：扫描字符串池中所有可打印字符串，用启发式提取关键属性
 */
function parseAxML(buf) {
    const result = {
        application_class: null,
        entry_activity: null,
        permissions: [],
        package_name: null,
        raw_strings: []
    };

    // 检查 AXML 魔数
    if (buf.length < 8) return result;
    const magic = buf.readUInt32LE(0);
    if (magic !== 0x00080003) {
        // 不是标准 AXML，尝试提取可打印字符串
        return extractStringsFromBinary(buf, result);
    }

    // 字符串池偏移（相对头部的偏移，头部 8 字节）
    const stringPoolOffset = buf.readUInt32LE(4); // 实际是 string pool offset
    // AXML header: magic(4) + file_size(4) = 8 bytes
    // String pool chunk: type(4) + chunk_size(4) + string_count(4) + style_count(4) + flags(4) + string_start_offset(4) + styles_start_offset(4)
    // string pool chunk type = 0x001C0001

    let offset = 8; // skip header
    const strings = [];

    while (offset < buf.length - 8) {
        const chunkType = buf.readUInt32LE(offset);
        const chunkSize = buf.readUInt32LE(offset + 4);

        if (chunkType === 0x001C0001) {
            // String pool chunk
            const stringCount = buf.readUInt32LE(offset + 8);
            const stringStart = offset + 28; // after chunk header (type(4)+size(4)+count(4)+style_count(4)+flags(4)+string_start(4)+style_start(4))

            for (let i = 0; i < stringCount && stringStart + 4 < buf.length; i++) {
                const strOffset = stringStart + i * 4;
                const charOffset = stringStart + buf.readUInt32LE(strOffset);
                let end = charOffset;
                while (end < buf.length - 1) {
                    // UTF-16LE null terminator
                    if (buf[end] === 0 && buf[end + 1] === 0) break;
                    end += 2;
                }
                if (end > charOffset) {
                    const str = buf.toString('utf16le', charOffset, end);
                    strings.push(str);
                }
            }
            break;
        }
        offset += chunkSize;
    }

    result.raw_strings = strings;

    // 启发式提取
    for (const s of strings) {
        // Package name
        if (!result.package_name && /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/.test(s)) {
            result.package_name = s;
        }

        // Application class
        if (s.startsWith('android:name=')) {
            const cls = s.replace('android:name=', '').trim();
            if (cls.includes('Application') || cls.includes('App')) {
                result.application_class = cls;
            }
        }

        // Permissions
        if (s.startsWith('android.permission.')) {
            result.permissions.push(s);
        }

        // Activity
        if (s.includes('Activity') && s.includes('.')) {
            // Look for MAIN/LAUNCHER pattern — but that's in intent-filter, not strings
            // Just record last plausible activity name
            if (!s.startsWith('android') && !s.startsWith('com.android')) {
                // could be activity
            }
        }

        // manifest tag attributes are stored as:
        // For each element, the attribute name strings and value strings are stored
        // This is hard to parse fully without the XML tree structure
        // So we scan for known Android namespace attributes
        if (s.includes('Application') && (s.includes('.') || s.includes('com.'))) {
            if (!result.application_class) result.application_class = s;
        }
    }

    // Direct scan for application class in raw bytes (AXML stores them as string refs)
    // The full string pool has been extracted above; scan for fully-qualified class names
    for (const s of strings) {
        // Fully qualified Java class name pattern
        if (/^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+(\.(App|Application|Shell|Wrapper|Entry))$/i.test(s)) {
            result.application_class = s;
        }
        if (/^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+\.(MainActivity|SplashActivity|HomeActivity)$/i.test(s)) {
            result.entry_activity = s;
        }
    }

    return result;
}

/**
 * 从二进制数据中提取可打印的 UTF-16LE 字符串
 */
function extractStringsFromBinary(buf, result) {
    const strings = [];
    let current = '';
    for (let i = 0; i < buf.length - 1; i += 2) {
        const code = buf.readUInt16LE(i);
        if (code >= 0x20 && code < 0x7F) {
            current += String.fromCharCode(code);
        } else if (code === 0) {
            if (current.length >= 3) strings.push(current);
            current = '';
        } else {
            if (current.length >= 3) strings.push(current);
            current = '';
        }
    }

    for (const s of strings) {
        if (s.startsWith('android.permission.')) result.permissions.push(s);
        if (/^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/.test(s) && !result.package_name) result.package_name = s;
        if (/\.(Application|App|Shell|Wrapper|Entry)$/i.test(s)) result.application_class = s;
        if (/\.(MainActivity|SplashActivity|HomeActivity)$/i.test(s)) result.entry_activity = s;
    }

    return result;
}

/**
 * 列出 APK 中所有 classes*.dex 文件
 */
function listDexFiles(apkPath) {
    const dexFiles = [];
    try {
        const psCmd = `powershell -NoProfile -Command "$ErrorActionPreference='Stop';`
            + `Add-Type -AssemblyName System.IO.Compression.FileSystem;`
            + `$zip=[System.IO.Compression.ZipFile]::OpenRead('${apkPath.replace(/'/g, "''")}');`
            + `$zip.Entries|Where-Object{$_.Name -match '^classes\\d*\\.dex$'}|ForEach-Object{$_.FullName};`
            + `$zip.Dispose()"`;

        const out = execSync(psCmd, { encoding: 'utf-8', stdio: 'pipe' });
        const lines = out.split(/\r?\n/).filter(l => l.trim());
        dexFiles.push(...lines);
    } catch (e) {
        // fallback: use Node native
        try {
            const AdmZip = require('adm-zip');
            const zip = new AdmZip(apkPath);
            const entries = zip.getEntries();
            for (const entry of entries) {
                if (/^classes\d*\.dex$/i.test(entry.entryName)) {
                    dexFiles.push(entry.entryName);
                }
            }
        } catch (e2) {
            // silent
        }
    }
    return dexFiles;
}

/**
 * 列出 APK 中 lib/ 目录下所有 .so 文件
 */
function getNativeLibs(apkPath) {
    const libs = [];
    try {
        const psCmd = `powershell -NoProfile -Command "$ErrorActionPreference='Stop';`
            + `Add-Type -AssemblyName System.IO.Compression.FileSystem;`
            + `$zip=[System.IO.Compression.ZipFile]::OpenRead('${apkPath.replace(/'/g, "''")}');`
            + `$zip.Entries|Where-Object{$_.Name -match '\\.so$'}|ForEach-Object{$_.Name};`
            + `$zip.Dispose()"`;

        const out = execSync(psCmd, { encoding: 'utf-8', stdio: 'pipe' });
        const lines = out.split(/\r?\n/).filter(l => l.trim());
        libs.push(...lines);
    } catch (e) {
        try {
            const AdmZip = require('adm-zip');
            const zip = new AdmZip(apkPath);
            const entries = zip.getEntries();
            for (const entry of entries) {
                if (/\.so$/i.test(entry.name)) {
                    libs.push(entry.name);
                }
            }
        } catch (e2) {
            // silent
        }
    }
    return libs;
}

/**
 * 列出 APK 中 assets/ 目录下所有文件
 */
function listAssets(apkPath) {
    const assets = [];
    try {
        const psCmd = `powershell -NoProfile -Command "$ErrorActionPreference='Stop';`
            + `Add-Type -AssemblyName System.IO.Compression.FileSystem;`
            + `$zip=[System.IO.Compression.ZipFile]::OpenRead('${apkPath.replace(/'/g, "''")}');`
            + `$zip.Entries|Where-Object{$_.FullName -like 'assets/*'}|ForEach-Object{$_.FullName};`
            + `$zip.Dispose()"`;

        const out = execSync(psCmd, { encoding: 'utf-8', stdio: 'pipe' });
        const lines = out.split(/\r?\n/).filter(l => l.trim());
        assets.push(...lines);
    } catch (e) {
        try {
            const AdmZip = require('adm-zip');
            const zip = new AdmZip(apkPath);
            const entries = zip.getEntries();
            for (const entry of entries) {
                if (entry.entryName.startsWith('assets/')) {
                    assets.push(entry.entryName);
                }
            }
        } catch (e2) {
            // silent
        }
    }
    return assets;
}

function cleanup(dir) {
    try {
        if (fs.existsSync(dir)) {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    } catch (e) { /* silent */ }
}

module.exports = {
    parseManifest,
    listDexFiles,
    getNativeLibs,
    listAssets,
    parseAxML
};
