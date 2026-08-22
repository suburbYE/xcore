/**
 * universal_probe.js — xcore Universal Native Probe
 *
 * 通用 Frida 探针，不绑定特定 SO 或 RVA。
 * 运行时动态发现目标 SO 的 JNI 注册、crypto 导出符号、Java 层签名入口。
 *
 * 用法：
 *   Spawn: frida -U -f com.target.pkg -l universal_probe.js --no-pause
 *   Attach: frida -U com.target.pkg -l universal_probe.js
 *
 * 输出到控制台，用 frida -o output.log 重定向到文件。
 */

'use strict';

// ═══════════════════════ 配置 ═══════════════════════
var CONFIG = {
    // 目标 SO 文件名关键词（自动从已加载模块匹配）
    libKeywords: ["crypto", "sscronet", "xyass", "xEF4", "sgmain", "sgsecuritybody", "libshield", "libDingTalk", "libmeituan", "libmtguard", "libbaiduprotect"],

    // 需要监控的导出符号关键词
    exportKeywords: ["SHA256", "SHA1", "MD5", "HMAC", "AES", "EVP", "RSA", "ECDSA", "PKCS7", "sign", "encrypt", "decrypt", "hash", "cipher", "Crypto"],

    // Java 层疑似签名类名关键词
    javaSignKeywords: ["Sign", "sign", "Crypto", "crypto", "Security", "security", "Encrypt", "encrypt", "Hash", "hash", "NativeUtil", "native", "JNI", "jni", "Token", "token"],

    // 输出配置
    hexDumpMaxLen: 256,      // byte[] 参数 hex dump 最大长度
    stringMaxLen: 256,       // String 参数最大长度
    moduleLoadTimeout: 30000 // 等待目标 SO 加载超时（ms）
};

var hookedExports = {};
var hookedNatives = {};
var targetsFound = [];

// ═══════════════════ Module 1: SO 加载监控 ═══════════════════
(function() {
    var dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");
    if (!dlopen_ext) {
        console.log("[!] android_dlopen_ext not found — no SO load monitoring");
        return;
    }

    var keywordList = CONFIG.libKeywords;
    var foundSet = {};

    Interceptor.attach(dlopen_ext, {
        onEnter: function(args) {
            this.path = args[0] ? args[0].readCString() : "";
        },
        onLeave: function(retval) {
            var path = this.path;
            if (!path) return;

            for (var i = 0; i < keywordList.length; i++) {
                if (path.indexOf(keywordList[i]) !== -1 && !foundSet[path]) {
                    foundSet[path] = true;
                    console.log("[SO_LOAD] " + path);
                    targetsFound.push(path);

                    // 延迟安装 hook，确保 SO 完全初始化
                    setTimeout(function() {
                        installExportHooks(path);
                    }, 100);
                    break;
                }
            }
        }
    });

    console.log("[*] SO load monitor active, watching " + keywordList.length + " keywords");
})();

// ═══════════════════ Module 2: Crypto 导出符号自动 Hook ═══════════════════
function installExportHooks(soPath) {
    // 从路径提取 SO 名
    var soName = soPath.split("/").pop();
    var mod = Process.findModuleByName(soName);
    if (!mod) {
        console.log("[!] installExportHooks: " + soName + " not in memory yet");
        return;
    }

    var exports = mod.enumerateExports();
    var keywordList = CONFIG.exportKeywords;
    var hooked = 0;

    for (var i = 0; i < exports.length; i++) {
        var name = exports[i].name;
        if (!name || hookedExports[name]) continue;

        for (var k = 0; k < keywordList.length; k++) {
            if (name.indexOf(keywordList[k]) !== -1) {
                hookedExports[name] = true;
                hookExport(mod, name, exports[i].address);
                hooked++;
                break;
            }
        }
    }

    console.log("[EXPORT] " + soName + ": hooked " + hooked + " crypto exports");
}

function hookExport(mod, name, addr) {
    Interceptor.attach(addr, {
        onEnter: function(args) {
            var log = "[CRYPTO] " + name + "(";
            for (var i = 0; i < Math.min(4, arguments.length); i++) {
                var arg = args[i];
                if (arg && typeof arg === 'object' && arg.toInt32) {
                    log += "arg" + i + "=" + arg + "(" + arg.toInt32() + ") ";
                } else {
                    log += "arg" + i + "=" + arg + " ";
                }
            }
            log += ")";
            console.log(log);

            // 尝试 dump arg1 (常见为数据指针) + arg2 (常见为长度)
            if (args[1] && args[2]) {
                try {
                    var len = args[2].toInt32 ? args[2].toInt32() : parseInt(args[2]);
                    if (len > 0 && len <= 4096) {
                        var dumpLen = Math.min(len, CONFIG.hexDumpMaxLen);
                        var bytes = args[1].readByteArray(dumpLen);
                        if (bytes) {
                            console.log("  data[" + len + "]: " + hexdump(bytes, {
                                offset: 0, length: dumpLen, header: false, ansi: false
                            }).replace(/\n/g, "\n  "));
                        }
                    }
                } catch(e) {}
            }
        }
    });
}

// ═══════════════════ Module 3: RegisterNatives 动态 JNI 拦截 ═══════════════════
(function() {
    var RegisterNatives = Module.findExportByName(null, "RegisterNatives");
    if (!RegisterNatives) {
        console.log("[!] RegisterNatives not found");
        return;
    }

    Interceptor.attach(RegisterNatives, {
        onEnter: function(args) {
            var env = args[0];
            var class_name_ptr = args[1];
            var methods_ptr = args[2];
            var num_methods = args[3].toInt32();

            if (num_methods <= 0 || num_methods > 500) return;

            var class_name;
            try {
                class_name = Java.vm.tryGetEnv().getStringUtfChars(class_name_ptr, null).readCString();
            } catch(e) { return; }

            // 过滤：仅关注疑似签名/加密/安全类
            var matched = false;
            for (var k = 0; k < CONFIG.javaSignKeywords.length; k++) {
                if (class_name.toLowerCase().indexOf(CONFIG.javaSignKeywords[k].toLowerCase()) !== -1) {
                    matched = true;
                    break;
                }
            }
            if (!matched) return;

            console.log("\n═══ [RegisterNatives] " + class_name + " (" + num_methods + " methods) ═══");

            for (var i = 0; i < num_methods; i++) {
                var entry = methods_ptr.add(i * Process.pointerSize * 3);
                var name_ptr = entry.readPointer();
                var sig_ptr = entry.add(Process.pointerSize).readPointer();
                var fn_ptr = entry.add(Process.pointerSize * 2).readPointer();

                if (name_ptr.isNull() || sig_ptr.isNull() || fn_ptr.isNull()) continue;

                var methodName = name_ptr.readCString();
                var methodSig = sig_ptr.readCString();
                var key = class_name + "." + methodName;

                if (hookedNatives[key]) continue;
                hookedNatives[key] = true;

                console.log("  [" + i + "] " + methodName + " :: " + methodSig + " → " + fn_ptr);

                hookJNIMethod(class_name, methodName, methodSig, fn_ptr);
            }
        }
    });

    console.log("[*] RegisterNatives hook installed");
})();

function hookJNIMethod(className, methodName, methodSig, fnPtr) {
    var key = className + "." + methodName;
    var parsed = parseJNISignature(methodSig);
    if (!parsed) return;

    Interceptor.attach(fnPtr, {
        onEnter: function(args) {
            var log = "┌─ " + key + " ENTER ───────";
            console.log(log);

            // args[0]=JNIEnv, args[1]=jclass/jobject
            for (var i = 0; i < parsed.args.length && i < 6; i++) {
                var t = parsed.args[i];
                var val = args[2 + i];
                dumpJNIArg(i, t, val);
            }

            this._key = key;
            this._retType = parsed.ret;
        },
        onLeave: function(retval) {
            var retType = this._retType;
            if (retType === '[' && retval && !retval.isNull()) {
                try {
                    var jArr = Java.array('byte', retval);
                    var hex = bytesToHex(jArr.slice(0, Math.min(jArr.length, CONFIG.hexDumpMaxLen)));
                    console.log("│  RETURN byte[" + jArr.length + "]: " + hex + (jArr.length > CONFIG.hexDumpMaxLen ? "..." : ""));
                } catch(e) {
                    console.log("│  RETURN (byte[]): read error");
                }
            } else if ((retType === 'L' || retType === 'Ljava/lang/String;') && retval && !retval.isNull()) {
                try {
                    var s = Java.vm.tryGetEnv().getStringUtfChars(retval, null).readCString();
                    console.log("│  RETURN String: " + s.slice(0, CONFIG.stringMaxLen));
                } catch(e) {
                    console.log("│  RETURN (String): read error");
                }
            } else if (retType === 'I' || retType === 'Z') {
                console.log("│  RETURN (int): " + retval + " (0x" + retval.toString(16) + ")");
            } else {
                console.log("│  RETURN (" + retType + "): " + retval);
            }
            console.log("└──────────────────────────────────────");
        }
    });
}

function dumpJNIArg(idx, type, val) {
    if (type === '[') {
        // byte[] — 最关键
        if (val && !val.isNull()) {
            try {
                var jArr = Java.array('byte', val);
                var hex = bytesToHex(jArr.slice(0, Math.min(jArr.length, CONFIG.hexDumpMaxLen)));
                console.log("│  arg" + idx + " byte[" + jArr.length + "]: " + hex + (jArr.length > CONFIG.hexDumpMaxLen ? "..." : ""));
            } catch(e) {
                console.log("│  arg" + idx + " byte[]: (read error)");
            }
        } else {
            console.log("│  arg" + idx + " byte[]: null");
        }
    } else if (type === 'L') {
        if (val && !val.isNull()) {
            try {
                var s = Java.vm.tryGetEnv().getStringUtfChars(val, null).readCString();
                console.log("│  arg" + idx + " String: \"" + s.slice(0, CONFIG.stringMaxLen) + "\"");
            } catch(e) {
                console.log("│  arg" + idx + " (Object): " + val);
            }
        } else {
            console.log("│  arg" + idx + " (Object): null");
        }
    } else if (type === 'I' || type === 'Z') {
        console.log("│  arg" + idx + " (int): " + val + " (0x" + val.toString(16) + ")");
    } else if (type === 'J') {
        console.log("│  arg" + idx + " (long): " + val + " (0x" + val.toString(16) + ")");
    } else {
        console.log("│  arg" + idx + " (" + type + "): " + val);
    }
}

// ═══════════════════ Module 4: Java 层签名方法 Hook ═══════════════════
Java.perform(function() {
    var seen = {};

    function hookJavaSignMethods() {
        Java.enumerateLoadedClasses({
            onMatch: function(className) {
                if (seen[className]) return;
                var matched = false;
                for (var k = 0; k < CONFIG.javaSignKeywords.length; k++) {
                    if (className.indexOf(CONFIG.javaSignKeywords[k]) !== -1) {
                        matched = true;
                        break;
                    }
                }
                if (!matched) return;
                seen[className] = true;

                try {
                    var cls = Java.use(className);
                    var methods = cls.class.getDeclaredMethods();
                    var hooked = 0;
                    methods.forEach(function(m) {
                        var mName = m.getName();
                        var overloads = cls[mName].overloads;
                        overloads.forEach(function(overload) {
                            overload.implementation = function() {
                                console.log("\n═══ [JAVA] " + className + "." + mName + " ═══");
                                for (var a = 0; a < arguments.length; a++) {
                                    var arg = arguments[a];
                                    if (arg === null || arg === undefined) {
                                        console.log("  arg[" + a + "] null");
                                    } else if (arg.getClass && arg.getClass().getName() === "[B") {
                                        var ba = Java.array('byte', arg);
                                        var hex = bytesToHex(ba.slice(0, Math.min(ba.length, CONFIG.hexDumpMaxLen)));
                                        console.log("  arg[" + a + "] byte[" + ba.length + "]: " + hex + (ba.length > CONFIG.hexDumpMaxLen ? "..." : ""));
                                    } else {
                                        var s = String(arg);
                                        console.log("  arg[" + a + "] " + (arg.getClass ? arg.getClass().getName() : typeof arg) + ": " + s.slice(0, CONFIG.stringMaxLen));
                                    }
                                }
                                var result = this[mName].apply(this, arguments);
                                if (result !== null && result !== undefined) {
                                    if (result.getClass && result.getClass().getName() === "[B") {
                                        var rba = Java.array('byte', result);
                                        console.log("  RETURN byte[" + rba.length + "]: " + bytesToHex(rba.slice(0, Math.min(rba.length, CONFIG.hexDumpMaxLen))));
                                    } else {
                                        console.log("  RETURN: " + String(result).slice(0, CONFIG.stringMaxLen));
                                    }
                                }
                                console.log("════════════════════════════════════");
                                return result;
                            };
                            hooked++;
                        });
                    });
                    if (hooked > 0) {
                        console.log("[JAVA] " + className + ": hooked " + hooked + " methods");
                    }
                } catch(e) {
                    // Class not loadable — that's fine
                }
            },
            onComplete: function() {
                console.log("[*] Java class enumeration complete");
            }
        });
    }

    // 延迟执行，等待 App 初始化
    setTimeout(hookJavaSignMethods, 2000);
});

// ═══════════════════ Module 5: 异常处理 + Spawn 支持 ═══════════════════
(function() {
    Process.setExceptionHandler(function(details) {
        // 静默吞掉 SIGSEGV，避免 frida 挂掉
        console.log("[!] Exception: " + details.type + " at " + details.address);
        return false;
    });

    // 已加载模块检查
    var existingMods = Process.enumerateModules();
    for (var i = 0; i < existingMods.length; i++) {
        var name = existingMods[i].name;
        for (var k = 0; k < CONFIG.libKeywords.length; k++) {
            if (name.indexOf(CONFIG.libKeywords[k]) !== -1) {
                targetsFound.push(name);
                console.log("[SO_EXIST] " + name + " @ " + existingMods[i].base);
                setTimeout((function(n) { return function() { installExportHooks(n); }; })(name), 100);
                break;
            }
        }
    }

    // 定期扫描新加载的模块（兜底 dlopen 遗漏的）
    var scannedSet = {};
    function periodicScan() {
        var mods = Process.enumerateModules();
        for (var i = 0; i < mods.length; i++) {
            var name = mods[i].name;
            if (scannedSet[name]) continue;
            for (var k = 0; k < CONFIG.libKeywords.length; k++) {
                if (name.indexOf(CONFIG.libKeywords[k]) !== -1) {
                    scannedSet[name] = true;
                    console.log("[SO_LATE] " + name + " @ " + mods[i].base);
                    installExportHooks(name);
                    break;
                }
            }
        }
    }
    setInterval(periodicScan, 3000);

    console.log("[*] Exception handler active");
})();

// ═══════════════════ Helpers ═══════════════════
function bytesToHex(bytes) {
    var hex = [];
    for (var i = 0; i < bytes.length; i++) {
        var b = bytes[i] & 0xFF;
        hex.push((b < 16 ? '0' : '') + b.toString(16));
    }
    return hex.join(' ');
}

function parseJNISignature(sig) {
    var m = sig.match(/^\(([^)]*)\)(.+)$/);
    if (!m) return null;

    var argsStr = m[1];
    var retStr = m[2];
    var args = [];
    var i = 0;

    while (i < argsStr.length) {
        var c = argsStr[i];
        if (c === '[') {
            args.push('[');
            i++;
            if (argsStr[i] === 'L') {
                while (i < argsStr.length && argsStr[i] !== ';') i++;
                i++;
            } else {
                i++;
            }
        } else if (c === 'L') {
            args.push('L');
            while (i < argsStr.length && argsStr[i] !== ';') i++;
            i++;
        } else {
            args.push(c);
            i++;
        }
    }

    var ret = (retStr[0] === '[') ? '[' :
              (retStr[0] === 'L') ? 'L' : retStr;

    return { args: args, ret: ret };
}

// ═══════════════════ 启动 ═══════════════════
console.log("\n╔══════════════════════════════════════════╗");
console.log("║  xcore Universal Native Probe v1.0      ║");
console.log("║  动态发现 · 零 RVA 绑定 · 通用适配       ║");
console.log("╚══════════════════════════════════════════╝\n");
console.log("[*] Target SO keywords: " + CONFIG.libKeywords.join(", "));
console.log("[*] Export keywords: " + CONFIG.exportKeywords.join(", "));
console.log("[*] Java sign keywords: " + CONFIG.javaSignKeywords.join(", "));
console.log("[*] Ready — waiting for SO loads & JNI registrations...\n");
