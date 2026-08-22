# X-Core Rule Engine

本地化高敏逆向运行时：规则扫描 + LLM 分类 + SQLite 判例库 + 自然语言审讯台 + 控制流去混淆 + Native 壳/靶心分析 + Frida 探针生成。

一个把「二进制特征识别 → 算法归类 → 经验沉淀 → 反混淆对抗」串成一条链的本地工具。全部逻辑跑在本地，LLM 分类依赖本地 Ollama，可选云端降级。

## 特性

- **多维度规则扫描**：C++ 引擎对二进制做 hex / string / entropy 多维度匹配，Boyer-Moore 预构造复用，双门判定（阈值 + 置信度）
- **L2 分层指纹**：L1 hex 命中 → ±256B 窗口内 L2 精确匹配 → 输出算法实现细节（库名 / 版本 / 输出格式）
- **LLM 分类**：本地 Ollama 多模型三级降级（3B → 7B → 云端），WinHTTP 零外部依赖
- **SQLite 判例库**：SHA-256 去重 + Jaccard 相似匹配，历史结论自动沉淀，避免重复分析
- **X-Chat 审讯台**：自然语言交互层，一条命令完成 scan / ask / learn / report 全链路
- **控制流去混淆**：五阶段流水线（AST 插桩 → VM 沙盒 trace → C++ 原生 flatten → 死分支剔除 → 自动等价性验证）
- **Native 分析**：APK 壳分类（6 类壳指纹）、密码学靶心定位（L1–L5 多维度）、Frida 动态探针一键生成
- **OLLVM 14 工具链**：本地编译混淆样本，自建指纹库（可选）

## 项目结构

```
xcore/
├── src/                # C++ 核心引擎（规则扫描 / LLM 通信 / 判例库 / flatten / verifier）
├── xchat/              # Python 自然语言交互审讯台（统一入口）
├── modules/
│   ├── deobfuscator/   # JS 控制流去混淆流水线
│   └── native/         # 壳分类 + 靶心扫描 + Frida 探针生成
├── rules/              # 指纹规则库（通用密码学 + 壳指纹）
│   └── fingerprints/
├── scripts/            # 辅助脚本
├── tools/              # 判例库工具
├── tests/              # 测试
├── build.bat           # 构建脚本
└── README.md
```

## 环境依赖

| 组件 | 版本 | 用途 |
|---|---|---|
| Windows | 10/11 x64 | 运行平台 |
| Visual Studio 2022 | 17.x (MSVC v143) | C++ 编译 |
| CMake | 3.20+ / Ninja | 构建 |
| Python | 3.10+ | xchat 交互层 |
| Node.js | 18+ | deobfuscator 模块 |
| Ollama | 0.x | 本地 LLM（qwen2.5:3b/7b/14b） |

```powershell
# Python 依赖
pip install -r xchat\requirements.txt

# 环境变量（xchat 需要）
$env:PYTHONPATH = "C:\path\to\xcore"

# Ollama 模型
ollama pull qwen2.5:3b
ollama pull qwen2.5:7b

# Node 依赖
npm install                              # 根目录：adm-zip
cd modules\deobfuscator && npm install   # acorn
```

C++ 依赖（sqlite3 / nlohmann-json）已内置源码树，无需额外安装。

## 构建

```
build.bat
```

## 使用

```
xcore scan     <file> <rules.json> [--fingerprints-dir <dir>] [--model <m>] [--db <path>] [--brief] [--json]
xcore pipe     <rules.json> [--fingerprints-dir <dir>] [--model <m>] [--db <path>]
xcore db       stats [--db <path>]
xcore classify <file> <rules.json> [--model <m>] [--db <path>]
xcore deobfuscate <input.js> --output <dir> [--freeze] [--raw]
xcore native    --apk <path> [--mode passive] [--json]
xcore native    --so <path> [--fingerprints-dir <dir>] [--json]
xcore native    --generate-probe <scan.json> [--out <script.js>] [--spawn]
xcore verify   <orig.js> <unflattened.js>
xcore help
```

日常使用直接输入 `xchat` 进入自然语言交互。

## Roadmap

- [ ] **大文件全量扫描**：移除 Native scanner 的 64KB 截断，支持 200MB+ 二进制全量扫描
- [ ] **LLM 降噪**：learn 前置滤网 + 置信度降权，消除对 VM 字节码的幻影识别（"我不知道"能力）
- [ ] **PE 格式检测**：完整解析 MZ 魔数 + IMAGE_FILE_HEADER
- [ ] **IL2CPP metadata 解析**：利用 global-metadata.dat 恢复符号

## License

MIT
