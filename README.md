# X-Core · 本地化逆向分析运行时

规则扫描 + LLM 分类 + 判例知识库 + 控制流去混淆 + 壳分类/脱壳 + Native 靶心定位 + Frida 探针生成。

一条链：**二进制特征识别 → 算法归类 → 经验沉淀 → 反混淆对抗**。全部逻辑跑在本地，
LLM 分类依赖本地 Ollama，可选云端降级（**出境前强制脱敏**）。

---

## 设计定位

**这是给 agent 用的工位，不是给人点的 GUI。**

人只在两端出现——开头定方向、结尾确认产出；中间由 agent 闭环完成。
所以引擎的设计标准是「**能把多少东西提前筛掉**」，不是「引擎自己能做多少事」。

能力统一注册为 **capability 契约**，GUI / CLI / MCP 都是它的客户端，**三者共用同一套能力，行为必然一致**。

---

## 能力全景（42 个 capability）

| 命名空间 | 数量 | 能力 |
|---|---|---|
| `engine.*` | 5 | 规则扫描 / Native 扫描 / 去混淆 / 验证 / 判例库统计 |
| `native.*` | 4 | APK 管线 / 壳分类 / Native 靶心定位 / Frida 探针生成 |
| `web.*` | 3 | Web 管线 / WASM 分析 / JSVM 分析 |
| `llm.*` | 3 | 问答 / 并行分发（fanout·race·hedge） / 路由预演 |
| `memory.*` | 5 | L1 精确 / L2 模糊 / L3 语义 / L4 情节 四级记忆库 |
| `agent.*` | 4 | 对话 / 案例库 / 调查 / 工具编排 |
| `job.*` | 4 | 异步作业：提交 / 列表 / 输出 / 终止 |
| `goal.*` | 3 | 目标：读 / 设 / 改 |
| `verify.*` | 2 | **验证闸门 / 变异测试** |
| `knowledge.*` | 2 | 样本入库 / 统计 |
| `fs.*` | 2 | 打补丁（apply-or-fail） / 检索（只回计数与文件名） |
| `ledger.*` | 1 | 调用账本：成本 / 延迟 / token / 实际执行模型 |
| `chat.*` | 2 | 历史 / 会话 |
| `code.*` | 1 | 代码执行 |
| `sh.*` | 1 | 命令执行（输出保头保尾） |

---

## 工程约束（写在契约里，不是文档里）

这些不是口号，是**验收过的行为保证**：

- **事件契约**：`started` 至多一次且必在首位，`result` / `error` 恰好一次且必在末位
- **前置拒绝不发 `started`** —— 尚未开始执行就发 `started`，等于撒谎
- **`verify.gate`：必须先证明检查能失败** —— 否则不予通过
- **`verify.mutate`：变异测试** —— 故意改坏，证明检测真的会响
- **不伪造数据**：查不到的字段如实显示「不支持」，不填占位数字
- **`unknown` 与 `clean` 严格分开** —— 分数低不等于干净
- **出境前脱敏在 `llm.py` 内强制**，不交给调用方 —— 未来的调用方**无法忘记**

---

## 项目结构

```
xcore/
├── src/                  # C++ 核心引擎（规则扫描 / LLM 通信 / 判例库 / verifier）
├── xchat/                # Python 交互层
│   ├── kernel/           # 能力契约 + 注册表 + 调度器
│   ├── providers/        # 云端接入：模型元数据 / 余额 / 调用账本
│   ├── memory/           # L3 向量 + L4 情节
│   ├── server/           # 本地 API：REST + SSE + WebSocket
│   └── tools/            # MCP server
├── modules/
│   ├── native/           # 壳分类 / 靶心扫描 / 常量扫描 / 探针生成
│   ├── web/              # WASM / JSVM / Web 管线
│   └── deobfuscator/     # 控制流去混淆流水线
├── rules/                # 通用指纹规则 + 壳指纹
├── scripts/              # 校验与辅助脚本（含提交前密钥门禁）
├── tests/
├── tools/                # 判例库工具
├── build.bat
└── README.md
```

---

## 环境依赖

| 组件 | 版本 | 用途 |
|---|---|---|
| Windows | 10/11 x64 | 运行平台 |
| Visual Studio 2022 | 17.x (MSVC v143) | C++ 编译 |
| CMake | 3.20+ / Ninja | 构建 |
| Python | 3.10+ | xchat 交互层 |
| Node.js | 18+ | modules/ 分析脚本 |
| Ollama | 0.x | 本地 LLM |

C++ 依赖（sqlite3 / nlohmann-json）已内置源码树，无需额外安装。

```powershell
pip install -r xchat\requirements.txt
$env:PYTHONPATH = "C:\path\to\xcore"
ollama pull qwen2.5:3b
npm install
```

---

## 构建与使用

```
build.bat
```

```
xcore scan     <file> <rules.json> [--fingerprints-dir <dir>] [--json]
xcore native   --apk <path> [--mode passive] [--json]
xcore native   --so <path> [--fingerprints-dir <dir>] [--json]
xcore native   --generate-probe <scan.json> [--out <script.js>]
xcore deobfuscate <input.js> --output <dir> [--freeze]
xcore verify   <orig.js> <unflattened.js>
xcore db       stats
xcore help
```

日常使用直接运行 `xchat` 进入自然语言交互。

---

## Roadmap

- [ ] **大文件全量扫描**：解除 Native scanner 的 64KB 截断，支持 200MB+ 二进制
- [ ] **LLM 降噪**：learn 前置滤网 + 置信度降权，消除对 VM 字节码的幻影识别
- [ ] **PE 格式检测**：完整解析 MZ 魔数 + IMAGE_FILE_HEADER
- [ ] **IL2CPP metadata 解析**：利用 `global-metadata.dat` 恢复符号

---

## 说明

本仓库为**展示快照**，与开发主线相比：
- 不含判例库数据、分析产出、会话记录、工作台前端
- 指纹规则只保留**通用算法与商业壳**部分（目标专属指纹不在此列）
- 部分内部文档未包含

## License

MIT