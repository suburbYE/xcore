"""
X-Chat module: config constants and path definitions.

All paths are relative to the xcore project root (parent of this xchat/ directory).
"""

from pathlib import Path
import os

# Project root = xchat/../ = xcore/
BASE_DIR = Path(__file__).resolve().parent.parent

# ── mutable vs. read-only roots ─────────────────────────────────────────────
#
# Everything xcore *writes* at runtime lives under STATE_ROOT: `state/` (agent
# db, memory db, usage ledger, server token), `sessions/` (per-conversation
# transcripts and scripts), `workbench/` (the agent's scratch).
#
# Everything it only *reads* stays on BASE_DIR: `rules/`, `knowledge/`,
# `modules/`, `tools/cases.db`, `xcore.exe`.
#
# Why the split exists at all: the test suite creates conversations, records
# claims and writes workbench scripts. Without a redirect those land in the
# user's real state — a test run stamps entries into the conversation list,
# where they are indistinguishable from the user's own work, and it happens
# on *every* run, so the list only ever grows.
#
# Override with XCORE_STATE_ROOT=<dir>. It must be set before any xchat import,
# because the paths below are module-level constants.
STATE_ROOT = Path(os.environ.get("XCORE_STATE_ROOT") or BASE_DIR).resolve()

XCORE_BIN = BASE_DIR / "xcore.exe"
RULES_PATH = BASE_DIR / "rules" / "rules.json"
FINGERPRINTS_DIR = BASE_DIR / "rules" / "fingerprints"
CLOUD_CONFIG = BASE_DIR / "cloud.json"
SESSION_FILE = BASE_DIR / ".xchat_session.json"
KNOWLEDGE_DIR = BASE_DIR / "knowledge"
REPORTS_DIR = BASE_DIR / "reports"

# Agent 工位：agent 唯一可写的地方。
# 目标只读、量具（脚本/日志/中间产物）可写——这条边界是结构性的，不是靠自觉：
# policy.default_policy() 只把这里列为 writable_root，别处一律拒绝写入。
# 之所以要这么分开：mhypbase 那次改的是 read_rva()（量具），不是靶子字节。
WORKBENCH_DIR = STATE_ROOT / "workbench"

# 持久状态（用量账本、模型目录覆盖等）——不是缓存，值得备份
STATE_DIR = STATE_ROOT / "state"
USAGE_DB = STATE_DIR / "usage.db"
MODELS_OVERRIDE = STATE_DIR / "models.json"

# 会话根目录（每场对话的 transcript / scripts / logs）也在这里取，见
# kernel/workspace.py：它是 state 的同级产物，没有理由各写各的根。
SESSIONS_DIR = STATE_ROOT / "sessions"

# ── 本地对话层 ──────────────────────────────────────────────
# 单一模型承担三件事：对话 / 判定是否该上云 / 复述云端结果。
# 在 Arc A770 16GB 上实测（脚本见 temp/_bench_models.py、temp/_bench_synth.py）：
#   qwen2.5:3b         94.4 t/s  冷启 2.6s   难题委派 5/5   复述 7/7   ← 当前选用
#   qwen2.5:7b         51.1 t/s  冷启 4.1s   难题委派 —     复述 6/7（丢事实）
#   qwen2.5:14b        26.6 t/s  冷启14.2s   难题委派 4/5   复述 7/7
#   qwen2.5-coder:14b  26.3 t/s  冷启14.0s   难题委派 4/5   复述 7/7
# 7B 出局：复述丢事实，且它一旦返回就短路云端升级。
# 14B 出局：7B 移除后 NEED_7B/NEED_CLOUD 都汇入云端，其"唯一会发 NEED_CLOUD"
# 的优势失效；而委派率反而不如 3B，速度只有 1/3.6。
#
# 后续换卡（含双卡）后改这一行即可切到 27B-32B：
#   DIALOG_MODEL = "qwen3:27b"   并同步 LOCAL_MODELS / MODEL_VRAM
DIALOG_MODEL = "qwen2.5:3b"
DIALOG_TIMEOUT = 120

# 只有 DIALOG_MODEL 常驻本地；7B/14B 不再参与，重活全部走脱敏后的云端。
LOCAL_MODELS = [DIALOG_MODEL]
OLLAMA_URL = "http://localhost:11434"
TIMEOUT_3B = 30          # 保留：老配置/外部脚本仍可能引用
TIMEOUT_7B = 120
TIMEOUT_14B = 300
TIMEOUT_CLOUD = 30
MAX_CLOUD_TOKENS = 800
MAX_HISTORY = 50

# Output budget for the agent's orchestrator call.
#
# Separate from MAX_CLOUD_TOKENS, and much larger, because the two calls are
# different jobs: MAX_CLOUD_TOKENS caps a one-shot answer, while the
# orchestrator has to emit *tool-call arguments* — which for `code.run` or
# `fs.patch` means a whole script or patch inside a JSON string.
#
# At the old hardcoded 1500 the model spent the entire budget on reasoning
# (observed: finish_reason=length, reasoning_tokens=1500), the argument was
# truncated mid-generation, and the tool call arrived missing its required
# parameter. The symptom looked like the model forgetting an argument; the
# cause was the ceiling. Codex and Claude Code run 8k-32k here.
AGENT_MAX_TOKENS = 8000

# VRAM budget (GB) per model — conservative estimates
MODEL_VRAM = {
    "qwen2.5:3b": 2.2,
    "qwen2.5:7b": 5.0,
    "qwen2.5:14b": 9.5,
    "qwen2.5-coder:14b": 9.5,
}
VRAM_RESERVE = 1.5  # GB reserved for dwm / CefRenderer / system
VRAM_FALLBACK_TOTAL = 16.0  # assume 16GB if detection fails

LOW_CONFIDENCE = [
    "不确定", "可能", "无法判断", "无法确定",
    "I don't know", "cannot determine", "unclear", "uncertain",
    "maybe", "possibly", "difficult to say",
    "抱歉", "我无法", "i cannot", "i'm not sure",
]
