"""
X-Chat module: config constants and path definitions.

All paths are relative to the xcore project root (parent of this xchat/ directory).
"""

from pathlib import Path

# Project root = xchat/../ = xcore/
BASE_DIR = Path(__file__).resolve().parent.parent

XCORE_BIN = BASE_DIR / "xcore.exe"
RULES_PATH = BASE_DIR / "rules" / "rules.json"
FINGERPRINTS_DIR = BASE_DIR / "rules" / "fingerprints"
CLOUD_CONFIG = BASE_DIR / "cloud.json"
SESSION_FILE = BASE_DIR / ".xchat_session.json"
KNOWLEDGE_DIR = BASE_DIR / "knowledge"
REPORTS_DIR = BASE_DIR / "reports"

LOCAL_MODELS = ["qwen2.5:3b", "qwen2.5:7b", "qwen2.5:14b"]
OLLAMA_URL = "http://localhost:11434"
TIMEOUT_3B = 30
TIMEOUT_7B = 120
TIMEOUT_14B = 300
TIMEOUT_CLOUD = 30
MAX_CLOUD_TOKENS = 800
MAX_HISTORY = 50

# VRAM budget (GB) per model — conservative estimates
MODEL_VRAM = {
    "qwen2.5:3b": 2.2,
    "qwen2.5:7b": 5.0,
    "qwen2.5:14b": 9.5,
}
VRAM_RESERVE = 1.5  # GB reserved for dwm / CefRenderer / system
VRAM_FALLBACK_TOTAL = 16.0  # assume 16GB if detection fails

LOW_CONFIDENCE = [
    "不确定", "可能", "无法判断", "无法确定",
    "I don't know", "cannot determine", "unclear", "uncertain",
    "maybe", "possibly", "difficult to say",
    "抱歉", "我无法", "i cannot", "i'm not sure",
]
