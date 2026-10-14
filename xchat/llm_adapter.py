"""
llm_adapter.py — 本地 Ollama 适配器 + C 编译校验闭环

职责:
  1. 读取 sliced_prompt.c → 喂给 qwen2.5-coder:14b
  2. System Prompt 强约束：剥离 IDA 伪类型，输出标准 C
  3. 正则抽取 Markdown 代码块
  4. GCC/Clang -fsyntax-only 语法校验

用法:
  from xchat.llm_adapter import LLMAdapter
  adapter = LLMAdapter()
  result = adapter.process_sliced_prompt("output/sliced_prompt.c")
  if result["success"]:
      print(result["cleaned_c_code"])

作者: xcore
许可: MIT
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import time
import urllib.request
import urllib.error
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .config import DIALOG_MODEL


# ────────────────────────────────────────────────────────────
# 常量
# ────────────────────────────────────────────────────────────

DEFAULT_OLLAMA_URL = "http://localhost:11434"
# 跟随全局单一本地模型，避免子系统各自拉起额外的 7B/14B 占用显存
DEFAULT_MODEL = DIALOG_MODEL
MAX_RETRIES = 3
RETRY_DELAY = 1.5  # seconds

# 密码学逆向专用 System Prompt
SYSTEM_PROMPT = (
    "You are a cryptographic reverse engineering engine.\n"
    "Your sole task: analyze the provided IDA Hex-Rays pseudocode (augmented with\n"
    "dynamic execution context — loop bounds, S-Box anchors, DMP-differentiated\n"
    "memory regions) and rewrite it as a clean, standalone, zero-dependency\n"
    "ANSI C function.\n\n"
    "Strict rules:\n"
    "1. Replace ALL IDA-specific pseudo-types:\n"
    "   __int64  → uint64_t\n"
    "   __int32  → int32_t\n"
    "   unsigned __int8 → uint8_t\n"
    "   _DWORD → uint32_t\n"
    "   _BYTE  → uint8_t\n"
    "   _OWORD → uint8_t[16]\n"
    "   _QWORD → uint64_t\n"
    "2. Preserve cryptographic logic EXACTLY — every XOR, shift, table lookup,\n"
    "   S-Box access, round loop, round key expansion.\n"
    "3. Use standard <stdint.h> types only. Include it explicitly.\n"
    "4. CRITICAL — Annotated Renaming rule:\n"
    "   Rename all IDA variables to semantic names (state, round_key, sbox, etc.).\n"
    "   BUT you MUST annotate every renamed variable with its original IDA name\n"
    "   as a trailing comment on the declaration line. Example:\n"
    "     uint32_t state[4];   // v5\n"
    "     uint32_t round_key;  // v12\n"
    "     uint8_t  sbox[256];  // v8\n"
    "   This 1:1 annotation is NON-NEGOTIABLE — it prevents semantic hallucination\n"
    "   and enables oracle-based correctness verification against the original trace.\n"
    "   For variables without a clear semantic role, keep the IDA name:  // v27\n"
    "5. Output ONLY the complete, compilable C function inside a single ```c block.\n"
    "6. No explanations, no markdown outside the code block, no conversation.\n"
    "7. If the pseudocode contains opaque builtins (_aese, _aesmc, etc.), replace\n"
    "   them with inline standard C code or clearly commented stubs.\n"
)

# 编译器探测优先级
# ── MSVC 路径缓存 ──
_MSVC_CL_PATH: Optional[str] = None

COMPILER_CANDIDATES = ["gcc", "clang", "cc", "tcc"]


# ────────────────────────────────────────────────────────────
# 数据结构
# ────────────────────────────────────────────────────────────

@dataclass
class AdapterResult:
    success: bool
    model: str
    compiler: str
    raw_output: str           # LLM 原始返回
    cleaned_c_code: str       # 清洗后的 C 代码
    compiler_err: Optional[str] = None
    elapsed: float = 0.0


# ────────────────────────────────────────────────────────────
# LLM 适配器
# ────────────────────────────────────────────────────────────

class LLMAdapter:
    """
    挂接本地 Ollama，负责 sliced_prompt.c → 标准 C 还原 + 语法校验。

    用法:
        adapter = LLMAdapter()
        result = adapter.process("output/sliced_prompt.c")
    """

    def __init__(
        self,
        ollama_url: str = DEFAULT_OLLAMA_URL,
        model: str = DEFAULT_MODEL,
        compiler: Optional[str] = None,
        system_prompt: Optional[str] = None,
    ):
        self.ollama_url = ollama_url.rstrip("/")
        self.model = model
        self.system_prompt = system_prompt or SYSTEM_PROMPT
        self.compiler = compiler or _detect_compiler()

    # ── 核心入口 ──

    def process(self, sliced_prompt_path: str) -> AdapterResult:
        """
        端到端: 读取 sliced_prompt.c → LLM 还原 → 清洗 → 编译校验。

        返回 AdapterResult。
        """
        t0 = time.time()
        path = Path(sliced_prompt_path)
        if not path.exists():
            raise FileNotFoundError(f"Sliced prompt not found: {sliced_prompt_path}")

        with open(path, "r", encoding="utf-8") as f:
            sliced_prompt = f.read()

        print(f"[LLMAdapter] Sending {len(sliced_prompt)} chars to {self.model} ...")

        # 1. LLM 推理
        raw = self._query(sliced_prompt)

        # 2. 抽取 C 代码
        cleaned = self._extract_c_code(raw)

        # 3. 编译校验
        passed, err = self._validate_syntax(cleaned)

        elapsed = time.time() - t0
        print(f"[LLMAdapter] Done in {elapsed:.1f}s — "
              f"{'PASS' if passed else 'FAIL'}: {len(cleaned)} chars of C")

        return AdapterResult(
            success=passed,
            model=self.model,
            compiler=self.compiler,
            raw_output=raw,
            cleaned_c_code=cleaned,
            compiler_err=err,
            elapsed=elapsed,
        )

    def process_raw(self, sliced_prompt: str, label: str = "inline") -> AdapterResult:
        """直接接收字符串 prompt（不读文件），其余流程相同。"""
        t0 = time.time()
        print(f"[LLMAdapter] Sending {len(sliced_prompt)} chars [{label}] → {self.model} ...")
        raw = self._query(sliced_prompt)
        cleaned = self._extract_c_code(raw)
        passed, err = self._validate_syntax(cleaned)
        elapsed = time.time() - t0
        print(f"[LLMAdapter] Done [{label}] — {'PASS' if passed else 'FAIL'}")
        return AdapterResult(
            success=passed,
            model=self.model,
            compiler=self.compiler,
            raw_output=raw,
            cleaned_c_code=cleaned,
            compiler_err=err,
            elapsed=elapsed,
        )

    # ── LLM 通信 ──

    def _query(self, prompt: str) -> str:
        """向 Ollama 发起同步 POST，带重试。"""
        endpoint = f"{self.ollama_url}/api/generate"
        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": self.system_prompt,
            "stream": False,
            "options": {
                "temperature": 0.1,
                "top_p": 0.95,
                "num_predict": 4096,
            },
        }
        body = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}

        last_err = None
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                req = urllib.request.Request(endpoint, data=body, headers=headers, method="POST")
                with urllib.request.urlopen(req, timeout=180) as resp:
                    return json.loads(resp.read().decode("utf-8")).get("response", "")
            except (urllib.error.URLError, ConnectionError, TimeoutError) as e:
                last_err = e
                if attempt < MAX_RETRIES:
                    print(f"[LLMAdapter] Retry {attempt}/{MAX_RETRIES} after {RETRY_DELAY}s: {e}")
                    time.sleep(RETRY_DELAY)

        raise RuntimeError(
            f"Ollama unreachable [{endpoint}] after {MAX_RETRIES} retries.\n"
            f"  Is Ollama running? Try: ollama pull {self.model}\n"
            f"  Last error: {last_err}"
        )

    def probe_model(self) -> bool:
        """检查 Ollama 是否在线且目标模型可用。"""
        try:
            req = urllib.request.Request(
                f"{self.ollama_url}/api/tags",
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                models = json.loads(resp.read().decode("utf-8")).get("models", [])
                available = [m["name"] for m in models]
                if self.model in available:
                    print(f"[LLMAdapter] Model '{self.model}' ready.")
                    return True

                # 模糊匹配（处理 :latest 后缀差异）
                for name in available:
                    if name.startswith(self.model.split(":")[0]):
                        print(f"[LLMAdapter] Model '{self.model}' → matched '{name}'")
                        self.model = name
                        return True

                print(f"[LLMAdapter] Model '{self.model}' NOT found. Available: {available[:10]}")
                return False
        except Exception as e:
            print(f"[LLMAdapter] Ollama probe failed: {e}")
            return False

    # ── 代码清洗 ──

    @staticmethod
    def _extract_c_code(llm_output: str) -> str:
        """从 LLM 返回中提取 ```c ... ``` 代码块。"""
        pattern = re.compile(r"```c\s*\n?(.*?)```", re.DOTALL | re.IGNORECASE)
        match = pattern.search(llm_output)
        if match:
            return match.group(1).strip()

        # 退化：查找任意 ``` 块
        pattern_any = re.compile(r"```\s*\n?(.*?)```", re.DOTALL)
        match = pattern_any.search(llm_output)
        if match:
            return match.group(1).strip()

        # 最终退化：返回原始文本（剔除明显的非代码行）
        lines = llm_output.strip().split("\n")
        code_lines = [
            l for l in lines
            if not l.startswith("#") and not l.startswith("```") and l.strip()
        ]
        return "\n".join(code_lines)

    # ── 编译校验 ──

    @staticmethod
    def _validate_syntax(c_code: str) -> Tuple[bool, str]:
        """
        拉起编译器做语法检查（GCC/Clang -fsyntax-only 或 MSVC /Zs）。

        返回 (passed: bool, stderr_or_ok_msg: str)。
        """
        compiler = _detect_compiler()
        if compiler is None:
            return False, "No C compiler found (gcc/clang/cl.exe). Install one to enable validation."

        prelude = _COMPILER_PRELUDE(compiler)
        full_code = prelude + c_code

        with tempfile.NamedTemporaryFile(
            suffix=".c", mode="w", encoding="utf-8", delete=False
        ) as tf:
            tf.write(full_code)
            tmp_path = tf.name

        try:
            is_msvc = compiler.endswith("cl.exe")
            if is_msvc:
                # 手动设置 INCLUDE 路径（避免 cmd /c call vcvars 的引号转义问题）
                msvc_include = _find_msvc_include(compiler)
                env = os.environ.copy()
                if msvc_include:
                    # 同时探测 Windows SDK
                    sdk_include = _find_winsdk_include()
                    includes = [msvc_include]
                    if sdk_include:
                        includes.extend(sdk_include)
                    env["INCLUDE"] = ";".join(includes)

                result = subprocess.run(
                    [compiler, "/Zs", "/W3", "/wd4101", tmp_path],
                    capture_output=True, text=True, timeout=15, env=env,
                )
            else:
                cmd = [compiler, "-fsyntax-only", "-Wall", "-Wno-unused-variable", tmp_path]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)

            if result.returncode == 0:
                return True, "OK"
            err_text = (result.stderr or "") or (result.stdout or "")
            return False, err_text.strip()
        except FileNotFoundError:
            return False, f"Compiler not found: {compiler}"
        except subprocess.TimeoutExpired:
            return False, "Syntax check timed out (>30s)"
        except Exception as exc:
            return False, str(exc)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


# ────────────────────────────────────────────────────────────
# 辅助函数
# ────────────────────────────────────────────────────────────

def _detect_compiler() -> Optional[str]:
    """按优先级探测可用的 C 编译器（含 MSVC）。"""
    global _MSVC_CL_PATH

    # 先探测传统编译器
    for name in COMPILER_CANDIDATES:
        try:
            result = subprocess.run(
                [name, "--version"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                return name
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

    # ── 探测 MSVC cl.exe ──
    if _MSVC_CL_PATH and os.path.isfile(_MSVC_CL_PATH):
        return _MSVC_CL_PATH

    # 按优先级扫描 VS 安装目录
    candidates = [
        r"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC",
        r"C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Tools\MSVC",
        r"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC",
    ]
    for vc_root in candidates:
        if not os.path.isdir(vc_root):
            continue
        try:
            versions = sorted(os.listdir(vc_root), reverse=True)
            for ver in versions:
                cl_path = os.path.join(vc_root, ver, "bin", "Hostx64", "x64", "cl.exe")
                if os.path.isfile(cl_path):
                    _MSVC_CL_PATH = cl_path
                    return cl_path
        except OSError:
            continue

    return None


def _find_msvc_include(cl_path: str) -> Optional[str]:
    """从 cl.exe 路径反查 MSVC include 目录。"""
    # cl.exe: .../MSVC/<ver>/bin/Hostx64/x64/cl.exe
    # include: .../MSVC/<ver>/include
    cl_dir = os.path.dirname(cl_path)                        # bin/Hostx64/x64
    msvc_ver_dir = os.path.dirname(os.path.dirname(os.path.dirname(cl_dir)))  # MSVC/<ver>
    include_dir = os.path.join(msvc_ver_dir, "include")
    if os.path.isdir(include_dir):
        return include_dir
    return None


def _COMPILER_PRELUDE(compiler: Optional[str]) -> str:
    """根据编译器返回兼容的 include prelude。"""
    if compiler and compiler.endswith("cl.exe"):
        # MSVC: stddef.h/string.h 来自 Windows SDK（未安装时全部跳过）
        return "#include <stdint.h>\n\n"
    else:
        # GCC/Clang
        return "#include <stdint.h>\n#include <stddef.h>\n#include <string.h>\n\n"


def _find_winsdk_include() -> Optional[list[str]]:
    """探测 Windows SDK include 目录（ucrt + shared）。"""
    kits_root = r"C:\Program Files (x86)\Windows Kits\10\Include"
    if not os.path.isdir(kits_root):
        return None
    try:
        versions = sorted(os.listdir(kits_root), reverse=True)
        for ver in versions:
            ucrt = os.path.join(kits_root, ver, "ucrt")
            shared = os.path.join(kits_root, ver, "shared")
            if os.path.isdir(ucrt) and os.path.isdir(shared):
                return [ucrt, shared]
    except OSError:
        pass
    return None


# ────────────────────────────────────────────────────────────
# 快速测试入口
# ────────────────────────────────────────────────────────────

def smoke_test(prompt_path: Optional[str] = None):
    """独立烟雾测试：无需 pipeline，直接用内置样本调 Ollama。"""
    adapter = LLMAdapter()

    # 编译器探测
    cc = adapter.compiler or "N/A"
    print(f"[smoke] Compiler: {cc}")

    # 模型探测
    if not adapter.probe_model():
        print("[smoke] Ollama 不可达或模型缺失。跳过 LLM 调用。")
        return

    # 测试 prompt
    test_prompt = (
        "/* @algorithm AES-128 @loop W8=10 @dmp PATH_ALIGNED */\n"
        "void sub_1A3C(uint32_t *plain, uint32_t *key, uint32_t *out) {\n"
        "  uint32_t state[4];\n"
        "  uint32_t round_keys[44];\n"
        "  int round = 10;\n"
        "  // key expansion stub\n"
        "  for (int i = 0; i < 4; i++) state[i] = plain[i];\n"
        "  // round loop\n"
        "  do {\n"
        "    uint32_t t = state[0];\n"
        "    state[0] = (t << 8) | (t >> 24);\n"
        "    state[3] ^= round_keys[round * 4 + 3];\n"
        "  } while (--round);\n"
        "  for (int i = 0; i < 4; i++) out[i] = state[i];\n"
        "}"
    )

    if prompt_path:
        result = adapter.process(prompt_path)
    else:
        result = adapter.process_raw(test_prompt, label="smoke-aes-stub")

    print(f"\n{'='*60}")
    print(f"  success:  {result.success}")
    print(f"  model:    {result.model}")
    print(f"  compiler: {result.compiler}")
    print(f"  elapsed:  {result.elapsed:.1f}s")
    print(f"  C output: {len(result.cleaned_c_code)} chars")
    if result.compiler_err:
        short = result.compiler_err[:200]
        print(f"  err:      {short}{'...' if len(result.compiler_err)>200 else ''}")
    print(f"{'='*60}")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        smoke_test(sys.argv[1])
    else:
        smoke_test()
