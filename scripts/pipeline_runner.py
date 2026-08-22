"""
pipeline_runner.py — xcore 全链路管道调度器

串联 001 → 004 模块，单指令拉起:

    python scripts/pipeline_runner.py \
        --input libtarget.so \
        --rva 0x1A3C \
        --pseudo pseudocode.c \
        --out output/

流程:
    1. 加载 SO，提取目标 RVA 代码段
    2. 提取核心 BB (bb_extractor)
    3. Unicorn 微执行 (micro_executor) → trace_result.json
    4. IR 切片 (ir_slicer_psc) → sliced_prompt.c

作者: xcore
许可: MIT
"""

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

# ---------- 路径引导 ----------
SCRIPT_DIR = Path(__file__).resolve().parent
MODULE_DIR = SCRIPT_DIR.parent / "modules" / "native"

sys.path.insert(0, str(MODULE_DIR))
if str(SCRIPT_DIR.parent) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR.parent))

# ---------- 核心模块导入 ----------
try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

    from modules.native.bb_extractor    import extract_core_bb
    from modules.native.micro_executor  import MicroExecutor, DMPEngine
    from modules.native.ir_slicer_psc   import slice_pseudocode, inject_anchor_header, infer_seed_vars
except ImportError as e:
    print(f"[FATAL] Module import failed: {e}")
    print(f"  sys.path[:3]: {sys.path[:3]}")
    sys.exit(1)


# ---------- 数据结构 ----------

@dataclass
class StageResult:
    stage: str
    ok: bool
    data: dict = field(default_factory=dict)
    error: str = ""


# ---------- 管道调度器 ----------

class XCorePipeline:
    """xcore 001→004 全链路管道"""

    def __init__(
        self,
        so_path: str,
        target_rva: int,
        pseudo_path: str | None = None,
        raw_pseudocode: str | None = None,
        seed_vars: list[str] | None = None,
        output_dir: str = "output",
        debug: bool = False,
    ):
        self.so_path        = so_path
        self.target_rva     = target_rva
        self.pseudo_path    = pseudo_path
        self.raw_pseudocode = raw_pseudocode
        self.seed_vars      = seed_vars or []
        self.output_dir     = Path(output_dir)
        self.debug          = debug

        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.results: list[StageResult] = []

    # ---------- Stage 1: 加载 SO + 提取 BB ----------

    def stage_load_and_extract(self) -> StageResult:
        """加载 SO 文件，提取目标 RVA 的核心 BB（ELF-aware, 使用 lief 按段映射）。"""
        try:
            import lief

            elf = lief.parse(self.so_path)
            if elf is None:
                return StageResult("load", False, error=f"lief failed to parse: {self.so_path}")

            # VA → 文件偏移映射
            text_offset = None
            text_va = None
            text_size = 0
            for seg in elf.segments:
                if seg.type != lief.ELF.Segment.TYPE.LOAD:
                    continue
                va_start = seg.virtual_address
                va_end = va_start + seg.virtual_size
                if va_start <= self.target_rva < va_end:
                    text_va = va_start
                    text_offset = seg.file_offset
                    text_size = seg.virtual_size
                    break

            if text_offset is None:
                return StageResult("load", False,
                                   error=f"RVA {hex(self.target_rva)} not covered by any LOAD segment")

            # 读取目标段内容
            with open(self.so_path, "rb") as f:
                f.seek(text_offset)
                seg_data = f.read(text_size)

            if not seg_data:
                return StageResult("load", False, error="Segment data is empty")

            # 从目标 RVA 附近截取代码 (保守取 64KB)
            rel_offset = self.target_rva - text_va
            start = max(0, rel_offset - 0x1000)
            end = min(len(seg_data), rel_offset + 0xF000)
            code = seg_data[start:end]
            base_rva = text_va + start

            # Capstone 反汇编
            md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
            md.detail = True

            bbs = extract_core_bb(code, base_rva, md)
            if not bbs:
                return StageResult("load", False,
                                   error=f"extract_core_bb returned empty for RVA {hex(self.target_rva)}")

            # 找到包含目标 RVA 的 BB
            target_bb = None
            for bb in bbs:
                if bb.start_rva <= self.target_rva <= bb.end_rva:
                    target_bb = bb
                    break

            if not target_bb:
                return StageResult("load", False,
                                   error=f"No BB contains target RVA {hex(self.target_rva)}")

            self._log(f"Stage 1/4: ELF loaded (seg @ {hex(text_va)}, {len(seg_data)} bytes), "
                      f"{len(bbs)} BBs extracted, target BB @ {hex(target_bb.start_rva)} "
                      f"({len(target_bb.insns)} insns)")

            return StageResult("load", True, {
                "target_bb": target_bb,
                "all_bbs": bbs,
            })

        except FileNotFoundError:
            return StageResult("load", False, error=f"SO not found: {self.so_path}")
        except Exception as e:
            return StageResult("load", False, error=str(e))

    # ---------- Stage 2: Unicorn 微执行 ----------

    def stage_micro_execute(self, target_bb) -> StageResult:
        """Unicorn 微执行，产出 TraceResult"""
        try:
            executor = MicroExecutor(algorithm_hint="AES")

            trace = executor.execute(
                bb=target_bb,
                function_name=f"sub_{self.target_rva:X}",
            )

            # DMP 双跑 (自定义明文 B)
            trace_b = executor.execute(
                bb=target_bb,
                plaintext=bytes(range(0x10, 0x20)),
                key=bytes(range(0x20, 0x30)),
                function_name=f"sub_{self.target_rva:X}_B",
            )

            dmp_result = DMPEngine.compare(trace, trace_b)

            # 组装契约
            contract = {
                "function":           f"sub_{self.target_rva:X}",
                "algorithm":          "AES-128",
                "confidence":         dmp_result.confidence,
                "anchors":            {},
                "loop_info":          {},
                "dmp_status":         dmp_result.status,
                "path_hash":          trace.path_hash,
                "executed_inst_count": trace.executed_inst_count,
            }

            json_path = self.output_dir / "trace_result.json"
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(contract, f, indent=2, default=str)

            self._log(f"Stage 2/4: Micro executed "
                      f"({trace.executed_inst_count}/{trace_b.executed_inst_count} insts, "
                      f"DMP={dmp_result.status})")

            return StageResult("micro_exec", True, {
                "contract": contract,
                "json_path": str(json_path),
            })

        except Exception as e:
            import traceback
            return StageResult("micro_exec", False, error=f"{e}\n{traceback.format_exc()}")

    # ---------- Stage 3: IR 切片 ----------

    def stage_ir_slice(self, contract: dict) -> StageResult:
        """004 IR Slicer 切片"""
        try:
            # 获取伪代码文本
            raw_pseudo = self.raw_pseudocode
            if not raw_pseudo and self.pseudo_path:
                with open(self.pseudo_path, "r", encoding="utf-8") as f:
                    raw_pseudo = f.read()

            if not raw_pseudo:
                return StageResult("ir_slice", False,
                                   error="No pseudocode available (use --pseudo or --code)")

            # 种子变量
            seeds = list(self.seed_vars)
            if not seeds:
                seeds = infer_seed_vars(raw_pseudo)

            # 切片
            sliced_lines = slice_pseudocode(
                lines=raw_pseudo.split("\n"),
                seed_vars=seeds,
                trace_json=contract,
            )

            # Anchor 头
            header = inject_anchor_header(contract)
            sliced_prompt = header + "\n" + "\n".join(sliced_lines)

            # 写出
            out_path = self.output_dir / "sliced_prompt.c"
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(sliced_prompt)

            orig_lines = len(raw_pseudo.split("\n"))
            self._log(f"Stage 3/4: IR sliced ({orig_lines} → {len(sliced_lines)} lines, "
                      f"seeds={seeds[:5]}...)")

            return StageResult("ir_slice", True, {
                "sliced_path": str(out_path),
                "original_lines": orig_lines,
                "sliced_lines": len(sliced_lines),
                "seed_vars": seeds,
            })

        except Exception as e:
            import traceback
            return StageResult("ir_slice", False, error=f"{e}\n{traceback.format_exc()}")

    # ---------- 全流程 ----------

    def run(self) -> list[StageResult]:
        """执行完整管道"""
        self._log(f"=== xcore Pipeline START ===")
        self._log(f"  SO: {self.so_path}")
        self._log(f"  RVA: {hex(self.target_rva)}")
        self._log(f"  Output: {self.output_dir}")

        # Stage 1
        r1 = self.stage_load_and_extract()
        self.results.append(r1)
        if not r1.ok:
            self._log("Pipeline ABORTED at Stage 1")
            self._print_summary()
            return self.results

        # Stage 2
        r2 = self.stage_micro_execute(r1.data["target_bb"])
        self.results.append(r2)
        if not r2.ok:
            self._log("Pipeline ABORTED at Stage 2")
            self._print_summary()
            return self.results

        # Stage 3
        r3 = self.stage_ir_slice(r2.data["contract"])
        self.results.append(r3)

        # Stage 4: 预留 LLM
        r4 = StageResult("llm", True, {"status": "skipped (reserved)"})
        self.results.append(r4)

        self._log("=== xcore Pipeline DONE ===")
        self._print_summary()
        return self.results

    # ---------- 辅助 ----------

    def _log(self, msg: str):
        if self.debug:
            print("[pipeline] " + msg)

    def _print_summary(self):
        ok = sum(1 for r in self.results if r.ok)
        fail = len(self.results) - ok
        print(f"\n{'='*50}")
        print(f"  Pipeline Summary: {ok}/{len(self.results)} stages OK")
        if fail:
            print(f"  FAILURES ({fail}):")
            for r in self.results:
                if not r.ok:
                    print(f"    [{r.stage}] {r.error[:120]}")
        print(f"{'='*50}\n")


# ---------- CLI 入口 ----------

def main():
    parser = argparse.ArgumentParser(description="xcore 001→004 Pipeline Runner")
    parser.add_argument("--input", required=True, help="Path to libtarget.so")
    parser.add_argument("--rva", required=True, help="Target function RVA (hex, e.g. 0x1A3C)")
    parser.add_argument("--pseudo", default=None, help="Path to pseudocode.c from IDA exporter")
    parser.add_argument("--seeds", default=None, help="Comma-separated seed vars (e.g. a1,a2,v5)")
    parser.add_argument("--out", default="output", help="Output directory")
    parser.add_argument("--debug", action="store_true", help="Verbose logging")

    args = parser.parse_args()
    rva = int(args.rva, 16) if args.rva.startswith("0x") else int(args.rva)
    seeds = args.seeds.split(",") if args.seeds else []

    pipeline = XCorePipeline(
        so_path        = args.input,
        target_rva     = rva,
        pseudo_path    = args.pseudo,
        seed_vars      = seeds,
        output_dir     = args.out,
        debug          = True,
    )
    results = pipeline.run()
    sys.exit(0 if all(r.ok for r in results) else 1)


if __name__ == "__main__":
    main()
