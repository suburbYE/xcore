"""
Triage: turn a capability's raw result into what the agent still has to decide.

This is the mechanism behind "the engine filters out a big round of work".
Without it a capability hands the agent everything it computed and the agent
re-derives the interesting part; with it the agent receives three lists:

    decided    the engine settled this, with its evidence
    undecided  the engine could not settle this, and *why not*
    suggested  what would settle it (a method, never a conclusion)

`undecided` carrying the reason is the load-bearing part. "18 of 986 failed" is
a fact; "18 failed and all of them have P outside the .upx0 segment" is a
hypothesis handed over ready to test. The 9649-to-16 collapse on the mhypbase
work is the same idea: the engine reduces the space, the model works the
remainder.

Implemented as a **view over existing results**, not as a change to every
provider. The scanners already compute everything needed; what was missing was
presenting it as "settled / not settled" rather than as one flat blob. Doing it
here means a capability gains triage without being rewritten, and the mapping
stays honest — it can only report what the result actually contains.
"""

from __future__ import annotations

from typing import Any

# Capabilities whose results are pure statistics: nothing is left undecided.
_FULLY_DECIDED = {
    "engine.db_stats", "memory.stats", "knowledge.stats", "ledger.stats",
    "job.list", "chat.sessions", "goal.get", "chat.history",
}


def triage(capability: str, result: Any) -> dict | None:
    """Return {decided, undecided, suggested} or None when nothing applies.

    Returning None (rather than an empty triage) matters: an empty triage would
    read as "the engine decided nothing", which is a different claim from "this
    capability has no triage view".
    """
    if not isinstance(result, dict):
        return None
    if capability in _FULLY_DECIDED:
        return {"decided": [_summarise(result)], "undecided": [], "suggested": []}
    if capability in ("engine.native_scan", "native.target_scan"):
        return _scan_triage(result)
    if capability == "engine.scan":
        return _rule_scan_triage(result)
    if capability == "native.shell_classify":
        return _shell_triage(result)
    if capability in ("web.wasm", "web.jsvm"):
        return _web_triage(result)
    return None


def _summarise(result: dict) -> str:
    bits = [f"{k}={v}" for k, v in list(result.items())[:6]
            if isinstance(v, (int, float, str)) and k != "text"]
    return "; ".join(bits) or "(result)"


def _scan_triage(result: dict) -> dict:
    """Native scanner: the verdict vocabulary already is a triage."""
    verdict = str(result.get("verdict") or "").lower()
    score = result.get("final_score")
    algorithm = result.get("algorithm") or "unknown"
    library = result.get("library") or ""
    decided: list[str] = []
    undecided: list[str] = []
    suggested: list[str] = []

    if score is not None:
        decided.append(f"融合评分 {score}")

    if verdict in ("annotate", "flag"):
        decided.append(f"算法归因：{algorithm}" + (f"（库：{library}）" if library else ""))
    elif verdict == "note":
        decided.append(f"存在可识别特征，算法倾向：{algorithm}")
        undecided.append("证据强度不足以归因到具体实现")
        suggested.append("补充样本或扩大扫描范围，看特征是否随规模稳定出现")
    elif verdict == "unknown":
        # The whole point of separating `unknown` from `clean`.
        undecided.append(
            "有信号但**低于归因阈值**：不等于干净，只是现有证据不足以命名")
        suggested.append("用 engine.native_scan 的层明细定位是哪一层给的信号，"
                         "对该层做定向验证")
        suggested.append("若涉及控制流，考虑 engine.deobfuscate 或动态探针")
    elif verdict == "clean":
        decided.append("各层零命中——这是『查过没有』，不是『没查』")
        undecided.append("零命中无法排除该类别本身不在 L1-L5 覆盖范围内")
        suggested.append("确认目标类别（内核驱动/反作弊/主机平台二进制）是否在"
                         "扫描器的覆盖范围内；不在则需要换方法而不是换参数")
    elif verdict == "error":
        undecided.append("有子层失败，本次结论不可信")
        suggested.append("查看 failed_layers，修复后再判定")

    layers = result.get("layers")
    if isinstance(layers, dict):
        hit_layers = [k for k, v in layers.items()
                      if isinstance(v, dict) and (v.get("hits") or [])]
        if hit_layers:
            decided.append(f"命中层：{', '.join(hit_layers)}")
    return {"decided": decided, "undecided": undecided, "suggested": suggested}


def _rule_scan_triage(result: dict) -> dict:
    decided: list[str] = []
    undecided: list[str] = []
    suggested: list[str] = []
    hits = result.get("rule_hits") or result.get("hits")
    if isinstance(hits, list):
        if hits:
            decided.append(f"规则命中 {len(hits)} 条")
        else:
            decided.append("规则零命中")
    similar = result.get("similar") or result.get("cases")
    if isinstance(similar, list) and similar:
        top = similar[0]
        sim = top.get("similarity") if isinstance(top, dict) else None
        if isinstance(sim, float):
            if 0.40 <= sim <= 0.55:
                # The BORDERLINE band is exactly the "engine cannot decide" case.
                undecided.append(
                    f"与判例 #{(top or {}).get('id')} 相似度 {sim}，落在 BORDERLINE 区间")
                suggested.append("用动态探针证伪，或补充该实现的指纹")
            elif sim > 0.55:
                decided.append(f"与判例 #{(top or {}).get('id')} 相似度 {sim}，可参照")
    return {"decided": decided, "undecided": undecided, "suggested": suggested}


def _shell_triage(result: dict) -> dict:
    shell = result.get("shell") or result.get("shell_class")
    if shell:
        return {"decided": [f"壳类型：{shell}"],
                "undecided": [], "suggested": ["按该壳的脱壳流程处理"]}
    return {"decided": [],
            "undecided": ["未匹配任何已知商业壳签名"],
            "suggested": ["可能是自研壳或未收录的变体；对 .so 做靶心扫描"]}


def _web_triage(result: dict) -> dict:
    decided: list[str] = []
    undecided: list[str] = []
    suggested: list[str] = []
    if result.get("framework"):
        decided.append(f"框架：{result['framework']}")
    obf = result.get("obfuscation")
    if isinstance(obf, dict) and any(obf.values()):
        undecided.append(f"检测到混淆特征：{obf}")
        suggested.append("静态还原后需行为等价性验证（engine.verify）")
    if not decided and not undecided:
        undecided.append("解析成功但未提取到可判定特征")
        suggested.append("检查导出签名与数据段字符串是否为空")
    return {"decided": decided, "undecided": undecided, "suggested": suggested}


def render(t: dict) -> str:
    """Compact model-facing form. Omitted sections stay omitted."""
    parts = []
    if t.get("decided"):
        parts.append("decided: " + "; ".join(t["decided"]))
    if t.get("undecided"):
        parts.append("undecided (需要你判断): " + "; ".join(t["undecided"]))
    if t.get("suggested"):
        parts.append("suggested (只是建议，不是结论): " + "; ".join(t["suggested"]))
    return "<triage>\n" + "\n".join(parts) + "\n</triage>"
