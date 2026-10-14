"""Memory write/read budget guards.

Why this exists: everything written to the memory store is retrieved later, and
retrieval output is pasted into a model's context. An unbounded store is
therefore an unbounded token bill, and the growth is invisible at write time.
These tests pin the guards that bound it.

Run:  python tests/test_memory_budget.py
"""
import asyncio
import json
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _isolate  # noqa: E402,F401  — must precede every xchat import below

from xchat.kernel import bootstrap
from xchat.kernel.contract import InvokeContext
from xchat.kernel.providers import agent as agent_provider
from xchat.kernel.providers import memory as memory_provider
from xchat.memory import store

SESSION = "budget_guard_test"
# Taken from the module that opens it, not spelled out as BASE_DIR/state.
# The hardcoded path is what would have kept this suite writing into the real
# memory database after XCORE_STATE_ROOT moved everything else aside — a
# redirect that only half applies is harder to notice than none at all.
MEMORY_DB = store.MEMORY_DB
checks: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    checks.append((name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))


async def call(registry, cap: str, **params):
    """Invoke a capability and return (value, error, events)."""
    events = []
    async for e in registry.invoke(cap, params, InvokeContext(session_id=SESSION)):
        events.append(e)
    value = next((e.data.get("value") for e in events if e.type == "result"), None)
    error = next((e.data for e in events if e.type == "error"), None)
    return value, error, events


def cleanup() -> int:
    """Remove only rows this test created, identified by session_id."""
    conn = sqlite3.connect(MEMORY_DB)
    try:
        ids = [r[0] for r in conn.execute(
            "SELECT id FROM episodes WHERE session_id=?", (SESSION,))]
        if ids:
            marks = ",".join("?" * len(ids))
            conn.execute(f"DELETE FROM episodes WHERE id IN ({marks})", ids)
            conn.execute(f"DELETE FROM vectors WHERE source='episode'"
                         f" AND ref IN ({marks})", ids)
        conn.commit()
        return len(ids)
    finally:
        conn.close()


async def main() -> None:
    registry = bootstrap(reset=True)
    before = store.count_episodes()
    print(f"episodes before: {before}  (session={SESSION})")

    # ── write guards ────────────────────────────────────────────────────────
    _, error, _ = await call(registry, "memory.record", content="ok", index=False)
    check("短内容被拒绝", (error or {}).get("code") == "too_short",
          f"code={(error or {}).get('code')}")

    body = ("kernel_drv_x.sys 内核驱动 L1-L5 扫描 verdict=clean；"
            "libhash_x_iv 与 crc32_poly 两条指纹为误报，已由泛型模式过滤剔除。")
    first, error, _ = await call(registry, "memory.record", content=body, index=False)
    check("正常写入成功", bool(first) and not first.get("deduped"),
          f"id={first and first['id']}")
    check("会话按 ctx 归属",
          store.count_episodes(SESSION) == 1,
          f"count(session)={store.count_episodes(SESSION)}")

    second, _, _ = await call(registry, "memory.record", content=body, index=False)
    check("重复内容不重复落库",
          second["id"] == first["id"] and second.get("deduped") is True,
          f"id 相同={second['id'] == first['id']}")
    check("重复后总数未增长",
          store.count_episodes(SESSION) == 1,
          f"count(session)={store.count_episodes(SESSION)}")

    long_body = "C" * (memory_provider.MAX_EPISODE_CHARS + 500)
    truncated, _, events = await call(registry, "memory.record",
                                      content=long_body, index=False)
    warned = any(e.type == "log" and e.data.get("level") == "warning"
                 for e in events)
    check("超长内容只存开头并告警",
          truncated["truncated_from"] == len(long_body) and warned,
          f"truncated_from={truncated['truncated_from']}")

    # Per-session cap, exercised at a small value so the test stays cheap.
    original_cap = memory_provider.MAX_EPISODES_PER_SESSION
    memory_provider.MAX_EPISODES_PER_SESSION = 2
    try:
        _, error, _ = await call(registry, "memory.record",
                                 content="这条应该被会话上限挡住。", index=False)
        check("会话上限生效", (error or {}).get("code") == "memory_full",
              f"code={(error or {}).get('code')}")
    finally:
        memory_provider.MAX_EPISODES_PER_SESSION = original_cap

    # ── recall budget ───────────────────────────────────────────────────────
    hits = [{"source": "case", "ref": f"c{i}", "score": 0.9 - i * 0.01,
             "text": "x" * 600, "detail": {}} for i in range(8)]
    kept, used = [], 0
    budget = memory_provider.MAX_RECALL_CHARS
    for h in hits:
        cost = len(h["text"])
        if kept and used + cost > budget:
            break
        kept.append(h)
        used += cost
    check("recall 字符预算能截断",
          len(kept) < len(hits) and used <= budget,
          f"保留 {len(kept)}/{len(hits)} 命中, {used} <= {budget} 字符")

    # ── L1 ↔ L3 consistency ─────────────────────────────────────────────────
    # Two failure modes that both look like "everything is fine" from counts
    # alone: a knowledge file that is never embedded (invisible to recall), and
    # a vector pointing at a file that is gone (wastes a recall slot forever).
    #
    # This section deliberately reaches outside the isolated sandbox and reads
    # the *production* database. It audits a property of the data set, not of
    # the code: does every knowledge file have a vector, and does every vector
    # still point at a file? Pointing it at the scratch database would compare
    # 115 real knowledge files against an empty vector table — the orphan check
    # would then pass while having examined nothing, which is the exact failure
    # this whole suite exists to catch.
    from xchat.config import BASE_DIR as _BASE
    from xchat.memory.index import knowledge_text

    kdir = _BASE / "knowledge"
    names = {p.stem for p in kdir.glob("*.json")}
    prod_db = _BASE / "state" / "memory.db"
    # Read-only: an audit that can write is one bug away from being the incident.
    conn = sqlite3.connect(f"file:{prod_db}?mode=ro", uri=True)
    try:
        refs = {r[0][:16] for r in
                conn.execute("SELECT ref FROM vectors WHERE source='knowledge'")}
    finally:
        conn.close()

    orphans = sorted(refs - names)
    check("无孤儿知识向量", not orphans, f"{orphans[:3]}")

    unindexed = []
    for stem in sorted(names - refs):
        raw = (kdir / f"{stem}.json").read_text(encoding="utf-8")
        entry = json.loads(raw)
        if knowledge_text(entry).strip():
            unindexed.append(stem)
    check("所有可解析的知识条目都已入索引", not unindexed,
          f"未入索引且有正文: {unindexed[:3]}")

    # Hydration resolves the on-disk name. It used to slice nothing (the vector
    # ref is the full digest, the file is named by its first 16 chars), so every
    # knowledge hit silently came back without its `detail`.
    from xchat.memory import recall as recall_mod
    if names:
        sample = sorted(names)[0]
        hit = recall_mod.Hit(source="knowledge", ref=sample + "0" * 48,
                             score=1.0, text="x")
        recall_mod.hydrate([hit])
        check("hydrate 能按 nameref 找到知识文件", bool(hit.detail),
              f"ref={sample}+48位, detail={'有' if hit.detail else '空'}")

    # ── transcript budgets (agent side) ─────────────────────────────────────
    history = [{"role": "user" if i % 2 == 0 else "assistant",
                "content": f"turn {i} " + "y" * 3000} for i in range(12)]
    kept_hist, dropped = agent_provider._bounded_history(history)
    total = sum(len(m["content"]) for m in kept_hist)
    check("历史总长受预算约束",
          total <= agent_provider.MAX_HISTORY_CHARS and dropped > 0,
          f"{len(kept_hist)} 轮保留 / {dropped} 轮丢弃, {total} 字符")

    one_huge = agent_provider._bounded_history(
        [{"role": "user", "content": "z" * 99000}])[0]
    check("单条超长历史被截断但保留",
          len(one_huge) == 1 and len(one_huge[0]["content"]) <=
          agent_provider.MAX_HISTORY_MSG_CHARS + 32,
          f"{len(one_huge[0]['content'])} 字符")

    messages = [{"role": "user", "content": "q"}]
    for i in range(10):
        messages.append({"role": "assistant", "content": "",
                         "tool_calls": [{"id": f"t{i}"}]})
        messages.append({"role": "tool", "tool_call_id": f"t{i}",
                         "content": json_pad(i)})
    elided = agent_provider._trim_transcript(messages)
    live = sum(len(m["content"]) for m in messages if m["role"] == "tool"
               and not m["content"].startswith("[elided"))
    check("转录中超额工具结果被释放",
          elided > 0 and live <= agent_provider.MAX_TRANSCRIPT_CHARS,
          f"释放 {elided} 条, 剩余 {live} 字符")
    check("用户提问未被裁剪",
          messages[0]["content"] == "q")
    check("助手轮次未被裁剪",
          all(m.get("tool_calls") for m in messages if m["role"] == "assistant"))

    # ── cleanup ─────────────────────────────────────────────────────────────
    removed = cleanup()
    after = store.count_episodes()
    check("测试数据已清理且未动原有数据",
          after == before and removed == 2,
          f"删除 {removed} 条, episodes {before} -> {after}")
    check("memory.db 完整性", store.integrity_check() == "ok")

    failed = [n for n, ok, _ in checks if not ok]
    print()
    print(f"{len(checks) - len(failed)}/{len(checks)} PASS"
          + (f", FAILED: {failed}" if failed else ""))
    sys.exit(1 if failed else 0)


def json_pad(i: int) -> str:
    return "r" * 4000 + str(i)


asyncio.run(main())
