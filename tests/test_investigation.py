"""Goal rounds and the claim ledger.

Everything here is local — no model calls — because the mechanisms under test
are deterministic. That is the point: the parts of a long investigation that
decide whether a result can be trusted should not themselves need a model.

The two mechanisms worth understanding before reading:

* **Harness CAS.** A claim records the digest of the workbench scripts it was
  measured with. Edit a script and every claim measured with the old script is
  marked stale. This is the structural answer to the `read_rva` episode: the
  formula was right and the *ruler* was wrong, and nobody had to remember that
  changing the ruler invalidated the measurement.
* **Evidence-gated completion.** `goal.update(phase="complete")` refuses unless
  the ledger holds a verified, non-stale claim. Combined with `verify.gate`
  being the ledger's only writer, a goal cannot be declared done on narration.

Run:  python tests/test_investigation.py
"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _isolate  # noqa: E402,F401  — must precede every xchat import below

from xchat.config import WORKBENCH_DIR
from xchat.kernel import agentstate as A
from xchat.kernel import workspace as W
from xchat.kernel import bootstrap
from xchat.kernel.contract import InvokeContext
from xchat.kernel.providers.agent import (COMPLETION_MARKERS, GOAL_ROUND_PROMPT,
                                          detect_overclaim,
                                          render_goal_round_prompt)

checks: list[tuple[str, bool, str]] = []
SESSION = "p2p3_test"


def check(name: str, ok: bool, detail: str = "") -> None:
    checks.append((name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))


async def call(registry, cap: str, **params):
    events = []
    async for e in registry.invoke(cap, params, InvokeContext(session_id=SESSION)):
        events.append(e)
    value = next((e.data.get("value") for e in events if e.type == "result"), None)
    error = next((e.data for e in events if e.type == "error"), None)
    return value, error, events


def script(name: str, body: str) -> str:
    WORKBENCH_DIR.mkdir(parents=True, exist_ok=True)
    (WORKBENCH_DIR / name).write_text(body, encoding="utf-8")
    return f"python {name}"


# ── overclaim detection (pure function, no I/O) ─────────────────────────────

def test_overclaim() -> None:
    done = [{"capability": "sh.run", "ok": True}]
    v = detect_overclaim("已经全部完成，知识库已归档。", done)
    check("识别出无证据的完成声明", v["overclaim"] is True,
          f"markers={v['markers']}")

    verified = [{"capability": "verify.gate", "ok": True, "ledger_id": "abc123"}]
    v = detect_overclaim("已经全部完成，账本见 abc123。", verified)
    check("有闸门执行时不算过度声称", v["overclaim"] is False,
          f"gate_runs={v['gate_runs']} ledger={v['ledger_entries']}")

    # The honest disclosure the prompt asks for must not be punished.
    v = detect_overclaim("我还没有验证这一步，所以不能宣称完成。", done)
    check("如实说明未验证不被误判", v["overclaim"] is False,
          f"hedges={v['hedges']}")

    v = detect_overclaim("这个文件有 63 处匹配。", done)
    check("普通回答不触发", v["overclaim"] is False)

    v = detect_overclaim("", [])
    check("空回答不触发", v["overclaim"] is False)

    check("完成标记表非空", len(COMPLETION_MARKERS) > 5)


def test_prompt() -> None:
    text = render_goal_round_prompt(
        {"objective": "还原 VM 解码", "criteria": "986/986", "max_rounds": 6}, 3)
    check("续轮提示含目标", "还原 VM 解码" in text)
    check("续轮提示含判据", "986/986" in text)
    check("续轮提示含轮次", "3/6" in text)
    # The two load-bearing instructions.
    check("要求去查世界状态而非信叙述",
          "inspect them instead of assuming earlier narration" in text)
    check("要求宣布完成前取证",
          "gather evidence" in text)
    check("模板占位符齐全",
          all(k in GOAL_ROUND_PROMPT for k in
              ("{objective}", "{criteria}", "{round}", "{max_rounds}")))


# ── ledger ──────────────────────────────────────────────────────────────────

def test_ledger(registry) -> None:
    ok = script("_p2_ok.py", "raise SystemExit(0)\n")
    bad = script("_p2_bad.py", "raise SystemExit(1)\n")
    summary = script("_p2_sum.py",
                     "import json\n"
                     "print(json.dumps({'cases_total': 986, 'cases_passed': 984,\n"
                     "                  'failures': ['0x18a1', '0x18b2']}))\n"
                     "raise SystemExit(0)\n")

    before = A.ledger_stats()["total"]
    value, error, _ = asyncio.run(call(
        registry, "verify.gate", claim="P2 测试主张", check=summary,
        negative_control=bad, record=True))
    check("闸门可写账本", error is None and value["recorded"],
          (error or {}).get("code", ""))
    after = A.ledger_stats()
    check("账本条数增加", after["total"] == before + 1, f"{before}->{after['total']}")

    entry = [c for c in A.claims() if c["id"] == value["recorded"]][0]
    check("记下分母", entry["cases_total"] == 986, str(entry["cases_total"]))
    check("记下通过数", entry["cases_passed"] == 984)
    check("记下失败清单（不只是分数）",
          entry["failures"] == ["0x18a1", "0x18b2"], str(entry["failures"]))
    check("记下负对照命令", bool(entry["negative_control"]))
    check("记下 harness 指纹", len(entry["harness_digest"]) == 16,
          entry["harness_digest"])

    # Module-level refusal: nothing can record a verified claim without proof
    # the check can fail, no matter which caller routes around the capability.
    try:
        A.record_claim("没有负对照", status="verified")
        check("模块层拒绝无负对照的已验证主张", False, "竟然接受了")
    except ValueError:
        check("模块层拒绝无负对照的已验证主张", True)
    try:
        A.record_claim("分母矛盾", status="verified", negative_control="x",
                       cases_total=10, cases_passed=11)
        check("拒绝 passing > total", False, "竟然接受了")
    except ValueError:
        check("拒绝 passing > total", True)

    # A refuted claim records the failure instead of hiding it.
    value, _, _ = asyncio.run(call(
        registry, "verify.gate", claim="P2 会失败的主张", check=bad,
        negative_control=bad, record=True))
    entry = [c for c in A.claims() if c["id"] == value["recorded"]][0]
    check("未通过的主张记为 refuted", entry["status"] == "refuted",
          entry["status"])


def test_harness_cas(registry) -> None:
    """The ruler changing must invalidate what it measured — and only that.

    Two claims, two conversations, two harnesses. The failure this test exists
    to prevent is not "stale never fires" but "stale fires for the wrong
    investigation": when every conversation shared one workbench, writing an
    unrelated script in B marked A's verified claim stale. That is a wrong
    answer, not a conservative one, and it teaches people to ignore the flag.
    """
    a = A.create_conversation(session_id=SESSION, title="A")
    b = A.create_conversation(session_id=SESSION, title="B")

    for cid, tag in ((a, "a"), (b, "b")):
        W.scripts_dir(cid).mkdir(parents=True, exist_ok=True)
        (W.scripts_dir(cid) / "check.py").write_text("raise SystemExit(0)\n",
                                                     encoding="utf-8")
        (W.scripts_dir(cid) / "broken.py").write_text("raise SystemExit(1)\n",
                                                      encoding="utf-8")

    ok_a = f"python {W.scripts_dir(a).name}/check.py"
    bad_a = f"python {W.scripts_dir(a).name}/broken.py"

    def ctx_for(cid):
        return InvokeContext(session_id=tag_for(cid),
                             options={"workspace": str(W.workspace(cid))})

    def tag_for(cid):
        return "cas"

    async def gate(cid, claim):
        from xchat.kernel.providers.workbench import verify_gate
        events = []
        async for ev in verify_gate(
                {"claim": claim, "check": "python check.py",
                 "negative_control": "python broken.py", "record": True},
                ctx_for(cid)):
            events.append(ev)
        return next((e.data.get("value") for e in events if e.type == "result"),
                    None)

    v = asyncio.run(gate(a, "A 的结论"))
    check("A 记录了一条已验证主张", bool(v and v["verified"]),
          str(v and v.get("verified")))
    cid_claim = (v or {}).get("recorded")
    entry = [c for c in A.claims() if c["id"] == cid_claim][0]
    check("主张带着 scope", entry["scope"] == a, repr(entry["scope"]))
    check("主张带着当时指纹", len(entry["harness_digest"]) == 16,
          entry["harness_digest"])
    check("刚记录时未失效",
          [c["stale"] for c in A.claims() if c["id"] == cid_claim] == [0])

    # The bug: another investigation's work must not touch this one.
    (W.scripts_dir(b) / "unrelated.py").write_text("x = 1\n", encoding="utf-8")
    A.revalidate()
    still = [c["stale"] for c in A.claims() if c["id"] == cid_claim]
    check("别的会话写脚本不影响本会话结论", still == [0], str(still))

    # And this investigation's own instrument change must invalidate it.
    (W.scripts_dir(a) / "check.py").write_text("raise SystemExit(0)  # v2\n",
                                               encoding="utf-8")
    # `newly_stale` means "went stale on *this* call", so it is read from the
    # revalidation that did the marking. A second call correctly reports
    # nothing — that is idempotence, not a miss.
    marked = A.revalidate()
    check("revalidate 报出刚刚失效的 id", cid_claim in marked["newly_stale"],
          str(marked["newly_stale"]))
    gone = [c["stale"] for c in A.claims() if c["id"] == cid_claim]
    check("自己改量具则结论失效", gone == [1], str(gone))
    check("再次 revalidate 不重复报告", A.revalidate()["newly_stale"] == [],
          "幂等")

    stats = A.ledger_stats()
    check("stats 报出失效数", stats["stale"] >= 1, str(stats["stale"]))
    check("指纹按会话区分", W.harness_digest(a) != W.harness_digest(b),
          f"{W.harness_digest(a)} vs {W.harness_digest(b)}")


# ── goal ────────────────────────────────────────────────────────────────────

def test_goal(registry) -> None:
    value, error, _ = asyncio.run(call(
        registry, "goal.set", objective="把 P2 目标对象跑通",
        criteria="账本里有一条已验证主张", max_rounds=3))
    check("能建目标", error is None and value["id"], (error or {}).get("code", ""))
    gid = value["id"]

    got, _, _ = asyncio.run(call(registry, "goal.get"))
    check("能读回目标", (got or {}).get("goal", {}).get("id") == gid,
          str((got or {}).get("goal", {}).get("id")))
    check("目标带完成判据", "账本里有一条已验证主张" in (got or {}).get("text", ""),
          (got or {}).get("text", "")[:80])

    # Completion is refused while the ledger holds nothing for this goal.
    _, error, _ = asyncio.run(call(registry, "goal.update", goal_id=gid,
                                   phase="complete"))
    check("无证据不许标记完成",
          (error or {}).get("code") == "no_evidence", (error or {}).get("code"))

    # Record a claim against this goal, then completion is allowed...
    bad = script("_p2_bad3.py", "raise SystemExit(1)\n")
    good = script("_p2_good3.py", "raise SystemExit(0)\n")
    asyncio.run(call(registry, "verify.gate", claim="目标内主张", check=good,
                     negative_control=bad, record=True, goal_id=gid))
    value, error, _ = asyncio.run(call(registry, "goal.update", goal_id=gid,
                                       phase="complete"))
    check("有已验证主张后可标记完成", error is None,
          (error or {}).get("code", ""))
    check("完成后自动解除武装",
          (value or {}).get("activation") == "disarmed",
          str((value or {}).get("activation")))
    check("phase 变为 complete", (value or {}).get("phase") == "complete")

    # ...but a stale claim revokes that permission.
    gid2 = asyncio.run(call(registry, "goal.set", objective="第二个目标",
                            criteria="x", replace=True))[0]["id"]
    conv2 = A.create_conversation(session_id=SESSION, title="goal2")
    W.scripts_dir(conv2).mkdir(parents=True, exist_ok=True)
    (W.scripts_dir(conv2) / "good3.py").write_text("raise SystemExit(0)\n",
                                                   encoding="utf-8")
    (W.scripts_dir(conv2) / "bad3.py").write_text("raise SystemExit(1)\n",
                                                  encoding="utf-8")
    events = []
    from xchat.kernel.providers.workbench import verify_gate
    ctx2 = InvokeContext(session_id=SESSION,
                         options={"workspace": str(W.workspace(conv2))})

    async def record2():
        async for _ in verify_gate(
                {"claim": "会失效的主张", "check": "python good3.py",
                 "negative_control": "python bad3.py", "record": True,
                 "goal_id": gid2}, ctx2):
            pass
    asyncio.run(record2())
    (W.scripts_dir(conv2) / "good3.py").write_text(
        "raise SystemExit(0)  # v2\n", encoding="utf-8")
    A.revalidate()
    _, error, _ = asyncio.run(call(registry, "goal.update", goal_id=gid2,
                                   phase="complete"))
    check("有失效主张时不许标记完成",
          (error or {}).get("code") == "stale_evidence", (error or {}).get("code"))

    stats, _, _ = asyncio.run(call(registry, "ledger.stats", goal_id=gid2))
    check("ledger.stats 标出失效", (stats or {}).get("stale", 0) >= 1,
          str((stats or {}).get("stale")))
    check("ledger.stats 报告无分母的已验证主张",
          "verified_without_denominator" in (stats or {}))
    check("ledger.stats 文本含 harness 指纹",
          "harness digest" in (stats or {}).get("text", ""))


def test_conversations(registry) -> None:
    """Conversation context must survive closing the client.

    It used to live in a JS array in the chat panel, so reopening the client
    started from nothing and the same task had to be explained again — the same
    understanding paid for twice.
    """
    cid = A.create_conversation(session_id=SESSION)
    A.append_turn(cid, "user", "我想逆向一个 APK，里面有个 libsgmain.so")
    A.append_turn(cid, "assistant", "先看壳。",
                  steps=[{"capability": "sh.run", "ok": True}])
    A.append_turn(cid, "user", "那 360 加固怎么脱？")

    turns = A.conversation_history(cid)
    check("会话可读回", len(turns) == 3, str(len(turns)))
    check("顺序正确", turns[0]["role"] == "user" and turns[2]["role"] == "user")
    check("内容完整", "libsgmain" in turns[0]["content"])

    conv = A.get_conversation(cid)
    check("首条用户消息自动成为标题",
          "libsgmain" in (conv or {}).get("title", ""),
          str((conv or {}).get("title")))
    check("轮数被记录", (conv or {}).get("turns") == 3, str((conv or {}).get("turns")))
    check("最近会话就是它", (A.latest_conversation() or {}).get("id") == cid)

    # Tool steps are kept for the UI and for auditing...
    full = A.conversation_turns(cid)
    check("工具调用有留存", full[1]["steps"][0]["capability"] == "sh.run")
    # ...but must NOT be replayed into the model's context, or persistence
    # becomes a larger bill than starting fresh.
    check("回放里不含工具输出", "steps" not in turns[1])

    # Write-ahead appends the user turn before the model call, so a retry after
    # a failure would otherwise duplicate it.
    r = A.append_turn(cid, "user", "那 360 加固怎么脱？")
    check("紧邻重复的 user 轮被折叠", r.get("deduped") is True)
    check("折叠后轮数不变", A.get_conversation(cid)["turns"] == 3)
    A.append_turn(cid, "assistant", "脱壳流程是…")
    r = A.append_turn(cid, "user", "那 360 加固怎么脱？")
    check("隔了一轮再问同一句不算重复", not r.get("deduped"))

    # Replay is bounded. Persisting everything and replaying everything is how
    # a saved conversation becomes more expensive than a fresh one.
    big = A.create_conversation(session_id=SESSION)
    for _ in range(30):
        A.append_turn(big, "user", "x" * 3000)
        A.append_turn(big, "assistant", "y" * 3000)
    replayed = A.conversation_history(big)
    chars = sum(len(t["content"]) for t in replayed)
    check("回放轮数有上限", len(replayed) == W.REPLAY_TURNS, str(len(replayed)))
    check("回放字符有上限",
          chars <= W.REPLAY_TURNS * W.REPLAY_CHARS_PER_TURN,
          f"{chars} 字符，上限 {W.REPLAY_TURNS * W.REPLAY_CHARS_PER_TURN}")
    check("存的多、回放的少",
          A.get_conversation(big)["turns"] == 60 and len(replayed) == 12,
          f"存 {A.get_conversation(big)['turns']} / 回放 {len(replayed)}")

    sess, error, _ = asyncio.run(call(registry, "chat.sessions"))
    check("chat.sessions 能列出会话", error is None and sess["conversations"],
          f"{len((sess or {}).get('conversations', []))} 条")
    hist, error, _ = asyncio.run(call(registry, "chat.history",
                                      conversation_id=cid))
    # Assert consistency with the store rather than a magic number that has to
    # be recounted every time this test grows a turn.
    stored_turns = A.get_conversation(cid)["turns"]
    check("chat.history 能读回会话",
          error is None and len(hist["turns"]) == stored_turns,
          f"{len((hist or {}).get('turns', []))} vs 存 {stored_turns}")
    check("chat.history 文本含轮次摘要",
          "user:" in (hist or {}).get("text", ""))
    A.archive_conversation(big)
    check("会话可归档",
          A.get_conversation(big)["archived"] == 1)


def cleanup() -> None:
    import sqlite3
    for p in WORKBENCH_DIR.glob("_p2_*"):
        p.unlink(missing_ok=True)
    conn = sqlite3.connect(A.AGENT_DB)
    try:
        # Collect the conversation ids first: their content lives in folders now
        # (transcript.jsonl and the harness), so removing the rows alone would
        # leave the folders behind for the next run to read.
        ids = [r[0] for r in conn.execute(
            "SELECT id FROM conversations WHERE session_id=?", (SESSION,))]
        conn.execute("DELETE FROM claims WHERE goal_id IN "
                     "(SELECT id FROM goals WHERE session_id=?)", (SESSION,))
        conn.execute("DELETE FROM goals WHERE session_id=?", (SESSION,))
        conn.execute("DELETE FROM conversations WHERE session_id=?", (SESSION,))
        conn.commit()
    finally:
        conn.close()
    for cid in ids:
        W.delete(cid)


def main() -> None:
    registry = bootstrap(reset=True)
    ids = {s["id"] for s in registry.specs()}
    for cap in ("goal.set", "goal.get", "goal.update", "ledger.stats",
                "agent.investigate", "chat.sessions", "chat.history"):
        check(f"能力已注册: {cap}", cap in ids)
    check("能力数至少包含调查层", len(ids) >= 33, str(len(ids)))

    print("\n── 过度声称检测（确定性，无模型）──")
    test_overclaim()
    print("\n── 续轮提示 ──")
    test_prompt()
    print("\n── 主张账本 ──")
    test_ledger(registry)
    print("\n── harness 指纹 CAS（改了量具，旧结论自动失效）──")
    test_harness_cas(registry)
    print("\n── 目标对象与完成闸门 ──")
    test_goal(registry)
    print("\n── 会话留存（关掉客户端不丢上下文）──")
    test_conversations(registry)

    cleanup()
    failed = [n for n, ok, _ in checks if not ok]
    print()
    print(f"{len(checks) - len(failed)}/{len(checks)} PASS"
          + (f", FAILED: {failed}" if failed else ""))
    sys.exit(1 if failed else 0)


main()
