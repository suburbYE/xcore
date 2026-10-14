"""Substrate P4/P5/P6: jobs, code mode, triage.

All local. The mechanisms under test — a scheduler, a batching bridge, and a
result-shaping view — are deterministic and must not need a model to verify.

Run:  python tests/test_substrate.py
"""
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _isolate  # noqa: E402,F401  — must precede every xchat import below

from xchat.kernel import bootstrap, triage
from xchat.kernel import agentstate as A
from xchat.kernel import jobs as jobmod
from xchat.kernel.contract import InvokeContext
from xchat.kernel.providers import agent as agent_provider

checks: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    checks.append((name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))


async def call(registry, cap, **params):
    value = error = None
    async for e in registry.invoke(cap, params, InvokeContext(session_id="p456")):
        if e.type == "result":
            value = e.data.get("value")
        elif e.type == "error":
            error = e.data
    return value, error


# ── jobs (P4) ───────────────────────────────────────────────────────────────

def test_jobs(registry) -> None:
    async def go():
        v, e = await call(registry, "job.submit", capability="sh.run",
                          params={"command": 'python -c "print(1)"'},
                          label="smoke")
        if e:
            return e.get("code"), None
        jid = v["id"]
        # Incremental reads: a wait-read is itself a read, so the one after it
        # must be empty. That is what stops a long job from re-billing its whole
        # output every time the agent looks at it.
        first, _ = await call(registry, "job.output", job_id=jid, wait=True,
                              timeout_s=20)
        second, _ = await call(registry, "job.output", job_id=jid)
        lst, _ = await call(registry, "job.list")
        return jid, (first, second, lst)

    jid, rest = asyncio.run(go())
    check("能提交后台作业", bool(jid) and jid != "internal_error", str(jid))
    if not rest:
        return
    first, second, lst = rest
    check("作业跑完", first["job"]["status"] == "completed",
          first["job"]["status"])
    check("首次读取有输出", first["new_lines"] > 0, str(first["new_lines"]))
    check("增量读取不重发", second["new_lines"] == 0, str(second["new_lines"]))
    check("读取带状态行", "[status:" in first["text"])
    check("作业列表有计数", lst["counts"]["total"] >= 1, str(lst["counts"]))

    async def kill():
        v, _ = await call(registry, "job.submit", capability="sh.run",
                          params={"command": 'python -c "import time;time.sleep(30)"'})
        jid = v["id"]
        k, _ = await call(registry, "job.kill", job_id=jid, reason="test")
        return k["outcome"]

    check("能终止作业", asyncio.run(kill()) == "cancellation-requested")

    async def unknown():
        _, e = await call(registry, "job.output", job_id="nope")
        return (e or {}).get("code")

    check("未知作业报 not_found", asyncio.run(unknown()) == "not_found")

    # The two capabilities that were banned for being slow are the reason this
    # mechanism exists; they must now be reachable.
    ids = {s["id"] for s in registry.specs()}
    check("长能力已解禁", "engine.deobfuscate" in ids and "native.apk_pipeline" in ids)
    _, rev = agent_provider.build_tool_schemas(registry)
    tools = {
        rev[t["function"]["name"]]: t for t in
        agent_provider.build_tool_schemas(registry)[0]
    }
    for cap in ("engine.deobfuscate", "native.apk_pipeline"):
        props = tools.get(cap, {}).get("function", {}).get("parameters", {}).get("properties", {})
        check(f"{cap} 暴露 background 参数", "background" in props,
              f"{len(props)} props")


# ── budget (P4) ─────────────────────────────────────────────────────────────

def test_budget() -> None:
    check("全局调用上限已抬高", agent_provider.MAX_CALLS_TOTAL >= 30,
          str(agent_provider.MAX_CALLS_TOTAL))
    check("轮次上限已抬高", agent_provider.MAX_ROUNDS_DEFAULT >= 10,
          str(agent_provider.MAX_ROUNDS_DEFAULT))
    check("有可见预算阈值", len(agent_provider.BUDGET_WARN_AT) >= 1,
          str(agent_provider.BUDGET_WARN_AT))


# ── code mode (P5) ──────────────────────────────────────────────────────────

def test_code(registry) -> None:
    async def run(source, **kw):
        return await call(registry, "code.run", source=source, **kw)

    # Many capability calls inside one turn — the whole point. `capabilities()`
    # deliberately does not count as a call; only `call()` reaches the kernel.
    v, e = asyncio.run(run(
        "caps = xcore.capabilities()\n"
        "seen = []\n"
        "for cap in caps[:5]:\n"
        "    seen.append(xcore.call(cap, **{}) if False else cap)\n"
        "xcore.call('memory.stats')\n"
        "xcore.call('memory.stats')\n"
        "result = {'cases_total': len(caps), 'cases_passed': len(caps),\n"
        "          'failures': [], 'seen': seen}\n"))
    check("一次往返多次调用", e is None and v["calls"] == 2,
          f"calls={v and v['calls']}")
    check("返回 result 绑定", (v or {}).get("result", {}).get("cases_total") >= 1,
          json.dumps((v or {}).get("result", {}).get("cases_total")))
    check("识别为可作证据", (v or {}).get("looks_like_evidence") is True)

    v, e = asyncio.run(run("result = {'ok': True}"))
    check("脚本异常被如实返回",
          asyncio.run(run('raise ValueError("boom")'))[0]["error"]["code"]
          == "script_error")

    v, _ = asyncio.run(run(
        "import time\nwhile True:\n    xcore.call('memory.stats')\n", timeout_s=2))
    check("死循环在调用边界被切断", v["error"]["code"] == "timeout",
          f"calls={v['calls']}")
    check("被切断时保留已发生的调用数", v["calls"] > 0, str(v["calls"]))

    v, _ = asyncio.run(run("print('hello')\nresult = 1"))
    check("脚本自身的 print 被回传", "hello" in v["text"])

    _, e = asyncio.run(run("   "))
    check("空脚本被拒", (e or {}).get("code") == "invalid_params")

    # A script that sets no result and prints no JSON is reported, not guessed at.
    v, _ = asyncio.run(run("x = 1"))
    check("无 result 时明确说明", "set no `result`" in v["text"])


# ── triage (P6) ─────────────────────────────────────────────────────────────

def test_triage() -> None:
    t = triage.triage("native.target_scan",
                      {"verdict": "unknown", "final_score": 0.05,
                       "algorithm": "unknown",
                       "layers": {"L5_cfp": {"hits": ["ror_chain_x3"]}}})
    check("unknown 进 undecided", any("归因阈值" in u for u in t["undecided"]),
          str(t["undecided"])[:60])
    check("unknown 给出建议", bool(t["suggested"]))
    check("命中层进 decided", any("L5_cfp" in d for d in t["decided"]))

    t = triage.triage("native.target_scan",
                      {"verdict": "clean", "final_score": 0.0, "layers": {}})
    check("clean 与 unknown 措辞不同",
          any("查过没有" in d for d in t["decided"]))
    check("clean 也保留 undecided（覆盖范围未知）", bool(t["undecided"]))

    t = triage.triage("native.target_scan",
                      {"verdict": "annotate", "final_score": 0.75,
                       "algorithm": "aes", "library": "openssl 1.0.2j"})
    check("annotate 进 decided 且带库", any("openssl" in d for d in t["decided"]),
          str(t["decided"]))
    check("annotate 无 undecided", not t["undecided"])

    t = triage.triage("engine.scan", {"similar": [{"id": 42, "similarity": 0.478}]})
    check("BORDERLINE 相似度进 undecided",
          any("BORDERLINE" in u for u in t["undecided"]), str(t["undecided"]))

    t = triage.triage("engine.db_stats", {"cases": 22})
    check("统计类能力全 decided", t["decided"] and not t["undecided"])

    check("无 triage 视图的能力返回 None",
          triage.triage("sh.run", {"exit_code": 0}) is None)
    check("非 dict 结果返回 None", triage.triage("engine.scan", [1, 2]) is None)

    rendered = triage.render(triage.triage(
        "native.target_scan", {"verdict": "unknown", "final_score": 0.05,
                               "layers": {}}))
    check("渲染三段齐备",
          "decided:" in rendered and "undecided" in rendered
          and "suggested" in rendered)
    check("建议明确标注为非结论", "不是结论" in rendered)


# ── inbox: mid-task messages ────────────────────────────────────────────────

def test_inbox() -> None:
    """Two modes, and they must not be confused for each other.

    `interject` is consumed by the running turn at its next round boundary;
    `queue` must survive that, because it belongs to the *next* turn. Taking one
    for the other either loses a queued thought or delivers it too early.
    """
    from xchat.kernel import inbox as inbox_mod
    box = inbox_mod.Inbox()          # a fresh one, not the process-wide INBOX

    box.push("c1", "插一句", inbox_mod.INTERJECT)
    box.push("c1", "排一句", inbox_mod.QUEUE)
    check("两种模式都记下了", len(box.pending("c1")) == 2, str(len(box.pending("c1"))))

    taken = box.take_interjections("c1")
    check("插队被取走", len(taken) == 1 and taken[0].text == "插一句",
          str([n.text for n in taken]))
    check("排队不受影响", [n["text"] for n in box.pending("c1")] == ["排一句"],
          str(box.pending("c1")))

    taken2 = box.take_interjections("c1")
    check("插队取完不再重复取", taken2 == [], str(taken2))

    q = box.take_queued("c1")
    check("排队可单独取走", len(q) == 1 and q[0].text == "排一句")
    check("取走后收件箱空", box.pending("c1") == [])

    # A flood of interjections is capped per turn rather than thrashing.
    for i in range(10):
        box.push("c2", f"n{i}", inbox_mod.INTERJECT)
    cap = box.take_interjections("c2")
    check("单轮插话有上限", len(cap) == inbox_mod.MAX_INTERJECT_PER_TURN,
          f"{len(cap)} vs {inbox_mod.MAX_INTERJECT_PER_TURN}")
    check("超出的留在收件箱等下一轮",
          len(box.pending("c2")) == 10 - inbox_mod.MAX_INTERJECT_PER_TURN,
          str(len(box.pending("c2"))))

    check("按会话隔离", box.pending("c1") == [] and box.pending("nope") == [])

    box.push("c3", "x")
    check("可清空", box.clear("c3") == 1 and box.pending("c3") == [])

    # Unknown modes must not silently become interjections, which would let a
    # typo steer a running turn.
    n = box.push("c4", "t", "bogus")
    check("未知模式回落为排队", n.mode == inbox_mod.QUEUE, n.mode)

    # The agent loop reports interjections it could not deliver, so a late
    # thought is returned to the caller instead of sitting in the inbox.
    from xchat.kernel.providers import agent as ag
    src = __import__("inspect").getsource(ag.chat)
    check("chat 在结果里回报未送达的插话", "undelivered" in src)
    check("chat 在轮边界消费插话", "take_interjections" in src)


# ── harness mutation (P6b) ──────────────────────────────────────────────────

def test_mutation(registry) -> None:
    """A check that cannot fail proves nothing; this makes that testable.

    The scenario is the mhypbase episode itself: the formula was right and the
    *ruler* was wrong, and only the failures revealed it. Here the harness is
    deliberately broken and the check is expected to notice.
    """
    from xchat.kernel import workspace as W
    conv = A.create_conversation(session_id="p456", title="mutation")

    def ctx():
        return InvokeContext(session_id="mutation",
                             options={"workspace": str(W.workspace(conv))})

    scripts = W.scripts_dir(conv)
    scripts.mkdir(parents=True, exist_ok=True)
    # A harness whose correctness is observable: the "ruler" has a right and a
    # wrong reading, and the check compares against the right one.
    # `measure.py` must be importable: the first version ended with a
    # module-level `sys.exit(0)`, so `import measure` terminated the check
    # before it ran and the check passed unconditionally. The mutation run
    # correctly reported that as a survivor — a check that cannot fail — which
    # is the mechanism working and the fixture being wrong.
    (scripts / "measure.py").write_text(
        "SEGMENTS = ['text', 'rdata']   # the fixed version walks the table\n"
        "def read(rva):\n"
        "    return rva if 'rdata' in SEGMENTS else 0\n", encoding="utf-8")
    (scripts / "check.py").write_text(
        "import sys\n"
        "import measure\n"
        "ok = measure.read(1) == 1\n"
        "print('PASS' if ok else 'FAIL')\n"
        "sys.exit(0 if ok else 1)\n", encoding="utf-8")

    async def call_mutate(**params):
        from xchat.kernel.contract import CapabilityError
        from xchat.kernel.providers.workbench import verify_mutate
        events = []
        try:
            async for ev in verify_mutate(params, ctx()):
                events.append(ev)
        except CapabilityError as exc:
            # Calling the handler directly skips the registry wrapper, which is
            # what normally turns a CapabilityError into an `error` event.
            return None, {"code": exc.code, "message": str(exc)}
        return (next((e.data.get("value") for e in events
                      if e.type == "result"), None),
                next((e.data for e in events if e.type == "error"), None))

    # A mutation the check notices: restore the hardcoded single-segment ruler.
    good = [{"name": "旧版 read_rva（只看 .upx0）",
             "edits": [{"path": "measure.py",
                        "old": "SEGMENTS = ['text', 'rdata']",
                        "new": "SEGMENTS = ['text']"}]}]
    v, e = asyncio.run(call_mutate(check="python check.py", mutations=good))
    check("变异被检查发现", e is None and v["detected"] == 1,
          f"applied={v and v['applied']} detected={v and v['detected']}")
    check("检测到时不报 survivor", v["survivors"] == [], str(v["survivors"]))
    check("结果里报告 harness 作用域", v["scope"] == conv, str(v["scope"]))

    # Restoring is not optional: a mutation run that leaves the harness broken
    # is worse than not running one.
    restored = (scripts / "measure.py").read_text(encoding="utf-8")
    check("变异跑完把量具还原", "rdata" in restored,
          restored.splitlines()[1] if restored else "?")

    # A mutation the check does NOT notice is a survivor — and a survivor is the
    # finding, not a failure of this mechanism.
    blind = [{"name": "改一个不影响结论的常量",
              "edits": [{"path": "measure.py",
                         "old": "SEGMENTS = ['text', 'rdata']",
                         "new": "SEGMENTS = ['text', 'rdata']  # noop"}]}]
    v, _ = asyncio.run(call_mutate(check="python check.py", mutations=blind))
    check("未发现的变异被报为 survivor", v["survivors"] == ["改一个不影响结论的常量"],
          str(v["survivors"]))
    check("有 survivor 时 ok=false", "ok=false" in v["text"], v["text"][-60:])

    # A mutation whose anchor text is absent must be reported, not silently
    # skipped — otherwise a stale mutation list looks like a clean run.
    stale = [{"name": "锚点已不存在",
              "edits": [{"path": "measure.py", "old": "不存在的文本",
                         "new": "x"}]}]
    v, _ = asyncio.run(call_mutate(check="python check.py", mutations=stale))
    check("锚点找不到被如实报告",
          v["applied"] == 0 and v["results"][0]["applied"] is False,
          str(v["results"][0].get("error", ""))[:60])

    # The check itself is policy-gated like any other command.
    _, e = asyncio.run(call_mutate(check="rm -rf /", mutations=good))
    check("变异检查的命令也过策略", (e or {}).get("code") == "policy_denied",
          (e or {}).get("code"))

    _, e = asyncio.run(call_mutate(check="python check.py"))
    check("不给变异直接拒绝", (e or {}).get("code") in
          ("invalid_params", "missing"), (e or {}).get("code"))


# ── MCP surface ─────────────────────────────────────────────────────────────

def test_mcp_surface() -> None:
    """MCP must derive from the registry, not hand-write a second list.

    The two surfaces disagreeing is the exact failure the capability contract
    exists to prevent, and it had already happened: five hand-written MCP tools
    against a registry that had grown well past them.
    """
    from xchat.tools.mcp_server import MCP_DENY, _registry_tools
    pairs, _ = _registry_tools()
    names = [schema["name"] for _, schema in pairs]
    caps = [cap for cap, _ in pairs]

    check("MCP 工具数远超手写的 5 个", len(pairs) > 20, str(len(pairs)))
    check("新能力出现在 MCP 上", "code_run" in names and "verify_gate" in names,
          str([n for n in names if n in ("code_run", "verify_gate")]))
    check("agent.* 不暴露", not any(c.startswith("agent.") for c in caps))
    check("MCP_DENY 里的都不暴露",
          not (set(caps) & MCP_DENY), str(sorted(set(caps) & MCP_DENY)))
    check("工具名是把能力 id 的 . 换成 _",
          "engine_db_stats" in names and "engine.db_stats" in caps)
    check("每个工具都带 JSON Schema",
          all(s["parameters"].get("type") == "object" for _, s in pairs))
    check("描述非空", all(s["description"].strip() for _, s in pairs))
    check("工具名唯一", len(names) == len(set(names)), str(len(names)))


# ── process containment ─────────────────────────────────────────────────────

def test_containment() -> None:
    """Spawned processes must not outlive xcore.

    Measured before it was fixed: a child started through `sh.run` survived the
    death of the process that started it, so killing the client mid-scan left
    the scan running. The fix is a Windows Job Object, and this asserts it is
    actually in force rather than merely attempted.
    """
    from xchat.kernel import containment
    st = containment.contain_children()
    check("容器状态可查询",
          st["status"] in ("applied", "unsupported-platform", "failed"),
          f"{st['status']}: {st['detail'][:60]}")

    if sys.platform != "win32":
        check("非 Windows 明确报告不支持",
              st["status"] == "unsupported-platform", st["status"])
        return
    if st["status"] != "applied":
        # A machine that refuses nested jobs must still boot — but the test has
        # to say containment was not verified rather than pass silently.
        check("Job Object 已生效", False,
              f"未生效: {st['detail'][:90]} — 子进程可能变孤儿")
        return

    check("Job Object 已生效", st["handle"] is True, st["detail"])
    check("设了并发进程上限", "cap" in st["detail"], st["detail"])

    # The behaviour, not just the handle: spawn a grandchild whose survival is
    # observable, let its parent exit, and check it went too.
    import shutil
    import subprocess
    import tempfile
    import time
    from pathlib import Path as _P

    root = str(Path(__file__).resolve().parent.parent)
    tmp = _P(tempfile.mkdtemp())
    marker = tmp / "m.txt"
    child = tmp / "c.py"
    spawner = tmp / "s.py"
    child.write_text("import time\n"
                     "time.sleep(6)\n"
                     f"open(r'{marker}','w').write('alive')\n", encoding="utf-8")
    spawner.write_text(
        "import subprocess, sys\n"
        f"sys.path.insert(0, r'{root}')\n"
        "from xchat.kernel import containment\n"
        "containment.contain_children()\n"
        f"p = subprocess.Popen([sys.executable, r'{child}'])\n"
        "print(p.pid, flush=True)\n", encoding="utf-8")
    proc = subprocess.run([sys.executable, str(spawner)], capture_output=True,
                          text=True, cwd=root)
    if not (proc.stdout or "").strip().isdigit():
        # Guard against a fixture that silently no-ops and reports success.
        check("孤儿测试真的起了孙进程", False,
              f"没起来，测试没证明任何事: {(proc.stderr or '')[:80]}")
        shutil.rmtree(tmp, ignore_errors=True)
        return
    time.sleep(8)
    orphaned = marker.exists()
    check("父进程退出后孙进程不残留", not orphaned,
          "孙进程仍在跑" if orphaned else "已随父进程结束")
    shutil.rmtree(tmp, ignore_errors=True)


def main() -> None:
    registry = bootstrap(reset=True)
    ids = {s["id"] for s in registry.specs()}
    for cap in ("job.submit", "job.output", "job.list", "job.kill", "code.run"):
        check(f"能力已注册: {cap}", cap in ids)
    check("能力数至少包含本轮新增", len(ids) >= 40, str(len(ids)))

    print("\n── 后台作业（P4）──")
    test_jobs(registry)
    print("\n── 预算（P4）──")
    test_budget()
    print("\n── code mode（P5）──")
    test_code(registry)
    print("\n── 引擎三分返回（P6）──")
    test_triage()
    print("\n── 中途插话（收件箱）──")
    test_inbox()
    print("\n── 变异检验（P6b）──")
    test_mutation(registry)
    print("\n── MCP 工具面 ──")
    test_mcp_surface()
    print("\n── 进程容纳 ──")
    test_containment()

    failed = [n for n, ok, _ in checks if not ok]
    print()
    print(f"{len(checks) - len(failed)}/{len(checks)} PASS"
          + (f", FAILED: {failed}" if failed else ""))
    sys.exit(1 if failed else 0)


main()
