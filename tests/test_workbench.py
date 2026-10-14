"""Substrate tests: policy, sh.run, fs.patch, fs.search, verify.gate.

The policy section is deliberately adversarial. Writing the happy path for an
access-control layer proves nothing; every case below is one that a naive
implementation gets wrong, and most of them were found by exactly these probes
while the layer was being written:

  1. deny rules whose pattern uses `/` while the resolved path uses `\\`
  2. allow rules that can never beat a restrictive default (dead code)
  3. self-test examples derived from the pattern, which cannot fail
  4. only the first command of `a && b` being classified
  5. redirection targets never being checked at all
  6. a quoted `;` shredding the command into pieces
  7. a redirect target read as a command name (false `prompt`)
  8. a URL read as a filesystem path (false `deny`)

Run:  python tests/test_workbench.py
"""
import asyncio
import json
import os
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _isolate  # noqa: E402,F401  — must precede every xchat import below

from xchat.config import WORKBENCH_DIR
from xchat.kernel import bootstrap, policy as P
from xchat.kernel.contract import InvokeContext

checks: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    checks.append((name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))


async def call(registry, cap: str, **params):
    events = []
    async for e in registry.invoke(cap, params, InvokeContext(session_id="wb_test")):
        events.append(e)
    value = next((e.data.get("value") for e in events if e.type == "result"), None)
    error = next((e.data for e in events if e.type == "error"), None)
    return value, error, events


def write_script(name: str, body: str) -> str:
    """Drop a fixture script in the workbench. Returns the command to run it."""
    WORKBENCH_DIR.mkdir(parents=True, exist_ok=True)
    (WORKBENCH_DIR / name).write_text(body, encoding="utf-8")
    return f"python {name}"


# ── policy ──────────────────────────────────────────────────────────────────

def test_policy() -> None:
    pol = P.default_policy()

    problems = pol.selftest()
    check("策略内联自测全通过", not problems, f"{len(problems)} 个问题")

    home = os.environ.get("USERPROFILE") or os.path.expanduser("~")
    sensitive = [
        (f"{home}\\.ssh\\id_rsa", "ssh 私钥"),
        (f"{home}\\.aws\\credentials", "aws 凭据"),
        (f"{home}\\proj\\.ssh\\key", "嵌套的 ssh 私钥"),
        (f"{home}\\.git-credentials", "git 凭据"),
        (r"C:\Windows\System32\config\SAM", "注册表蜂巢"),
    ]
    for path, what in sensitive:
        decision, _ = pol.check_path(path, access=P.READ)
        check(f"读取被拒: {what}", decision == P.DENY, f"{decision}")

    ok_read, _ = pol.check_path(r"E:\hexin\hex\mhypbase.dll", access=P.READ)
    check("目标文件可读（只读分析不受限）", ok_read == P.ALLOW, ok_read)
    no_write, _ = pol.check_path(r"E:\hexin\hex\mhypbase.dll", access=P.WRITE)
    check("目标文件不可写（靶子神圣）", no_write == P.DENY, no_write)
    wb_write, _ = pol.check_path(WORKBENCH_DIR / "x.py", access=P.WRITE)
    check("工作台可写", wb_write == P.ALLOW, wb_write)

    # Compound commands: classifying only the first was a live bypass.
    for cmd in ("python safe.py && rm -rf /",
                "python x.py ; format C:",
                "rg foo | reg delete HKLM\\Software",
                "node a.js && diskpart"):
        decision, _ = pol.check_command(cmd)
        check(f"复合命令不放行: {cmd[:34]}", decision == P.DENY, decision)

    # Redirect targets were not checked at all.
    v = pol.classify_command("python x.py > C:/Windows/System32/drivers/etc/hosts")
    check("重定向到系统路径被拒", v["decision"] == P.DENY, v["decision"])
    v = pol.classify_command(f"python x.py > {WORKBENCH_DIR / 'out.txt'}")
    check("重定向进工作台放行", v["decision"] == P.ALLOW, v["decision"])

    # Quoted separators must not be treated as separators.
    segs = P.segments('python -c "import sys; sys.exit(0)"')
    check("引号内的 ; 不切分", len(segs) == 1 and len(segs[0]) == 3,
          f"{segs}")
    # A URL is not a path.
    v = pol.classify_command("curl http://example.com")
    check("URL 不被当作路径", v["decision"] == P.PROMPT and not v["paths"],
          f"{v['decision']} paths={len(v['paths'])}")

    # Unrestricted posture is reachable, and still honours DENY.
    free = P.default_policy(unrestricted=True)
    d, _ = free.check_command("curl http://example.com")
    check("unrestricted 放开了默认提示", d == P.ALLOW, d)
    d, _ = free.check_command("rm -rf /")
    check("unrestricted 仍守住 deny 规则", d == P.DENY, d)


def test_usability() -> None:
    """The regression that made every sh.run call fail.

    The first policy allowed only python/node/rg/git/xcore.exe among commands a
    shell agent reaches for, so `dir`, `ls`, `cd`, `echo`, `type`, `cat`,
    `where` all came back `prompt` — and with no approval channel, `prompt` is
    a hard refusal. 17 of 24 ordinary commands were refused, which is what
    "sh.run 一直都是这样 ✗" was.
    """
    pol = P.default_policy()
    ordinary = ["dir", "ls", "cd workbench", "cd /d <workspace>", "echo hi",
                "type notes.txt", "cat notes.txt", "where python", "tree",
                "findstr /c:x a.txt", "python sweep.py", "python --version",
                "node x.js", "rg --files", "git status", "xcore.exe help",
                "certutil -hashfile a.bin SHA256", "strings a.bin", "xxd a.bin",
                "Get-ChildItem workbench", "Select-String -Pattern x a.txt",
                "powershell Get-ChildItem", "ollama list", "tasklist",
                "driverquery", "whoami"]
    refused = [c for c in ordinary if pol.classify_command(c)["decision"] != P.ALLOW]
    check("常用只读/分析命令全部放行", not refused,
          f"被拒 {len(refused)}/{len(ordinary)}: {refused[:5]}")

    # Broadening must not have opened the destructive ones.
    for cmd in ("rm -rf /", "del /f /q *", "rmdir /s /q C:\\", "format C:",
                "diskpart", "reg delete HKLM\\Software", "bcdedit /set x",
                "vssadmin delete shadows"):
        check(f"破坏性命令仍被拒: {cmd[:24]}",
              pol.classify_command(cmd)["decision"] == P.DENY,
              pol.classify_command(cmd)["decision"])

    # Device sinks are not filesystem paths. `2>/dev/null` was resolved to
    # `C:\dev\null` and classified as a write outside the workbench, which
    # refused practically every command an agent writes — the most common
    # shell idiom there is.
    for cmd in ("ls -la / 2>/dev/null", "find / -iname x.apk 2>/dev/null",
                "python x.py > /dev/null", "dir 2>nul", "python x.py > NUL",
                "echo hi 2>&1", "python x.py 2>/dev/null > out.txt"):
        d = pol.classify_command(cmd)["decision"]
        check(f"设备汇放行: {cmd[:34]}", d == P.ALLOW, d)

    # ...but a redirect to a real path is still a write, and still confined.
    for cmd in ("dir > C:/Windows/System32/x", "python x.py > E:/outside.txt",
                "python x.py > C:/Users/x/.ssh/authorized_keys"):
        d = pol.classify_command(cmd)["decision"]
        check(f"重定向到真路径仍受管: {cmd[:34]}", d == P.DENY, d)

    # A prompt decision must explain how to lift it — a dead end trains the
    # agent to retry forever and tells the human nothing.
    from xchat.kernel.providers.workbench import _verdict_error, _windows_hint
    err = _verdict_error(pol.classify_command("curl http://x"),
                         what="command")
    check("需批准时给出可执行的解法",
          "rules/policy.json" in str(err) and "allow" in str(err),
          str(err)[:90])

    # The shell is cmd.exe but a shell-trained model reaches for POSIX. When the
    # shell itself reports the failure, the result carries the translation.
    hint = _windows_hint("", "'ls' is not recognized as an internal or external "
                             "command,\r\noperable program or batch file.")
    check("识别 Unix 惯用法失败", bool(hint))
    check("提示给出 dir/type/2>nul 等对照",
          all(k in hint for k in ("dir", "type", "2>nul", "%USERPROFILE%")))
    check("正常输出不触发提示", _windows_hint("dir listing", "") == "")

    # Credential stores are denied wherever they live, not just under %HOME%.
    for path in (f"{os.environ.get('USERPROFILE')}\\.ssh\\id_rsa",
                 "E:/hexin/.ssh/deploy_key",
                 "D:/keys/id_ed25519",
                 f"{os.environ.get('USERPROFILE')}\\.aws\\credentials"):
        check(f"凭据位置无关地被拒: {path[:34]}",
              pol.check_path(path, access=P.READ)[0] == P.DENY,
              pol.check_path(path, access=P.READ)[0])

    # But legitimate analysis material must stay readable — over-blocking is
    # its own failure mode.
    for path in ("E:/hexin/hex/mhypbase.dll", "D:/samples/key.pem",
                 "E:/work/server.key", "E:/hexin/hex/y.so"):
        check(f"分析素材仍可读: {path[:34]}",
              pol.check_path(path, access=P.READ)[0] == P.ALLOW,
              pol.check_path(path, access=P.READ)[0])


def test_compound_commands() -> None:
    """Segmentation of compound commands — the `&` family.

    Every case here is one that the classifier got wrong in a way a user hit
    for real, and each failure mode looks like the policy being arbitrary
    rather than broken:

      * a bare `&` (cmd.exe's sequential separator) was not a separator, so the
        second segment's argv[0] was the literal string `&` and matched no rule.
        Two allow-listed listings joined by `&` came back "no matching rule"
        while each half passed on its own.
      * `>` skipped exactly one token, so in `python x.py > out.txt 2>&1` the
        `2` and the `1` each became a command of their own. Redirecting stderr
        alongside stdout — one of the most ordinary things to type — was
        refused for two phantom commands that were never run.

    The deny cases matter more than the allow ones: a separator that splits
    commands must not become a way to smuggle a denied command past the first
    segment's verdict.
    """
    pol = P.default_policy()

    allow_cases = [
        ("bare & chains two listings", "dir & dir"),
        ("& chains listing and search", 'dir /s /b workbench & findstr /i x a.txt'),
        ("& with redirects on both", "dir 2>nul & dir 2>nul"),
        ("& with pipe in second half",
         'dir /s /b workbench & dir /s /b x | findstr /i tieba'),
        ("redirect then 2>&1", "python sweep.py > out.txt 2>&1"),
        ("2>&1 alone", "python x.py 2>&1"),
        ("stderr to a file", "python x.py 2> err.txt"),
        ("append redirect", "echo hi >> log.txt"),
        ("stdin redirect", "python x.py < input.txt"),
        ("&& unchanged", "dir && dir"),
        ("; unchanged", "dir ; dir"),
        ("| unchanged", "dir | findstr x"),
    ]
    for label, cmd in allow_cases:
        d = pol.classify_command(cmd)["decision"]
        check(f"复合命令放行: {label}", d == P.ALLOW,
              f"{d} segs={P.segments(cmd)}")

    # The security half: a chain is only as safe as its worst segment.
    deny_cases = [
        ("deny in the second half", "dir & del x.txt"),
        ("deny in the first half", "del x.txt & dir"),
        ("deny behind a redirect", "echo hi & reg add HKCU\\Software\\x"),
        ("deny after &&", "dir && format C:"),
        ("deny after ;", "dir ; del x.txt"),
    ]
    for label, cmd in deny_cases:
        d = pol.classify_command(cmd)["decision"]
        check(f"复合命令拦截: {label}", d == P.DENY,
              f"{d} segs={P.segments(cmd)}")

    # No segment may ever start with an operator: that is the shape of the bug.
    for label, cmd in allow_cases + deny_cases:
        segs = P.segments(cmd)
        head_is_op = [s for s in segs if s and s[0] in P._OPERATORS or s[:1] == ["&"]]
        check(f"没有以操作符开头的分段: {label}", not head_is_op, str(head_is_op))
        phantom = [s for s in segs if s and s[0] in ("1", "2")]
        check(f"没有幽灵 fd 分段: {label}", not phantom, str(phantom))


def test_user_policy() -> None:
    """rules/policy.json is how a human widens the sandbox without code edits."""
    import json
    path = P.USER_POLICY
    original = path.read_text(encoding="utf-8") if path.exists() else None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(
            {"allow": ["myanalyzer"], "deny": ["echo"]}), encoding="utf-8")
        pol = P.default_policy()
        d, _ = pol.check_command("myanalyzer --scan x")
        check("用户策略可放行新命令", d == P.ALLOW, d)
        d, _ = pol.check_command("echo hi")
        check("用户策略可收紧（deny 优先）", d == P.DENY, d)
        # A broken file must not stop the kernel, and must be visible.
        path.write_text("{ this is not json", encoding="utf-8")
        pol = P.default_policy()
        d, _ = pol.check_command("dir")
        check("策略文件损坏时回落到默认姿态", d == P.ALLOW, d)
    finally:
        if original is None:
            path.unlink(missing_ok=True)
        else:
            path.write_text(original, encoding="utf-8")


# ── sh.run ──────────────────────────────────────────────────────────────────

def test_searches_and_shell(registry) -> None:
    ok_cmd = write_script("_wb_ok.py", "print('hello substrate')\n")
    value, error, _ = asyncio.run(call(registry, "sh.run", command=ok_cmd))
    check("sh.run 能执行命令", error is None and value["exit_code"] == 0,
          f"exit={value and value['exit_code']}")
    check("结果自带状态行", value["text"].strip().endswith("]"),
          value["text"].strip().splitlines()[-1])
    check("状态行含退出码", "exit=0" in value["text"])

    # Head+tail: both ends survive, the middle is elided and described.
    big = write_script("_wb_big.py",
                       "for i in range(4000):\n"
                       "    print(f'line{i:05d}' + 'x' * 40)\n"
                       "print('FINAL_MARKER')\n")
    value, _, _ = asyncio.run(call(registry, "sh.run", command=big, max_chars=4000))
    text = value["stdout"]
    check("超长输出被截断", value["stdout_shape"]["truncated"])
    check("截断保留头部", "line00000" in text)
    check("截断保留尾部（结论在尾部）", "FINAL_MARKER" in text)
    check("截断标注原始长度",
          "chars total" in text and value["stdout_shape"]["original_lines"] > 1000,
          f"{value['stdout_shape']['original_lines']} 行")
    check("截断后不超过预算", len(text) <= 4000, f"{len(text)} 字符")

    _, error, _ = asyncio.run(call(registry, "sh.run", command="rm -rf /"))
    check("sh.run 拒绝被策略禁止的命令",
          (error or {}).get("code") == "policy_denied", (error or {}).get("code"))

    _, error, _ = asyncio.run(call(registry, "sh.run", command="curl http://x.test"))
    check("sh.run 对需批准的命令返回 approval_required",
          (error or {}).get("code") == "approval_required", (error or {}).get("code"))


def test_patch(registry) -> None:
    # Creation: the agent has no fs.write, so this is how a new script appears.
    fresh = WORKBENCH_DIR / "_wb_new.py"
    if fresh.exists():
        fresh.unlink()
    value, error, _ = asyncio.run(call(
        registry, "fs.patch", path=str(fresh), content="print('fresh')\n"))
    check("fs.patch 能新建文件", error is None and value["created"] is True,
          (error or {}).get("code", ""))
    check("新建内容正确", fresh.read_text(encoding="utf-8") == "print('fresh')\n")

    _, error, _ = asyncio.run(call(
        registry, "fs.patch", path=str(fresh), content="clobber\n"))
    check("fs.patch 不静默覆盖已存在文件",
          (error or {}).get("code") == "already_exists", (error or {}).get("code"))

    target = WORKBENCH_DIR / "_wb_patch.py"
    target.write_text("alpha = 1\nbeta = 2\n", encoding="utf-8")

    value, error, _ = asyncio.run(call(
        registry, "fs.patch", path=str(target),
        edits=[{"old": "alpha = 1", "new": "alpha = 42"}]))
    check("fs.patch 应用成功", error is None and value["chars_after"] > 0,
          (error or {}).get("code", ""))
    check("fs.patch 写入生效", "alpha = 42" in target.read_text(encoding="utf-8"))

    target.write_text("dup = 1\ndup = 1\n", encoding="utf-8")
    _, error, _ = asyncio.run(call(
        registry, "fs.patch", path=str(target),
        edits=[{"old": "dup = 1", "new": "dup = 2"}]))
    check("fs.patch 拒绝歧义匹配",
          (error or {}).get("code") == "patch_ambiguous", (error or {}).get("code"))

    _, error, _ = asyncio.run(call(
        registry, "fs.patch", path=str(target),
        edits=[{"old": "not here", "new": "x"}]))
    check("fs.patch 拒绝找不到的文本",
          (error or {}).get("code") == "patch_no_match", (error or {}).get("code"))

    # Apply-or-fail: the first edit must not land if a later one is invalid.
    target.write_text("keep = 1\n", encoding="utf-8")
    _, error, _ = asyncio.run(call(
        registry, "fs.patch", path=str(target),
        edits=[{"old": "keep = 1", "new": "keep = 2"},
               {"old": "missing", "new": "x"}]))
    check("fs.patch 全或无（前面不能先落盘）",
          "keep = 1" in target.read_text(encoding="utf-8"),
          target.read_text(encoding="utf-8").strip())

    outside = Path(os.environ.get("TEMP", ".")) / "_wb_outside.txt"
    outside.write_text("x", encoding="utf-8")
    _, error, _ = asyncio.run(call(
        registry, "fs.patch", path=str(outside),
        edits=[{"old": "x", "new": "y"}]))
    check("fs.patch 拒绝改工作台外的文件",
          (error or {}).get("code") == "policy_denied", (error or {}).get("code"))


def test_search(registry) -> None:
    (WORKBENCH_DIR / "_wb_s1.txt").write_text("needle here\n" * 3, encoding="utf-8")
    (WORKBENCH_DIR / "_wb_s2.txt").write_text("nothing\n", encoding="utf-8")

    value, error, _ = asyncio.run(call(
        registry, "fs.search", pattern="needle", path=str(WORKBENCH_DIR),
        glob="_wb_s*.txt"))
    check("fs.search 统计到命中", error is None and value["total_hits"] == 3,
          f"hits={value and value['total_hits']}")
    check("fs.search 返回文件名", any("_wb_s1" in f["file"] for f in value["files"]))
    # The whole point: no content, so the agent cannot walk every match.
    check("fs.search 不返回内容", "needle here" not in json.dumps(value),
          "只返回计数与文件名")
    check("fs.search 明确说明不返回内容", "not returned by design" in value["text"])

    _, error, _ = asyncio.run(call(registry, "fs.search", pattern="[unclosed"))
    check("fs.search 拒绝坏正则",
          (error or {}).get("code") == "invalid_params", (error or {}).get("code"))


def test_gate(registry) -> None:
    ok = write_script("_wb_gate_ok.py", "raise SystemExit(0)\n")
    bad = write_script("_wb_gate_bad.py", "raise SystemExit(1)\n")
    summary = write_script(
        "_wb_gate_summary.py",
        "import json\n"
        "print(json.dumps({'cases_total': 986, 'cases_passed': 986,\n"
        "                  'failures': []}))\n"
        "raise SystemExit(0)\n")

    # 1. No negative control -> refused. Two layers enforce this, on purpose:
    #    the schema marks the field required (so the model is told it cannot be
    #    omitted, and the registry refuses before the handler runs), and the
    #    handler additionally refuses an empty string with a message that
    #    explains *why* it is mandatory — a bare "missing parameter" teaches the
    #    agent nothing about negative controls.
    _, error, _ = asyncio.run(call(registry, "verify.gate",
                                   claim="x", check=ok))
    check("缺负对照被拒（schema 层）",
          (error or {}).get("code") == "invalid_params",
          (error or {}).get("code"))
    _, error, _ = asyncio.run(call(registry, "verify.gate",
                                   claim="x", check=ok, negative_control="  "))
    check("负对照为空被拒（handler 层，附解释）",
          (error or {}).get("code") == "negative_control_required",
          (error or {}).get("code"))

    # 2. Negative control PASSES -> the check proves nothing.
    _, error, _ = asyncio.run(call(registry, "verify.gate",
                                   claim="x", check=ok, negative_control=ok))
    check("负对照通过则驳回（检查无区分力）",
          (error or {}).get("code") == "no_discriminating_power",
          (error or {}).get("code"))

    # 3. Control fails, check passes -> verified.
    value, error, _ = asyncio.run(call(registry, "verify.gate",
                                       claim="公式覆盖全部用例",
                                       check=ok, negative_control=bad))
    check("负对照失败 + 检查通过 = 已验证",
          error is None and value["verified"] is True,
          f"verified={value and value['verified']}")

    # 4. Control fails, check fails -> not verified.
    value, _, _ = asyncio.run(call(registry, "verify.gate",
                                   claim="x", check=bad, negative_control=bad))
    check("检查失败 = 未验证", value["verified"] is False)

    # 5. Structured summary -> denominator and failures are captured.
    value, _, _ = asyncio.run(call(registry, "verify.gate",
                                   claim="986/986",
                                   check=summary, negative_control=bad))
    check("闸门记下分母", value["cases_total"] == 986,
          f"cases_total={value['cases_total']}")
    check("闸门记下通过数", value["cases_passed"] == 986)
    check("闸门识别结构化摘要", value["has_structured_summary"] is True)

    # 6. No summary -> says so rather than implying coverage.
    value, _, _ = asyncio.run(call(registry, "verify.gate",
                                   claim="x", check=ok, negative_control=bad))
    check("无摘要时明确提示要打印分母",
          value["has_structured_summary"] is False
          and "not reported" in value["text"])


def cleanup() -> None:
    for p in WORKBENCH_DIR.glob("_wb_*"):
        try:
            p.unlink()
        except OSError:
            pass


def main() -> None:
    registry = bootstrap(reset=True)
    ids = {s["id"] for s in registry.specs()}
    for cap in ("sh.run", "fs.patch", "fs.search", "verify.gate"):
        check(f"能力已注册: {cap}", cap in ids)
    # Deliberately not an exact count: a hardcoded total breaks every time a
    # capability is added, which trains people to update the number instead of
    # reading the failure. What matters is that the substrate is registered.
    check("能力数至少包含基座", len(ids) >= 28, f"{len(ids)}")

    print("\n── 策略层（对抗性）──")
    test_policy()
    print("\n── 策略可用性（曾导致 sh.run 全失败）──")
    test_usability()
    print("\n── 复合命令分段（& / 重定向）──")
    test_compound_commands()
    print("\n── 用户策略文件 ──")
    test_user_policy()
    print("\n── sh.run ──")
    test_searches_and_shell(registry)
    print("\n── fs.patch ──")
    test_patch(registry)
    print("\n── fs.search ──")
    test_search(registry)
    print("\n── verify.gate（负对照闸门）──")
    test_gate(registry)

    cleanup()
    failed = [n for n, ok, _ in checks if not ok]
    print()
    print(f"{len(checks) - len(failed)}/{len(checks)} PASS"
          + (f", FAILED: {failed}" if failed else ""))
    sys.exit(1 if failed else 0)


main()
