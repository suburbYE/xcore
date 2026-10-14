"""
Deterministic access policy for the agent substrate.

Design decision, taken from Codex's `execpolicy` and DSH's `fs-observation-policy`:
**"may I do this?" is a policy question answered by code, not a judgement call
handed to the model.** Prompts express preferences; only rules can guarantee.

Two layers of rules:

* **Path rules** — which parts of the filesystem the agent may read, write, or
  is refused outright. The default posture is a sandbox: exactly one directory
  (`workbench/`) is writable, everything else is read-only, and a short list of
  locations (system directories, credential stores) is denied even for reading.
  The posture can be widened per task by adding writable roots, which is how
  "sandbox by default, but xcore can be let loose on the machine" is expressed
  without editing code.

* **Command rules** — argv-prefix rules over shell invocations, most restrictive
  wins (`deny` > `prompt` > `allow`).

Both rule kinds carry inline self-tests. A rule whose self-test disagrees with
its own decision is a bug, and `selftest()` surfaces it at load time rather than
at the moment the agent runs `rm -rf`. Codex does the same thing with `match` /
`not_match` inside its Starlark policy files.

An honest limitation, stated here rather than buried: **this policy is a
guardrail against accidents, not a security boundary.** It inspects the outer
command line, so `python -c "import os; os.system(...)"` walks straight through
it. It exists to stop an agent from typing `rm -rf` or reading an SSH key by
mistake, and to make consequential operations ask first. Real confinement needs
OS enforcement (Windows restricted token + a Job Object, as Codex does), which
is a separate work item.

The first version of this table was also **too tight to be usable**: it allowed
only python/node/rg/git/xcore.exe, so 17 of the 24 commands an agent reaches for
first (`dir`, `ls`, `cd`, `echo`, `type`, `cat`, `where`, ...) came back
`prompt`. Because there is no approval channel yet, `prompt` behaves as a hard
refusal — the agent could not even list a directory, and every `sh.run` call
failed. A policy that blocks reading is not a safe policy, it is a broken one.
"""

from __future__ import annotations

import fnmatch
import os
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path

from ..config import BASE_DIR, STATE_DIR, WORKBENCH_DIR

# ── decisions ───────────────────────────────────────────────────────────────

ALLOW = "allow"
PROMPT = "prompt"
DENY = "deny"

# Most restrictive wins. The ordering lives in one place so the resolver below
# cannot drift from it.
_SEVERITY = {ALLOW: 0, PROMPT: 1, DENY: 2}

# Path classes, in the order they are reported to the caller.
READ = "read"
WRITE = "write"


def _worse(a: str, b: str) -> str:
    return a if _SEVERITY[a] >= _SEVERITY[b] else b


# ── rules ───────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class PathRule:
    """One glob rule over absolute paths.

    `decision` applies to `access` (read or write). A rule may set both, e.g.
    the workbench is writable and readable while a credential store is denied
    for either.
    """

    pattern: str
    access: str = WRITE
    decision: str = DENY
    reason: str = ""
    # Inline self-tests: absolute-ish paths that must resolve to `decision`.
    match: tuple[str, ...] = ()
    not_match: tuple[str, ...] = ()
    case_sensitive: bool = False

    def applies_to(self, path: str) -> bool:
        # Separators are normalised to "/" on both sides. Path.resolve() returns
        # backslashes on Windows while a hand-written pattern may use forwards,
        # and comparing them raw made every such rule silently unmatchable —
        # which the inline self-tests caught as "expected deny, got allow".
        pat = _norm(self.pattern)
        target = _norm(path)
        if not self.case_sensitive:
            pat = pat.lower()
            target = target.lower()
        return fnmatch.fnmatchcase(target, pat)


@dataclass(frozen=True)
class CommandRule:
    """One argv-prefix rule over a shell command.

    Matching is on the *first tokens* of the command after the executable, so
    `git status` and `git push` can differ while `rg` covers `rg --files`.
    """

    prefix: tuple[str, ...]
    decision: str = PROMPT
    reason: str = ""
    match: tuple[str, ...] = ()
    not_match: tuple[str, ...] = ()


# ── the policy ──────────────────────────────────────────────────────────────

@dataclass
class Policy:
    writable_roots: list[Path] = field(default_factory=list)
    readable_roots: list[Path] = field(default_factory=list)   # empty = anywhere
    path_rules: list[PathRule] = field(default_factory=list)
    command_rules: list[CommandRule] = field(default_factory=list)
    # When True the agent may touch anything (still subject to DENY rules).
    unrestricted: bool = False

    # ── paths ───────────────────────────────────────────────────────────────

    def resolve(self, path: str | Path, *, base: Path | None = None) -> Path:
        p = Path(path)
        if not p.is_absolute():
            p = (base or Path.cwd()) / p
        return Path(os.path.normpath(str(p))).resolve(strict=False)

    def check_path(self, path: str | Path, *, access: str = WRITE,
                   base: Path | None = None) -> tuple[str, str]:
        """Return (decision, reason) for one path.

        Rule order: explicit DENY rules first, then ALLOW rules, then the
        default posture. That ordering is what keeps a later ALLOW from
        punching through an earlier DENY.
        """
        target = self.resolve(path, base=base)
        text = str(target)

        deny_reason = ""
        allow_reason = ""
        for rule in self.path_rules:
            # A rule with access=read also constrains writes; a write rule does
            # not constrain reads. Reading is the weaker operation, so a write
            # restriction must not silently become a read restriction.
            if rule.access == WRITE and access == READ and rule.decision != DENY:
                continue
            if not rule.applies_to(text):
                continue
            if rule.decision == DENY:
                deny_reason = rule.reason or f"denied by rule {rule.pattern}"
            elif rule.decision == ALLOW and not allow_reason:
                allow_reason = rule.reason or f"allowed by rule {rule.pattern}"

        if deny_reason:
            return DENY, deny_reason
        if allow_reason:
            return ALLOW, allow_reason

        if self.unrestricted:
            return ALLOW, "unrestricted policy"

        # Default posture. Reads are open unless readable_roots is set; writes
        # are confined to the workbench.
        if access == WRITE:
            for root in self.writable_roots:
                if _under(target, root):
                    return ALLOW, "inside a writable root"
            return DENY, ("writes are confined to the workbench; "
                          "pass policy=unrestricted to widen")
        for root in self.readable_roots:
            if _under(target, root):
                return ALLOW, "inside a readable root"
        if self.readable_roots:
            return DENY, "outside the configured readable roots"
        return ALLOW, "reads are unrestricted by default"

    # ── commands ────────────────────────────────────────────────────────────

    def check_command(self, command: str) -> tuple[str, str]:
        """Classify a shell command line.

        **Every** segment is classified and the most restrictive verdict wins.
        Classifying only the first command was a bypass: `python safe.py && rm
        -rf /` read as `python` and came back `allow`. `deny` wins outright
        regardless of specificity, so a forbid rule cannot be defeated by a
        broader allow rule.

        Within one command, resolution is by specificity: the longest matching
        argv prefix wins, so `git` can be allowed while `git push` still asks.
        Note the asymmetry with the default — the posture is *restrictive*, so
        an explicit `allow` has to be able to beat it. An earlier version
        compared severities globally and therefore could never relax the
        default, making every allow rule dead code (the inline self-tests
        reported six failures).
        """
        segs = segments(command)
        if not segs:
            return DENY, "empty command"

        worst: tuple[str, str] | None = None
        for seg in segs:
            decision, reason = self._classify_one(seg)
            if worst is None or _SEVERITY[decision] > _SEVERITY[worst[0]]:
                worst = (decision, reason)
            if worst[0] == DENY:
                break
        return worst or (PROMPT, "no matching rule")

    def _classify_one(self, tokens: list[str]) -> tuple[str, str]:
        if not tokens:
            return PROMPT, "empty segment"
        exe = os.path.basename(tokens[0].strip('"\'')).lower()

        best: CommandRule | None = None
        best_key: tuple[int, int] = (-1, -1)
        deny_reason = ""

        for rule in self.command_rules:
            if not rule.prefix:
                continue
            want = tuple(p.lower() for p in rule.prefix)
            head = (exe, *(t.lower() for t in tokens[1:len(want)]))
            if head != want:
                continue
            if rule.decision == DENY and not deny_reason:
                deny_reason = rule.reason or f"matched rule {' '.join(rule.prefix)}"
            key = (len(want), _SEVERITY[rule.decision])
            if key > best_key:
                best, best_key = rule, key

        if deny_reason:
            return DENY, deny_reason
        if best is not None:
            # `unrestricted` lifts the *prompt* tier, not the deny tier. Asking
            # for the sandbox to be opened and then still being refused on
            # `curl` would make the switch useless, while `rm -rf` must never
            # become reachable by a flag whose whole purpose is convenience.
            if best.decision == PROMPT and self.unrestricted:
                return ALLOW, f"unrestricted; would otherwise ask ({best.reason or 'matched rule'})"
            return best.decision, (best.reason
                                   or f"matched rule {' '.join(best.prefix)}")
        if self.unrestricted:
            return ALLOW, "unrestricted policy"
        return PROMPT, "no matching rule"

    def classify_command(self, command: str) -> dict:
        """Full verdict for one command line: every segment plus every path.

        A command is only as safe as the paths in it, so segment decisions and
        path decisions are combined with most-restrictive-wins:
        `type E:\\secret.txt` is a read of a denied path even though `type`
        itself is harmless.
        """
        decision, reason = self.check_command(command)
        paths = []
        for raw, access in extract_paths(command):
            sub, sub_reason = self.check_path(raw, access=access)
            paths.append({"path": str(self.resolve(raw)), "access": access,
                          "decision": sub, "reason": sub_reason})
            if _SEVERITY[sub] > _SEVERITY[decision]:
                decision, reason = sub, f"{raw}: {sub_reason}"

        return {"decision": decision, "reason": reason, "paths": paths,
                "command": command, "severity": _SEVERITY[decision]}

    # ── self-test ───────────────────────────────────────────────────────────

    def selftest(self) -> list[dict]:
        """Run every rule's inline examples. Returns one record per failure.

        This is the mechanism that keeps a policy honest: a rule that says
        `deny` while its own `match` example is classified `allow` is reported
        here instead of failing open at runtime. Codex puts the same idea in
        its Starlark rules and ships a `check` subcommand for it.
        """
        problems: list[dict] = []
        for rule in self.path_rules:
            for example in rule.match:
                got, reason = self.check_path(example, access=rule.access)
                if got != rule.decision:
                    problems.append({
                        "kind": "path", "rule": rule.pattern, "example": example,
                        "expected": rule.decision, "got": got, "reason": reason,
                        "which": "match",
                    })
            for example in rule.not_match:
                got, _ = self.check_path(example, access=rule.access)
                if got == rule.decision:
                    problems.append({
                        "kind": "path", "rule": rule.pattern, "example": example,
                        "expected": f"not {rule.decision}", "got": got,
                        "reason": "example in not_match resolved to the rule's decision",
                        "which": "not_match",
                    })
        for rule in self.command_rules:
            for example in rule.match:
                got, _ = self.check_command(example)
                if got != rule.decision:
                    problems.append({
                        "kind": "command", "rule": " ".join(rule.prefix),
                        "example": example, "expected": rule.decision, "got": got,
                        "which": "match",
                    })
            for example in rule.not_match:
                got, _ = self.check_command(example)
                if got == rule.decision:
                    problems.append({
                        "kind": "command", "rule": " ".join(rule.prefix),
                        "example": example, "expected": f"not {rule.decision}",
                        "got": got, "which": "not_match",
                    })
        return problems


def _under(target: Path, root: Path) -> bool:
    try:
        target.relative_to(root)
        return True
    except ValueError:
        return False


def _norm(path: str) -> str:
    """Canonical separator form for glob matching (forward slashes)."""
    return str(path).replace("\\", "/")


# ── command parsing ─────────────────────────────────────────────────────────

# Commands that write. Used only to pick the access class for path arguments;
# getting this wrong is a false ALLOW on a *read* of a write-protected path,
# never a silent write into a protected one, because the rule table is still
# consulted first.
_WRITE_VERBS = {
    "rm", "del", "erase", "mv", "move", "cp", "copy", "mkdir", "md",
    "rmdir", "rd", "tee", "touch", "set-content", "out-file", "new-item",
    "remove-item", "copy-item", "move-item", "rename-item", "truncate",
    "dd", "install", "patch",
}

# A URI is not a filesystem path. `curl http://x` was classified as a write to
# a path named "http://x", which landed outside the writable root and turned a
# plain download into `deny`.
_URI = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")

# Device sinks and std streams are not filesystem paths. `2>/dev/null` is the
# single most common shell idiom for discarding output, and treating it as a
# write to `C:\dev\null` refused essentially every command an agent writes.
# `$null` additionally appears as a PowerShell stream name.
_DEVICE_SINKS = {
    "/dev/null", "/dev/zero", "/dev/stdout", "/dev/stderr", "/dev/tty",
    "/dev/full", "/dev/random", "/dev/urandom",
    "nul", "null", "$null", "/nul",
    "con", "prn", "aux",           # Windows reserved device names
    "/dev/fd/1", "/dev/fd/2", "&1", "&2", "&-",
}

_OPERATORS = ("&&", "||", ";", "|", ">>", ">", "<")


def _tokenize(command: str) -> list[str]:
    """Split a command line into tokens, keeping operators as their own tokens.

    Quote-aware: a `;` or `|` inside `"..."` is part of the argument, not a
    separator. The previous version did a global string replace before
    tokenising, which shredded `python -c "import os; ..."` into pieces and
    made the policy classify arguments as commands. That direction is only ever
    over-restrictive (it can produce a spurious `prompt`, never a spurious
    `allow`), but a policy layer that misreads its input is not one you can
    reason about, so the state machine is worth the twenty lines.
    """
    tokens: list[str] = []
    current: list[str] = []
    quote: str | None = None
    i = 0
    n = len(command)

    def flush() -> None:
        if current:
            tokens.append("".join(current))
            current.clear()

    while i < n:
        ch = command[i]
        if quote is not None:
            current.append(ch)
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            current.append(ch)
            i += 1
            continue
        if ch in ("\r", "\n"):
            flush()
            tokens.append(";")
            i += 1
            continue
        if ch.isspace():
            flush()
            i += 1
            continue

        two = command[i:i + 2]
        if two in ("&&", "||", ">>"):
            flush()
            tokens.append(two)
            i += 2
            continue
        if ch in (";", "|", ">", "<"):
            flush()
            tokens.append(ch)
            i += 1
            continue
        current.append(ch)
        i += 1

    flush()
    return tokens


def split_command(command: str) -> list[str]:
    """All tokens of a command line, operators included."""
    return _tokenize(command)


def _redirect_end(toks: list[str], i: int) -> int:
    """Index just past a redirection starting at ``toks[i]``, or ``i`` if none.

    A redirection is ``[fd]? (">" | ">>" | "<") ( "&" fd | target )``. It has to
    be recognised as a whole shape rather than consumed token by token, because
    the two halves of `2>&1` are a token apart: skipping only the target leaves
    the `2` behind, and the `1` behind that, each of which then reads as a
    command named "2" and "1" and matches no rule.

    That was a live refusal: `python x.py > out.txt 2>&1` -- stdout to a file,
    stderr with it, one of the most ordinary things to type -- classified as
    ``prompt`` because of two phantom commands that were never run.
    """
    j = i
    if toks[j] in ("1", "2"):
        j += 1
        if j >= len(toks) or toks[j] not in (">", ">>", "<"):
            return i          # a bare "2" argument, not an fd prefix
    if toks[j] not in (">", ">>", "<"):
        return i
    j += 1
    if j < len(toks) and toks[j] == "&":
        return j + 2          # `>&1`: an fd, not a path
    return j + 1              # the target, checked separately by extract_paths


def segments(command: str) -> list[list[str]]:
    """Split a compound command into one token list per command.

    Redirection targets are *skipped* rather than treated as a new command.
    Without this, `python sweep.py > out.txt` produced a second "command"
    named `out.txt`, which matched no rule and turned a legitimate redirect
    into `prompt`. The target is still checked — as a path, by
    ``extract_paths``, with write access — which is where it belongs.

    A bare `&` separates commands in cmd.exe, same as `&&`. It is handled here
    rather than by adding it to ``_OPERATORS``, because it cannot simply join
    that tuple: see ``_redirect_end`` for why. Missing it entirely was a real
    refusal -- two allow-listed listings joined by `&` came back
    "no matching rule", because the second segment's argv[0] was the literal
    string `&`. Each half passed on its own, which is what made the policy look
    arbitrary rather than wrong.
    """
    toks = _tokenize(command)
    out: list[list[str]] = []
    current: list[str] = []
    i = 0
    while i < len(toks):
        end = _redirect_end(toks, i)
        if end > i:
            if current:
                out.append(current)
                current = []
            i = end
            continue
        tok = toks[i]
        if tok in _OPERATORS or tok == "&":
            if current:
                out.append(current)
                current = []
            i += 1
            continue
        current.append(tok)
        i += 1
    if current:
        out.append(current)
    return out


# Path-looking tokens: quoted strings, drive-letter paths, UNC paths, or any
# token containing a separator. Deliberately over-inclusive — a false positive
# costs an extra policy check, a false negative costs a bypass.
_PATHISH = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\|/|\.{1,2}[\\/])")
_DRIVE = re.compile(r"[A-Za-z]:[\\/]")


def extract_paths(command: str) -> list[tuple[str, str]]:
    """Every path-looking token, paired with the access it implies.

    Three sources, because all three can name a protected location:

    * the command name itself, when it is a path (`C:\\tools\\x.exe`)
    * arguments (access taken from the command's verb class)
    * **redirection targets** — always a write for `>` / `>>`, always a read
      for `<`. These were previously skipped entirely, so
      `python x.py > C:\\Windows\\System32\\drivers\\etc\\hosts` checked only
      `x.py` and came back clean.
    """
    toks = _tokenize(command)
    found: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(tok: str, access: str) -> None:
        candidate = tok.strip("\"'")
        if not candidate or candidate.startswith("-"):
            return
        if not _looks_like_path(candidate) or candidate in seen:
            return
        seen.add(candidate)
        found.append((candidate, access))

    first_in_segment = True
    redirect: str | None = None
    segment_access = READ
    exe = ""

    for tok in toks:
        if tok in _OPERATORS:
            if tok in (">", ">>", "<"):
                redirect = WRITE if tok != "<" else READ
            else:
                first_in_segment = True
            continue
        if redirect is not None:
            add(tok, redirect)
            redirect = None
            continue
        if first_in_segment:
            first_in_segment = False
            exe = os.path.basename(tok.strip("\"'")).lower()
            segment_access = WRITE if exe in _WRITE_VERBS else READ
            add(tok, READ)
            continue
        add(tok, segment_access)

    return found


def _looks_like_path(token: str) -> bool:
    """Deliberately over-inclusive, except for things that are not paths at all.

    A false positive costs one extra policy check; a false negative costs a
    bypass, so anything with a separator or a drive letter counts — but device
    sinks, URIs and redirection operators are excluded, because refusing those
    refuses ordinary shell usage.
    """
    if not token or token.startswith("--"):
        return False
    if _URI.match(token):
        return False
    low = token.lower().rstrip("/\\") or token.lower()
    if low in _DEVICE_SINKS or token.lower() in _DEVICE_SINKS:
        return False
    if _PATHISH.match(token) or _DRIVE.search(token):
        return True
    if "\\" in token or "/" in token:
        # Exclude obvious non-paths that merely contain a slash, e.g. a bare
        # `a/b` inside a regex is still checked — over-inclusion is intended.
        return True
    return False


# ── the default posture ─────────────────────────────────────────────────────

def default_policy(*, unrestricted: bool = False,
                   extra_writable: list[Path] | None = None,
                   base_root: Path | None = None) -> Policy:
    """The posture xcore starts in: sandbox on, widened by `rules/policy.json`.

    A user policy file is merged on top. That is the mechanism behind "sandbox
    by default, but it can be let loose": adding `{"allow": ["pip"]}` is a
    config edit a human makes in ten seconds, not a code change and a rebuild.
    """
    # The writable root is the caller's workspace when one is given, so a
    # conversation writes into its own folder. WORKBENCH_DIR stays writable as
    # well so that CLI/direct use, which has no conversation, keeps working.
    writable = [base_root or WORKBENCH_DIR, WORKBENCH_DIR,
                *(extra_writable or [])]

    home = _norm(os.environ.get("USERPROFILE") or os.path.expanduser("~"))

    # Reads outside the workbench are allowed, but credential stores are
    # refused even for reading — an agent that can read them can leak them into
    # a cloud call in one step.
    #
    # Patterns are LOCATION-INDEPENDENT. The first version anchored them to the
    # user's home (`{home}/.ssh/**` plus a nested variant), so an `.ssh`
    # directory anywhere else — a checkout on another drive, a mounted image —
    # was readable. A credential store is a credential store wherever it sits.
    #
    # Deliberately NOT denied: `*.pem` / `*.key`. A reversing task may legitimately
    # need to analyse key material, and a filename is not a reliable signal that
    # the contents are a live secret. Over-blocking is its own failure: the
    # previous policy was so tight that 17 of 24 ordinary commands were refused.
    denied: list[tuple[str, str]] = [
        ("**/.ssh/**", "ssh keys"),
        ("**/.aws/**", "aws credentials"),
        ("**/.config/gcloud/**", "gcloud credentials"),
        ("**/.git-credentials", "git credentials"),
        ("**/.netrc", "netrc credentials"),
        ("**/id_rsa", "ssh private key"),
        ("**/id_ed25519", "ssh private key"),
        ("**/id_ecdsa", "ssh private key"),
        # The token lives under state/, wherever state/ has been rooted.
        # Hardcoding BASE_DIR/state here would leave this rule pointing at a
        # directory that no longer holds the token once XCORE_STATE_ROOT is set,
        # so the credential would be readable while the self-test still passed.
        (_norm(STATE_DIR / "server_token"), "xcore server token"),
        (_norm(BASE_DIR / "cloud.json"), "cloud provider keys"),
        ("C:/Windows/System32/config/**", "windows registry hives"),
        ("**/AppData/Roaming/Microsoft/Credentials/**", "windows credential store"),
        ("**/AppData/Local/Microsoft/Credentials/**", "windows credential store"),
    ]

    # Hand-written examples, one per rule, of the path shape the rule exists to
    # stop. An earlier version derived examples from the pattern itself
    # (`**` -> `x`), which meant the example always had the pattern's own shape
    # and could never fail — so `~/.ssh/id_rsa` was allowed while the self-test
    # reported zero problems. A generated example cannot falsify its generator.
    examples = {
        "ssh keys": (f"{home}/.ssh/id_rsa", "E:/hexin/.ssh/deploy_key"),
        "aws credentials": (f"{home}/.aws/credentials", f"{home}/.aws/config"),
        "gcloud credentials": (f"{home}/.config/gcloud/credentials.db",),
        "git credentials": (f"{home}/.git-credentials",),
        "netrc credentials": (f"{home}/.netrc",),
        "ssh private key": (f"{home}/.ssh/id_rsa", "D:/keys/id_ed25519"),
        "xcore server token": (_norm(STATE_DIR / "server_token"),),
        "cloud provider keys": (_norm(BASE_DIR / "cloud.json"),),
        "windows registry hives": ("C:/Windows/System32/config/SAM",),
        "windows credential store": (
            f"{home}/AppData/Roaming/Microsoft/Credentials/DFBE70A7E5CC19A3",),
    }

    path_rules = [
        PathRule(pattern=pat, access=READ, decision=DENY,
                 reason=f"{why} are off limits",
                 match=examples.get(why, ()))
        for pat, why in denied
    ]
    # Writing anywhere other than a writable root is denied even when a broad
    # ALLOW rule would otherwise cover it. The not_match example is a path
    # inside the real workbench, because "not matched by THIS rule" still has
    # to clear the default write posture to be allowed.
    path_rules.append(PathRule(
        pattern="C:/Windows/**", access=WRITE, decision=DENY,
        reason="system directory",
        match=("C:/Windows/System32/drivers/etc/hosts",),
        not_match=(str(WORKBENCH_DIR / "notes.txt"),),
    ))

    command_rules = [
        # ── deny: destructive or non-recoverable ────────────────────────────
        CommandRule(prefix=("rm",), decision=DENY, reason="destructive",
                    match=("rm -rf /",), not_match=("rg rm",)),
        # `del` was missing from the deny list while being listed as a write
        # verb, so `del /f /q *` fell through to the default and merely asked.
        CommandRule(prefix=("del",), decision=DENY, reason="destructive",
                    match=("del /f /q *",), not_match=("dir del",)),
        CommandRule(prefix=("erase",), decision=DENY, reason="destructive"),
        CommandRule(prefix=("rmdir",), decision=DENY, reason="destructive"),
        CommandRule(prefix=("rd",), decision=DENY, reason="destructive"),
        CommandRule(prefix=("deltree",), decision=DENY, reason="destructive"),
        CommandRule(prefix=("format",), decision=DENY, reason="destructive"),
        CommandRule(prefix=("diskpart",), decision=DENY, reason="disk partitioning"),
        CommandRule(prefix=("mkfs",), decision=DENY, reason="filesystem creation"),
        CommandRule(prefix=("reg",), decision=DENY, reason="registry mutation",
                    match=("reg delete HKLM\\Software",), not_match=("rg reg",)),
        CommandRule(prefix=("bcdedit",), decision=DENY, reason="boot configuration"),
        CommandRule(prefix=("shutdown",), decision=DENY, reason="session control"),
        CommandRule(prefix=("vssadmin",), decision=DENY, reason="shadow copies"),

        # ── prompt: consequential, a human should decide ────────────────────
        CommandRule(prefix=("sc",), decision=PROMPT, reason="service control"),
        CommandRule(prefix=("net",), decision=PROMPT, reason="accounts and shares"),
        CommandRule(prefix=("schtasks",), decision=PROMPT, reason="scheduled tasks"),
        CommandRule(prefix=("takeown",), decision=PROMPT, reason="ownership change"),
        CommandRule(prefix=("icacls",), decision=PROMPT, reason="ACL change"),
        CommandRule(prefix=("attrib",), decision=PROMPT, reason="attribute change"),
        CommandRule(prefix=("dd",), decision=PROMPT, reason="raw device write"),
        CommandRule(prefix=("wmic",), decision=PROMPT, reason="broad system mutation surface"),
        CommandRule(prefix=("curl",), decision=PROMPT, reason="network access"),
        CommandRule(prefix=("wget",), decision=PROMPT, reason="network access"),
        CommandRule(prefix=("pip",), decision=PROMPT, reason="modifies the Python environment"),
        CommandRule(prefix=("npm",), decision=PROMPT, reason="modifies the node environment"),

        # ── allow: navigation, inspection, and the analysis runtimes ────────
        #
        # This list is deliberately generous. The first version allowed only
        # python/node/rg/git/xcore.exe, which meant 17 of the 24 commands an
        # agent reaches for first (`dir`, `ls`, `cd`, `echo`, `type`, `cat`,
        # `where`, ...) came back `prompt` — and since there is no approval
        # channel yet, `prompt` was indistinguishable from a hard failure. The
        # policy exists to stop destructive and credential-touching operations,
        # not to stop a read-only listing.
        CommandRule(prefix=("dir",), decision=ALLOW, reason="listing",
                    match=("dir /b",), not_match=("rm -rf /",)),
        CommandRule(prefix=("ls",), decision=ALLOW, reason="listing"),
        CommandRule(prefix=("pwd",), decision=ALLOW, reason="navigation"),
        CommandRule(prefix=("cd",), decision=ALLOW, reason="navigation"),
        CommandRule(prefix=("chdir",), decision=ALLOW, reason="navigation"),
        CommandRule(prefix=("tree",), decision=ALLOW, reason="listing"),
        CommandRule(prefix=("echo",), decision=ALLOW, reason="output"),
        CommandRule(prefix=("type",), decision=ALLOW, reason="read file"),
        CommandRule(prefix=("cat",), decision=ALLOW, reason="read file"),
        CommandRule(prefix=("head",), decision=ALLOW, reason="read file"),
        CommandRule(prefix=("tail",), decision=ALLOW, reason="read file"),
        CommandRule(prefix=("more",), decision=ALLOW, reason="read file"),
        CommandRule(prefix=("sort",), decision=ALLOW, reason="read file"),
        CommandRule(prefix=("wc",), decision=ALLOW, reason="count"),
        CommandRule(prefix=("findstr",), decision=ALLOW, reason="search"),
        CommandRule(prefix=("find",), decision=ALLOW, reason="search"),
        CommandRule(prefix=("where",), decision=ALLOW, reason="locate"),
        CommandRule(prefix=("which",), decision=ALLOW, reason="locate"),
        CommandRule(prefix=("set",), decision=ALLOW, reason="environment query",
                    match=("set PATH",), not_match=("rm -rf /",)),
        CommandRule(prefix=("ver",), decision=ALLOW, reason="system info"),
        CommandRule(prefix=("hostname",), decision=ALLOW, reason="system info"),
        CommandRule(prefix=("whoami",), decision=ALLOW, reason="system info"),
        CommandRule(prefix=("tasklist",), decision=ALLOW, reason="process listing"),
        CommandRule(prefix=("systeminfo",), decision=ALLOW, reason="system info"),
        CommandRule(prefix=("driverquery",), decision=ALLOW, reason="driver listing"),
        CommandRule(prefix=("certutil",), decision=ALLOW, reason="hashing",
                    match=("certutil -hashfile a.bin SHA256",)),
        CommandRule(prefix=("sha256sum",), decision=ALLOW, reason="hashing"),
        CommandRule(prefix=("md5sum",), decision=ALLOW, reason="hashing"),
        CommandRule(prefix=("strings",), decision=ALLOW, reason="string extraction"),
        CommandRule(prefix=("xxd",), decision=ALLOW, reason="hex dump"),
        CommandRule(prefix=("hexdump",), decision=ALLOW, reason="hex dump"),
        CommandRule(prefix=("od",), decision=ALLOW, reason="hex dump"),
        CommandRule(prefix=("file",), decision=ALLOW, reason="type identification"),
        CommandRule(prefix=("objdump",), decision=ALLOW, reason="disassembly"),
        CommandRule(prefix=("readelf",), decision=ALLOW, reason="ELF analysis"),
        CommandRule(prefix=("nm",), decision=ALLOW, reason="symbol listing"),
        CommandRule(prefix=("jq",), decision=ALLOW, reason="JSON query"),
        CommandRule(prefix=("python",), decision=ALLOW, reason="analysis runtime",
                    match=("python sweep.py",), not_match=("rm -rf /",)),
        CommandRule(prefix=("python3",), decision=ALLOW, reason="analysis runtime"),
        CommandRule(prefix=("py",), decision=ALLOW, reason="analysis runtime"),
        CommandRule(prefix=("node",), decision=ALLOW, reason="analysis runtime",
                    match=("node target_scanner.js",)),
        CommandRule(prefix=("rg",), decision=ALLOW, reason="search",
                    match=("rg --files",)),
        CommandRule(prefix=("git",), decision=ALLOW, reason="version control",
                    match=("git status", "git log --oneline -20")),
        CommandRule(prefix=("xcore.exe",), decision=ALLOW, reason="the engine itself",
                    match=("xcore.exe native --so x",)),
        CommandRule(prefix=("ollama",), decision=ALLOW, reason="local models"),
        CommandRule(prefix=("capstone",), decision=ALLOW, reason="disassembly"),
        # PowerShell itself, and the two shells an agent reaches for.
        #
        # This is a real bypass surface and it is allowed with eyes open. The
        # policy only inspects the outer command line, so `python -c
        # "os.system(...)"` was already a hole before this line existed; the
        # rule table is a **guardrail against accidents, not a security
        # boundary**. Its job is to stop an agent from typing `rm -rf` or
        # reading an SSH key by mistake, and to make the consequential things
        # ask first. Anyone who needs a real boundary needs OS enforcement
        # (Windows restricted token + Job Object), which is a separate item.
        CommandRule(prefix=("powershell",), decision=ALLOW, reason="shell",
                    match=("powershell Get-ChildItem",)),
        CommandRule(prefix=("pwsh",), decision=ALLOW, reason="shell"),
        CommandRule(prefix=("cmd",), decision=ALLOW, reason="shell",
                    match=("cmd /c dir",)),
    ]

    # Read-only PowerShell cmdlets. An agent that reaches for PowerShell to list
    # or hash files should not be refused. Built with extend() because a list
    # literal cannot mix items with a comprehension.
    command_rules.extend(
        CommandRule(prefix=(cmdlet,), decision=ALLOW,
                    reason="read-only PowerShell cmdlet")
        for cmdlet in ("Get-ChildItem", "Get-Content", "Get-FileHash",
                       "Get-Item", "Get-ItemProperty", "Select-String",
                       "Measure-Object", "Test-Path", "Get-Command",
                       "Compare-Object", "Get-Member", "Resolve-Path",
                       "ConvertFrom-Json", "ConvertTo-Json", "Format-List",
                       "Format-Table", "Where-Object", "ForEach-Object",
                       "Sort-Object", "Select-Object"))

    pol = Policy(writable_roots=writable, path_rules=path_rules,
                 command_rules=command_rules, unrestricted=unrestricted)

    # Merge the user's own rules last so they win ties at equal specificity.
    user = load_user_policy()
    if user:
        for decision, names in (("allow", user.get("allow")),
                                ("prompt", user.get("prompt")),
                                ("deny", user.get("deny"))):
            for name in (names or []):
                pol.command_rules.append(CommandRule(
                    prefix=(str(name),), decision=decision,
                    reason="rules/policy.json"))
        for root in (user.get("writable_roots") or []):
            pol.writable_roots.append(Path(root))
        if user.get("unrestricted") is True:
            pol.unrestricted = True
    return pol


USER_POLICY = BASE_DIR / "rules" / "policy.json"

# Starter file written when absent, so the knob is discoverable rather than
# something you have to read the source to find.
_USER_POLICY_TEMPLATE = {
    "_comment": ("放宽或收紧 sh.run 的命令策略。改这里不用改代码。"
                 "allow/prompt/deny 三张表按命令名（可执行文件名，不含路径）匹配；"
                 "deny 永远优先，prompt 需要人工批准（当前无批准通道 = 拒绝）。"
                 "writable_roots 用来给工作台之外再加可写目录。"),
    "_examples": {
        "allow": ["pip", "ollama"],
        "prompt": ["sc"],
        "deny": ["mklink"],
        "writable_roots": ["E:/hexin/work"],
    },
    "allow": [],
    "prompt": [],
    "deny": [],
    "writable_roots": [],
}


def load_user_policy() -> dict:
    """Read rules/policy.json. Never raises: a broken policy file must not stop
    the kernel from starting, but it must be visible when it is broken."""
    import json
    if not USER_POLICY.exists():
        try:
            USER_POLICY.parent.mkdir(parents=True, exist_ok=True)
            USER_POLICY.write_text(
                json.dumps(_USER_POLICY_TEMPLATE, ensure_ascii=False, indent=2),
                encoding="utf-8")
        except OSError:
            pass
        return {}
    try:
        data = json.loads(USER_POLICY.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError) as exc:
        print(f"[policy] rules/policy.json unreadable ({exc}); using defaults",
              flush=True)
        return {}
