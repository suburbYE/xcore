"""
Result shaping: truncation and status lines for tool output.

Two rules, both taken from what the mature harnesses converged on:

**Keep the head and the tail; elide the middle** (Codex `HeadTailBuffer` +
`TruncationPolicy`, DSH `ToolResultPruner` at 8192/4096/1024). For the output of
an experiment the head carries the setup and the tail carries the verdict and
the totals — a truncation that keeps only the head throws away exactly the part
the agent needs, which is what xcore's previous `payload[:MAX]` did.

**Say what was removed, with the original size.** A bare "…" leaves the model
unable to tell a short result from a clipped one. Every truncation carries the
original character and line counts, so a number read off a clipped result can be
recognised as clipped.

The cut is measured in characters but reported in both characters and lines,
because a 9649-line failure list is naturally described by its line count.

A third rule, from the same sources: **truncation happens once, where output
enters the transcript**, not inside each producer. Callers shape their own
output for humans; `shape()` is the single place that decides what the model
sees.
"""

from __future__ import annotations

from dataclasses import dataclass

# Defaults chosen to match DSH's pruner so behaviour is comparable.
DEFAULT_MAX_CHARS = 8192
DEFAULT_HEAD_CHARS = 4096
DEFAULT_TAIL_CHARS = 1024


@dataclass(frozen=True)
class Shaped:
    """The model-facing form of some text, plus what was done to it."""

    text: str
    truncated: bool
    original_chars: int
    original_lines: int
    kept_head: int = 0
    kept_tail: int = 0

    @property
    def removed_chars(self) -> int:
        return self.original_chars - len(self.text) if self.truncated else 0

    def to_dict(self) -> dict:
        return {
            "truncated": self.truncated,
            "original_chars": self.original_chars,
            "original_lines": self.original_lines,
            "kept_head": self.kept_head,
            "kept_tail": self.kept_tail,
            "removed_chars": self.removed_chars,
        }


def shape(text: str, *, max_chars: int = DEFAULT_MAX_CHARS,
          head_chars: int = DEFAULT_HEAD_CHARS,
          tail_chars: int = DEFAULT_TAIL_CHARS) -> Shaped:
    """Clip `text` to a character budget, keeping both ends.

    The marker is self-describing: it names how many characters and lines were
    dropped and what the original size was, so a reader can tell a clipped
    result from a complete one without guessing.
    """
    if max_chars <= 0:
        raise ValueError("max_chars must be positive")
    original_chars = len(text)
    original_lines = text.count("\n") + 1 if text else 0
    if original_chars <= max_chars:
        return Shaped(text, False, original_chars, original_lines)

    # Marker is charged against the budget so the result never exceeds it.
    marker = _marker(original_chars, original_lines)
    budget = max_chars - len(marker)
    if budget <= 0:
        # Budget smaller than the marker: emit the marker alone rather than a
        # silently unmarked clip.
        return Shaped(marker, True, original_chars, original_lines)

    # Allocate head and tail. The defaults (4096/1024) only fit a budget of
    # 5120+, so a caller passing a smaller max_chars used to give the whole
    # budget to the head and leave the tail with zero — losing exactly the
    # verdict-and-totals end that this function exists to preserve. Under
    # pressure the requested ratio is scaled down instead of the tail being
    # dropped; when there is slack it all goes to the tail, because the
    # conclusion lives there.
    want = head_chars + tail_chars
    if budget < want:
        scale = budget / want
        head = max(1, int(head_chars * scale))
        tail = max(0, budget - head)
    else:
        head = min(head_chars, budget)
        tail = budget - head   # slack to the tail
    tail = min(tail, max(0, budget - head))

    kept = text[:head] + marker + (text[len(text) - tail:] if tail else "")
    return Shaped(kept, True, original_chars, original_lines,
                  kept_head=head, kept_tail=tail)


def _marker(original_chars: int, original_lines: int) -> str:
    return (f"\n\n[... {original_lines} lines / {original_chars} chars total; "
            f"middle elided ...]\n\n")


def status_line(*, ok: bool, detail: str = "", extra: dict | None = None) -> str:
    """One bracketed line describing how a tool call ended.

    Every tool result in the substrate ends with one. Without it a model that
    receives a clipped or empty result cannot tell "finished, nothing to say"
    from "still running" or "died halfway" — the failure mode DSH closes by
    appending `[status: ...]` to every job read.
    """
    parts = [f"ok={str(ok).lower()}"]
    if detail:
        parts.append(detail)
    for key, value in (extra or {}).items():
        parts.append(f"{key}={value}")
    return "[status: " + ", ".join(parts) + "]"


def with_status(text: str, *, ok: bool, detail: str = "",
                extra: dict | None = None) -> str:
    """Append a status line, keeping at most one trailing newline."""
    body = text.rstrip("\n")
    line = status_line(ok=ok, detail=detail, extra=extra)
    return f"{body}\n{line}" if body else line
