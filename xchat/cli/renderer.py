"""
Phase 5c: Rich terminal renderer for scan results.

Renders structured, high-contrast terminal reports from xcore scan
output using the ``rich`` library.
"""

from __future__ import annotations

import os
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

console = Console()

# ─── Color helpers ────────────────────────────────────────────────────────────


def _score_color(score: float, text: str = "") -> Text:
    """Return a Rich ``Text`` styled according to score threshold."""
    if score >= 0.7:
        return Text(text or f"{score:.2f}", style="bold green")
    if score >= 0.4:
        return Text(text or f"{score:.2f}", style="yellow")
    return Text(text or f"{score:.2f}", style="dim")


def _verdict_color(verdict: str) -> Text:
    """Return a Rich ``Text`` styled by verdict string."""
    v = verdict.lower()
    if v in ("hit", "annotate"):
        return Text(verdict, style="bold red")
    if v == "flag":
        return Text(verdict, style="bold yellow")
    if v == "note":
        return Text(verdict, style="cyan")
    return Text(verdict, style="dim white")


# ─── Layer detail helpers ─────────────────────────────────────────────────────


def _layer_detail(layer_data: dict[str, Any]) -> str:
    """Build a human-readable detail string for a scanning layer."""
    if not layer_data:
        return "无"

    parts: list[str] = []

    # L1: string hits
    hits = layer_data.get("hits", [])
    if hits and isinstance(hits, list) and hits:
        if all(isinstance(h, str) for h in hits):
            count = f" ({len(hits)} matches)"
            shown = hits[:5]
            if len(hits) > 5:
                shown.append(f"... +{len(hits) - 5}")
            parts.append(f"{' / '.join(str(h) for h in shown)}{count}")
        else:
            parts.append(f"{len(hits)} hits")

    # L2: constant families
    families = layer_data.get("families", [])
    if families:
        parts.append(f"families: {', '.join(str(f) for f in families[:5])}")

    # L4: fingerprint names
    fp_hits = layer_data.get("hits", [])
    if fp_hits and isinstance(fp_hits, list) and fp_hits and not isinstance(fp_hits[0], str):
        fp_names = []
        for h in fp_hits:
            if isinstance(h, dict):
                name = h.get("fingerprint") or h.get("name") or "?"
                fp_names.append(name)
        if fp_names:
            shown = fp_names[:3]
            if len(fp_names) > 3:
                shown.append(f"... +{len(fp_names) - 3}")
            parts.append(f"{', '.join(shown)}")

    # L5: pattern names
    details = layer_data.get("details", [])
    if details and isinstance(details, list) and details:
        if isinstance(details[0], dict):
            pattern_entries = []
            for d in details[:4]:
                name = d.get("name", "?")
                count = d.get("count", "")
                pattern_entries.append(f"{name}({count})" if count else name)
            parts.append(f"{', '.join(pattern_entries)}")

    return ", ".join(parts) if parts else "无"


# ─── Public render functions ──────────────────────────────────────────────────


def render_error(msg: str) -> None:
    """Render an error message in a red panel."""
    console.print()
    console.print(Panel(
        Text(msg, style="bold red"),
        title="Error",
        border_style="red",
    ))
    console.print()


def render_progress(msg: str) -> None:
    """Render a progress / status message."""
    console.print(f"  [dim]{msg}[/dim]")


def render_shell_classify(data: dict[str, Any]) -> None:
    """Render a shell classification result as a styled panel.

    Expected keys: ``shell`` (name/confidence/evidence),
    ``recommendation``, ``next_step``, ``package_name``.
    """
    console.print()

    shell_info = data.get("shell", {}) or {}
    name = shell_info.get("name", "unknown")
    confidence = shell_info.get("confidence", "N/A")
    rec = data.get("recommendation", "unknown")
    next_step = data.get("next_step", "")
    package = data.get("package_name", "")

    # Determine shell class display
    shell_class = rec
    if rec in ("heavy_shell", "strong_shell"):
        shell_class_text = Text(rec, style="bold red")
        suggestion = "frida_dump"
    elif rec in ("light_shell", "weak_shell"):
        shell_class_text = Text(rec, style="yellow")
        suggestion = "static_analysis"
    else:
        shell_class_text = Text(rec, style="cyan")
        suggestion = next_step or "proceed"

    # Confidence styling
    conf_upper = str(confidence).upper()
    if conf_upper in ("HIGH", "CRITICAL"):
        conf_text = Text(confidence, style="bold green")
    elif conf_upper == "MEDIUM":
        conf_text = Text(confidence, style="yellow")
    else:
        conf_text = Text(confidence, style="dim")

    body_lines: list[Text] = []
    body_lines.append(Text.assemble(("名称: ", "bold"), (str(name), "")))
    body_lines.append(Text.assemble(("类型: ", "bold"), shell_class_text))
    body_lines.append(Text.assemble(("置信度: ", "bold"), conf_text))
    body_lines.append(Text.assemble(("建议: ", "bold"), (suggestion, "cyan")))
    if package:
        body_lines.append(Text.assemble(("包名: ", "bold"), (package, "")))

    # Concatenate with newlines
    body = Text("\n").join(body_lines)

    console.print(Panel(
        body,
        title="[bold]壳分类结果[/bold]",
        border_style="bright_blue",
    ))
    console.print()


def _render_layers_table(layers: dict[str, Any], final_score: float,
                         verdict: str, algorithm: str) -> None:
    """Render the 7-layer confidence table for an individual SO scan."""
    table = Table(
        title="[bold]多层靶心扫描明细[/bold]",
        border_style="bright_blue",
        padding=(0, 1),
    )
    table.add_column("层级", style="bold", width=6)
    table.add_column("权重", justify="right", width=7)
    table.add_column("命中", width=18)
    table.add_column("详情", min_width=30)

    # Layer definitions: (key, label, weight)
    layer_defs = [
        ("L1_strings",      "L1", 0.10),
        ("L2_constants",    "L2", 0.15),
        ("L3_symbols",      "L3", 0.15),
        ("L4_fingerprints", "L4", 0.25),
        ("L5_cfp",          "L5", 0.25),
        (None,              "L6", 0.20),
    ]

    for key, label, weight in layer_defs:
        if key is None:
            # L6: CFG topology — always "未评估"
            table.add_row(
                label,
                f"{weight:.2f}",
                "—",
                Text("未评估", style="dim"),
            )
            continue

        layer = layers.get(key, {}) or {}
        score = layer.get("score", 0)
        has_hits = bool(layer.get("hits") or layer.get("families"))

        hit_str = _layer_hit_summary(key, layer)
        detail = _layer_detail(layer)

        table.add_row(
            label,
            f"{weight:.2f}",
            hit_str if has_hits else Text("无", style="dim"),
            detail,
        )

    # Footer row
    score_text = _score_color(final_score)
    verdict_text = _verdict_color(verdict)
    table.add_section()
    table.add_row(
        Text("最终得分", style="bold"),
        _score_color(final_score),
        Text.assemble(("判定: ", "bold"), verdict_text),
        Text.assemble(("算法: ", "bold"), (algorithm, "cyan")),
    )

    console.print(table)
    console.print()


def _layer_hit_summary(layer_key: str, layer: dict[str, Any]) -> str:
    """Build a short hit summary string for a layer column."""
    if layer_key == "L1_strings":
        hits = layer.get("hits", [])
        if hits and isinstance(hits, list) and hits:
            if all(isinstance(h, str) for h in hits):
                return f"字符串匹配 ({len(hits)} matches)"
        return "无"
    elif layer_key == "L2_constants":
        families = layer.get("families", [])
        if families:
            return f"常量指纹 ({len(families)} families)"
        hits = layer.get("hits", [])
        if hits:
            return f"常量 ({len(hits)} hits)"
        return "无"
    elif layer_key == "L3_symbols":
        hits = layer.get("hits", [])
        if hits:
            return f"符号检测 ({len(hits)} imports)"
        return "无"
    elif layer_key == "L4_fingerprints":
        hits = layer.get("hits", [])
        if hits:
            return f"算法指纹 ({len(hits)} matches)"
        return "无"
    elif layer_key == "L5_cfp":
        details = layer.get("details", [])
        if details:
            return f"位运算模式 ({len(details)} patterns)"
        return "无"
    return "无"


def _render_so_targets_table(so_targets: list[dict[str, Any]]) -> None:
    """Render the SO targets summary table from pipeline output.

    Filter: only show rows with score > 0.05.  If all rows are <= 0.05,
    show the first 10 with a note.
    """
    if not so_targets:
        console.print("  [dim]No SO targets found.[/dim]")
        return

    # Filter
    visible = [t for t in so_targets if t.get("score", 0) > 0.05]
    filter_note = ""
    if not visible:
        visible = so_targets[:10]
        if len(so_targets) > 10:
            filter_note = f" (仅显示前 10 / 共 {len(so_targets)} 行)"
        else:
            filter_note = " (所有行 score <= 0.05)"
    else:
        hidden = len(so_targets) - len(visible)
        if hidden > 0:
            filter_note = f" (已过滤 {hidden} 行 score <= 0.05)"

    table = Table(
        title=f"[bold]SO 靶心扫描汇总[/bold]{filter_note}",
        border_style="bright_blue",
        padding=(0, 1),
    )
    table.add_column("SO 文件", style="bold", min_width=25)
    table.add_column("得分", justify="right", width=8)
    table.add_column("判定", width=10)
    table.add_column("算法", min_width=14)

    # Stats
    total = len(so_targets)
    hit_count = sum(1 for t in so_targets if t.get("verdict", "").lower() in ("hit", "annotate", "flag"))
    probe_count = sum(1 for t in so_targets if t.get("score", 0) >= 0.4)

    for t in visible:
        name = t.get("name", "?")
        score = t.get("score", 0)
        verdict = t.get("verdict", "?")
        algorithm = t.get("algorithm", "?")

        table.add_row(
            name,
            _score_color(score),
            _verdict_color(verdict),
            Text(algorithm, style="cyan"),
        )

    # Summary footer
    table.add_section()
    table.add_row(
        Text(f"总计: {total} 个 SO", style="bold"),
        Text(f"命中: {hit_count}", style="bold red" if hit_count > 0 else ""),
        Text(f"探针: {probe_count}", style="bold green" if probe_count > 0 else ""),
        "",
    )

    console.print(table)
    console.print()


def _render_probe_code(probe_path: str) -> None:
    """Render a Frida probe script with JavaScript syntax highlighting."""
    if not os.path.isfile(probe_path):
        console.print(f"  [red]Probe file not found: {probe_path}[/red]")
        return

    try:
        with open(probe_path, "r", encoding="utf-8") as f:
            code = f.read()
    except Exception as e:
        console.print(f"  [red]Failed to read probe: {e}[/red]")
        return

    lines = code.split("\n")
    total_lines = len(lines)
    truncated = total_lines > 50

    display_code = "\n".join(lines[:50]) if truncated else code

    syntax = Syntax(
        display_code,
        "javascript",
        theme="monokai",
        line_numbers=True,
        word_wrap=True,
    )

    title = "Frida 探针脚本"
    if truncated:
        title += f" (截断，共 {total_lines} 行，完整代码见文件)"
    subtitle = Text(f"路径: {probe_path}", style="dim")

    console.print()
    console.print(Panel(
        Text.assemble(subtitle, "\n\n", syntax),
        title=f"[bold]{title}[/bold]",
        border_style="green",
    ))
    console.print()


def _render_individual_scan(scan_result: dict[str, Any]) -> None:
    """Render a single SO/DLL scan result (from run_native_scan)."""
    target = scan_result.get("target", "?")
    arch = scan_result.get("arch", "?")
    final_score = scan_result.get("final_score", 0)
    verdict = scan_result.get("verdict", "clean")
    algorithm = scan_result.get("algorithm", "unknown")
    layers = scan_result.get("layers", {})

    console.print()
    console.print(Panel(
        Text.assemble(
            ("目标: ", "bold"), (target, "bold cyan"), "\n",
            ("架构: ", "bold"), (arch, ""), "\n",
            ("得分: ", "bold"), _score_color(final_score), "\n",
            ("判定: ", "bold"), _verdict_color(verdict), "\n",
            ("算法: ", "bold"), (algorithm, "cyan"),
        ),
        title="[bold]Native Scan Result[/bold]",
        border_style="bright_blue",
    ))

    if layers:
        _render_layers_table(layers, final_score, verdict, algorithm)


def render_scan_result(data: dict[str, Any], title: str = "") -> None:
    """Render scan or pipeline results.

    Handles both ``run_apk_pipeline`` and ``run_native_scan`` output
    formats automatically.

    Args:
        data: The result dict from ``CommandResult.data``.
        title: Optional override title.
    """
    results_list = data.get("results", []) if isinstance(data, dict) else []

    if not results_list:
        console.print("  [dim]No results to render.[/dim]")
        return

    # Render warnings first
    warnings = data.get("warnings", []) if isinstance(data, dict) else []
    for w in warnings:
        console.print(f"  [yellow][!] {w}[/yellow]")

    for result in results_list:
        rtype = result.get("type", "")

        # ── APK pipeline ───────────────────────────────────────────────
        if rtype == "apk":
            shell = result.get("shell", {})
            if shell:
                render_shell_classify(shell)

            pipeline = result.get("pipeline", {})
            if pipeline:
                # Shell banner within pipeline context
                p_shell = pipeline.get("shell", {})
                if p_shell:
                    console.print()
                    console.print(Panel(
                        Text.assemble(
                            ("名称: ", "bold"), (str(p_shell.get("name", "?")), ""),
                            ("  类型: ", "bold"), (str(p_shell.get("class", "?")), ""),
                            ("  置信度: ", "bold"), (str(p_shell.get("confidence", "?")), ""),
                        ),
                        title="[bold]APK 壳信息[/bold]",
                        border_style="bright_blue",
                    ))

                # SO targets summary
                so_targets = pipeline.get("so_targets", [])
                if so_targets:
                    _render_so_targets_table(so_targets)

                # Probes
                probes = pipeline.get("probes", [])
                if probes:
                    console.print(f"  [bold]生成探针: {len(probes)} 个[/bold]")
                    for p in probes:
                        probe_path = p.get("probePath") or p.get("probe_path") or ""
                        if probe_path:
                            console.print(f"    - [cyan]{probe_path}[/cyan]")

        # ── Native scan (individual SO/DLL) ────────────────────────────
        elif rtype == "native":
            scan = result.get("scan", {})
            if scan:
                _render_individual_scan(scan)

        # ── Probe generation result ────────────────────────────────────
        elif rtype == "probe":
            probe_path = result.get("probe_path", "")
            if probe_path:
                _render_probe_code(probe_path)
            else:
                console.print("  [yellow]Probe path is empty.[/yellow]")

        else:
            console.print(f"  [dim]Unknown result type: {rtype}[/dim]")
