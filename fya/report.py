from __future__ import annotations

import html
import json
from typing import Optional

from . import __version__
from .models import ScanResult, Severity

_SEV_COLOR = {
    "critical": "bold white on red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}

_SEV_HEX = {
    "critical": "#ff4d4d",
    "high": "#ff784e",
    "medium": "#f5b301",
    "low": "#4db8ff",
    "info": "#8a94a6",
}

_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def render_console(result: ScanResult, console=None) -> None:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    if console is None:
        console = Console()
    counts = result.counts()
    summary = "  ".join(
        f"[{_SEV_COLOR[s.value]}]{counts[s.value]} {s.value}[/]"
        for s in reversed(list(Severity))
        if counts[s.value]
    ) or "[green]no findings[/]"

    console.print(
        Panel(
            f"target: [bold]{result.target.label()}[/]\n"
            f"kind: {result.target.kind.value}    profile: {result.profile.value}    "
            f"duration: {result.duration_seconds():.1f}s\n"
            f"findings: {summary}",
            title="fya scan report",
            border_style="grey37",
        )
    )

    if result.findings:
        table = Table(show_lines=False, border_style="grey30", header_style="bold")
        table.add_column("sev", no_wrap=True)
        table.add_column("title")
        table.add_column("category", style="grey62")
        table.add_column("location", style="grey62", overflow="fold")
        for f in result.sorted_findings():
            table.add_row(
                f"[{_SEV_COLOR[f.severity.value]}]{f.severity.value}[/]",
                f.title,
                f.category or "",
                f.location or "",
            )
        console.print(table)

    if result.errors:
        console.print(f"[grey50]{len(result.errors)} check error(s); see JSON report for detail[/]")


def to_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2, default=str)


def to_sarif(result: ScanResult) -> str:
    rules = {}
    sarif_results = []
    for f in result.sorted_findings():
        if f.check not in rules:
            rules[f.check] = {
                "id": f.check,
                "name": f.check,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description},
                "help": {"text": f.remediation or f.description},
                "helpUri": (f.references[0] if f.references else "https://github.com/ayam04/fya"),
                "properties": {"category": f.category, "cwe": f.cwe},
            }
        sarif_results.append(
            {
                "ruleId": f.check,
                "level": _SARIF_LEVEL[f.severity.value],
                "message": {"text": f"{f.title}: {f.description}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.location or result.target.label()}
                        }
                    }
                ],
                "properties": {
                    "severity": f.severity.value,
                    "confidence": f.confidence.value,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                },
                "partialFingerprints": {"fya/v1": f.key()},
            }
        )
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "fya",
                        "informationUri": "https://github.com/ayam04/fya",
                        "version": __version__,
                        "rules": list(rules.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }
    return json.dumps(doc, indent=2)


def to_markdown(result: ScanResult) -> str:
    counts = result.counts()
    lines = [
        f"# fya scan report: {result.target.label()}",
        "",
        f"- kind: `{result.target.kind.value}`",
        f"- profile: `{result.profile.value}`",
        f"- duration: {result.duration_seconds():.1f}s",
        "- findings: "
        + ", ".join(f"{counts[s.value]} {s.value}" for s in reversed(list(Severity)) if counts[s.value])
        or "- findings: none",
        "",
        "## Findings",
        "",
    ]
    if not result.findings:
        lines.append("No findings.")
    for f in result.sorted_findings():
        lines += [
            f"### [{f.severity.value.upper()}] {f.title}",
            "",
            f"- category: {f.category}" + (f" | CWE: {f.cwe}" if f.cwe else ""),
            f"- confidence: {f.confidence.value}",
            f"- location: `{f.location}`" if f.location else "",
            "",
            f.description,
            "",
            f"**Remediation:** {f.remediation}" if f.remediation else "",
            "",
            "```",
            (f.evidence or "").strip()[:2000],
            "```",
            "",
        ]
    return "\n".join(line for line in lines if line is not None)


def to_html(result: ScanResult) -> str:
    counts = result.counts()
    chips = "".join(
        f'<span class="chip" style="border-color:{_SEV_HEX[s.value]};color:{_SEV_HEX[s.value]}">'
        f"{counts[s.value]} {s.value}</span>"
        for s in reversed(list(Severity))
        if counts[s.value]
    ) or '<span class="chip ok">no findings</span>'

    cards = []
    for f in result.sorted_findings():
        refs = "".join(
            f'<a href="{html.escape(r)}" target="_blank" rel="noopener">{html.escape(r)}</a>'
            for r in f.references
        )
        cards.append(
            f"""
      <article class="card">
        <header>
          <span class="badge" style="background:{_SEV_HEX[f.severity.value]}">{f.severity.value}</span>
          <h3>{html.escape(f.title)}</h3>
        </header>
        <div class="meta">{html.escape(f.category)}{(' | CWE ' + html.escape(f.cwe)) if f.cwe else ''}
          | confidence {f.confidence.value}{(' | ' + html.escape(f.location)) if f.location else ''}</div>
        <p>{html.escape(f.description)}</p>
        {f'<div class="rem"><b>Fix.</b> {html.escape(f.remediation)}</div>' if f.remediation else ''}
        {f'<pre>{html.escape((f.evidence or "").strip()[:4000])}</pre>' if f.evidence else ''}
        {f'<div class="refs">{refs}</div>' if refs else ''}
      </article>"""
        )

    body_cards = "\n".join(cards) or "<p>No findings.</p>"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>fya report: {html.escape(result.target.label())}</title>
<style>
:root{{color-scheme:dark}}
*{{box-sizing:border-box}}
body{{margin:0;background:#0d1017;color:#c9d1d9;font:15px/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}}
.wrap{{max-width:960px;margin:0 auto;padding:32px 20px}}
h1{{font-size:20px;margin:0 0 4px}}
.sub{{color:#8a94a6;font-size:13px;margin-bottom:16px}}
.chips{{display:flex;flex-wrap:wrap;gap:8px;margin:16px 0 28px}}
.chip{{border:1px solid #30363d;border-radius:999px;padding:4px 12px;font-size:13px}}
.chip.ok{{color:#3fb950;border-color:#238636}}
.card{{border:1px solid #21262d;border-radius:10px;padding:16px 18px;margin:0 0 14px;background:#11151d}}
.card header{{display:flex;align-items:center;gap:10px}}
.card h3{{font-size:15px;margin:0}}
.badge{{color:#0d1017;font-weight:700;font-size:11px;text-transform:uppercase;padding:2px 8px;border-radius:5px}}
.meta{{color:#8a94a6;font-size:12px;margin:8px 0}}
.rem{{background:#0f2417;border:1px solid #1f6f3f;border-radius:6px;padding:8px 12px;margin:10px 0;font-size:13px}}
pre{{background:#0a0d13;border:1px solid #21262d;border-radius:6px;padding:12px;overflow-x:auto;font-size:12.5px;color:#9fb0c3}}
.refs{{margin-top:10px;display:flex;flex-direction:column;gap:2px}}
.refs a{{color:#58a6ff;font-size:12px;text-decoration:none;word-break:break-all}}
footer{{color:#565f6b;font-size:12px;margin-top:24px;border-top:1px solid #21262d;padding-top:12px}}
</style></head><body><div class="wrap">
<h1>fya scan report</h1>
<div class="sub">{html.escape(result.target.label())} | kind {result.target.kind.value} |
profile {result.profile.value} | {result.duration_seconds():.1f}s |
{len(result.checks_run)} checks</div>
<div class="chips">{chips}</div>
{body_cards}
<footer>Generated by fya. Test only what you own or are authorized to test.</footer>
</div></body></html>"""


_FORMATTERS = {
    "json": to_json,
    "sarif": to_sarif,
    "md": to_markdown,
    "markdown": to_markdown,
    "html": to_html,
}


def render(result: ScanResult, fmt: str) -> str:
    formatter = _FORMATTERS.get(fmt)
    if not formatter:
        raise ValueError(f"unknown format: {fmt}")
    return formatter(result)


def write_report(result: ScanResult, fmt: str, path: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(render(result, fmt))


def exit_code(result: ScanResult, threshold: Optional[str]) -> int:
    if not threshold:
        return 0
    from .models import severity_rank

    limit = Severity(threshold)
    for f in result.findings:
        if severity_rank(f.severity) >= severity_rank(limit):
            return 2
    return 0
