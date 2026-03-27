"""Formatting utilities for console and JSON output."""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .utils import Finding, ScanSummary, Severity

SEVERITY_COLOR = {"low": "green", "medium": "yellow", "high": "red"}


def to_json(summary: ScanSummary, score: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "score": score,
        "files": [
            {
                "path": str(f.path),
                "findings": [finding_to_json(x) for x in f.findings],
                "semantic": f.semantic.raw if f.semantic else None,
            }
            for f in summary.files
        ],
        "findings": [finding_to_json(f) for f in summary.static_findings],
    }


def finding_to_json(finding: Finding) -> Dict[str, Any]:
    return {
        "type": finding.type,
        "severity": finding.severity,
        "message": finding.message,
        "evidence": finding.evidence,
        "path": str(finding.path) if finding.path else None,
        "line": finding.line,
    }


def render_console(console: Console, summary: ScanSummary, score: Dict[str, Any], verbose: bool = False) -> None:
    title_text = Text(f"Risk: {score['level'].upper()} ({score['score']}/100)", style=SEVERITY_COLOR[score["level"]])
    console.print(Panel(title_text, title="skillguard", expand=False))

    grouped: Dict[Severity, List[Finding]] = defaultdict(list)
    for finding in summary.static_findings:
        grouped[finding.severity].append(finding)

    for severity in ("high", "medium", "low"):
        items = grouped.get(severity, [])
        if not items:
            continue
        table = Table(title=f"{severity.title()} Findings ({len(items)})", title_style=SEVERITY_COLOR[severity])
        table.add_column("Type", style="bold")
        table.add_column("Message")
        table.add_column("Path")
        if verbose:
            table.add_column("Evidence")
        for item in items:
            path_display = f"{item.path}" + (f":{item.line}" if item.line else "") if item.path else "-"
            row = [item.type, item.message, path_display]
            if verbose:
                row.append(item.evidence)
            table.add_row(*row)
        console.print(table)

    recommendations = _recommendations(grouped)
    if recommendations:
        console.print(Panel("\n".join(f"- {r}" for r in recommendations), title="Recommendations", border_style="cyan"))

    console.print(f"Files scanned: {len(summary.files)} | Findings: {len(summary.static_findings)}")


def _recommendations(grouped: Dict[Severity, List[Finding]]) -> List[str]:
    recs: List[str] = []
    if grouped.get("high"):
        recs.append("Remove or sandbox commands that fetch and execute remote code.")
        recs.append("Eliminate prompt-injection phrasing and enforce system prompts.")
    if grouped.get("medium"):
        recs.append("Review external URLs and restrict outbound access.")
        recs.append("Clarify instructions to avoid hidden behaviors.")
    if not recs:
        recs.append("No critical risks detected. Keep dependencies pinned and review updates.")
    return recs


__all__ = ["render_console", "to_json"]
