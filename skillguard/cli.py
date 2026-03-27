"""Command line interface for skillguard."""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from .scanner import scan
from .scorer import score_scan
from .formatter import render_console, to_json
from .utils import ScanSummary, most_severe, severity_at_least, Severity

app = typer.Typer(add_completion=False, help="Scan AI agent skills for security risks.")


@app.command()
def scan_command(
    path: Path = typer.Argument(Path("."), help="File or directory to scan"),
    json_output: bool = typer.Option(False, "--json", "--raw", help="Return machine-readable JSON"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show evidence for each finding"),
    fail_on: Optional[Severity] = typer.Option(None, "--fail-on", help="Fail if severity at or above level."),
    no_semantic: bool = typer.Option(False, "--no-semantic", help="Disable semantic analysis (API-free)"),
) -> None:
    """Scan markdown-based skills for prompt injection and unsafe commands."""

    _configure_logging()
    console = Console()
    summary = scan(path, semantic=not no_semantic)
    score = score_scan(summary)

    if json_output:
        typer.echo(json.dumps(to_json(summary, score), indent=2))
    else:
        render_console(console, summary, score, verbose=verbose)

    exit_code = _exit_code(summary, fail_on)
    raise typer.Exit(code=exit_code)


def _exit_code(summary: ScanSummary, fail_on: Optional[Severity]) -> int:
    if not summary.static_findings:
        return 0
    highest = most_severe(summary.static_findings)
    if fail_on and highest and severity_at_least(highest, fail_on):
        return 2
    return 1


def _configure_logging() -> None:
    level_name = os.getenv("SKILLGUARD_LOG_LEVEL", "WARNING").upper()
    level = getattr(logging, level_name, logging.WARNING)
    logging.basicConfig(level=level, format="%(asctime)s [%(levelname)s] %(message)s")


def main() -> None:  # pragma: no cover - Typer entry point
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
