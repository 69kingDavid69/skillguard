"""Scanner that traverses targets and aggregates findings."""
from __future__ import annotations

from pathlib import Path

from . import analyzer
from .rules import analyze_text
from .utils import FileReport, ScanSummary, iter_markdown_targets, read_text


def scan(target: str | Path, semantic: bool = True) -> ScanSummary:
    """Scan a path or file for security issues.

    Args:
        target: File or directory to scan.
        semantic: Whether to run semantic analysis (OpenAI).
    """

    path = Path(target).resolve()
    if not path.exists():
        raise FileNotFoundError(f"Path not found: {path}")

    files: list[FileReport] = []
    static_findings = []
    semantic_summaries = []

    for markdown in iter_markdown_targets(path):
        content = read_text(markdown)
        findings = analyze_text(content, markdown)
        static_findings.extend(findings)

        semantic_report = analyzer.analyze_semantic(content) if semantic else None
        if semantic_report:
            semantic_summaries.append(semantic_report)

        files.append(
            FileReport(
                path=markdown,
                findings=findings,
                semantic=semantic_report,
            )
        )

    return ScanSummary(
        files=files,
        static_findings=static_findings,
        semantic_summaries=semantic_summaries,
    )


__all__ = ["scan"]
