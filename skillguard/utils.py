"""Utility helpers for SkillGuard."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional
import logging

Severity = Literal["low", "medium", "high"]

# Order for comparing severities
SEVERITY_WEIGHTS: Dict[Severity, int] = {"low": 1, "medium": 2, "high": 3}

logger = logging.getLogger("skillguard")


@dataclass
class Finding:
    """Structured static finding."""

    type: str
    severity: Severity
    message: str
    evidence: str
    path: Optional[Path] = None
    line: Optional[int] = None


@dataclass
class SemanticReport:
    """Result from semantic analyzer."""

    summary: str
    risks: List[str]
    attack_vectors: List[str]
    confidence: float
    raw: Dict[str, Any]


@dataclass
class FileReport:
    """Aggregated report for a single file."""

    path: Path
    findings: List[Finding]
    semantic: Optional[SemanticReport]


@dataclass
class ScanSummary:
    """Overall scan result."""

    files: List[FileReport]
    static_findings: List[Finding]
    semantic_summaries: List[SemanticReport]


def iter_markdown_targets(target: Path) -> List[Path]:
    """Return markdown targets (SKILL.md or *.md) inside the target.

    If a file is provided, return it when it looks like markdown.
    If a directory is provided, walk recursively.
    """

    if target.is_file():
        if target.suffix.lower() == ".md" or target.name.upper() == "SKILL.MD":
            return [target]
        return []

    files: List[Path] = []
    for path in target.rglob("*.md"):
        files.append(path)
    # Ensure SKILL.md even if extension case differs
    for path in target.rglob("SKILL.md"):
        if path not in files:
            files.append(path)
    return sorted(set(files))


def read_text(path: Path) -> str:
    """Read text with safe defaults."""

    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("Failed to read %s: %s", path, exc)
        return ""


def most_severe(findings: List[Finding]) -> Optional[Severity]:
    if not findings:
        return None
    return max((f.severity for f in findings), key=lambda s: SEVERITY_WEIGHTS[s])


def severity_at_least(level: Severity, threshold: Severity) -> bool:
    return SEVERITY_WEIGHTS[level] >= SEVERITY_WEIGHTS[threshold]


def risk_level_from_score(score: float) -> Severity:
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


__all__ = [
    "Finding",
    "SemanticReport",
    "FileReport",
    "ScanSummary",
    "iter_markdown_targets",
    "read_text",
    "most_severe",
    "severity_at_least",
    "SEVERITY_WEIGHTS",
    "risk_level_from_score",
    "Severity",
]
