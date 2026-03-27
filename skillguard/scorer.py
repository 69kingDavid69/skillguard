"""Risk scoring for SkillGuard."""
from __future__ import annotations

from .utils import ScanSummary, risk_level_from_score

STATIC_BASE = {"low": 5, "medium": 10, "high": 20}


def score_scan(summary: ScanSummary) -> dict:
    score = 0.0

    for finding in summary.static_findings:
        base = STATIC_BASE[finding.severity]
        bonus = 10 if finding.type in {"prompt_injection", "command_execution", "execution_chain"} else 0
        score += base + bonus

    for semantic in summary.semantic_summaries:
        score += len(semantic.risks) * 8
        score += len(semantic.attack_vectors) * 5
        score += semantic.confidence * 5

    if any(f.severity == "high" for f in summary.static_findings):
        score = max(score, 70.0)

    score = min(score, 100.0)
    level = risk_level_from_score(score)
    return {"score": round(score, 2), "level": level}


__all__ = ["score_scan"]
