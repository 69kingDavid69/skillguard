from pathlib import Path

from skillguard.scorer import score_scan
from skillguard.utils import FileReport, Finding, ScanSummary


def test_high_severity_escalates_score() -> None:
    finding = Finding(
        type="prompt_injection",
        severity="high",
        message="",
        evidence="ignore previous instructions",
        path=Path("skill.md"),
        line=1,
    )
    summary = ScanSummary(
        files=[FileReport(path=Path("skill.md"), findings=[finding], semantic=None)],
        static_findings=[finding],
        semantic_summaries=[],
    )
    score = score_scan(summary)
    assert score["score"] >= 70
    assert score["level"] == "high"
