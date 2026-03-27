"""Static rule-based analysis for SkillGuard."""
from __future__ import annotations

import re
from pathlib import Path
from typing import List, Pattern

from .utils import Finding, Severity

PROMPT_INJECTION_PATTERNS: List[Pattern[str]] = [
    re.compile(r"ignore (?:all |any )?(previous|prior) (instructions|rules)", re.IGNORECASE),
    re.compile(r"disregard.*system prompt", re.IGNORECASE),
    re.compile(r"override .*safety", re.IGNORECASE),
    re.compile(r"you are now.*developer", re.IGNORECASE),
    re.compile(r"bypass.*policy", re.IGNORECASE),
    re.compile(r"act as (an )?unfiltered", re.IGNORECASE),
]

HIDDEN_INSTRUCTION_PATTERNS: List[Pattern[str]] = [
    re.compile(r"<!--.*?-->", re.DOTALL),
    re.compile(r"\[comment\]: #", re.IGNORECASE),
    re.compile(r"\bsecret instructions\b", re.IGNORECASE),
]

DANGEROUS_COMMANDS: List[str] = [
    "curl",
    "wget",
    "bash",
    "sh -c",
    "eval",
    "nc ",
    "powershell",
    "Invoke-WebRequest",
    "scp",
    "sftp",
    "python -c",
    "node -e",
    "rm -rf",
]

EXECUTION_CHAIN = re.compile(r"(curl|wget)[^\n]*\|[^\n]*(bash|sh)", re.IGNORECASE)
EXTERNAL_URL = re.compile(r"https?://[\w\-._~:/?#\[\]@!$&'()*+,;=%]+", re.IGNORECASE)


def analyze_text(text: str, path: Path | None = None) -> List[Finding]:
    """Run static rules against text and return findings."""

    findings: List[Finding] = []

    lines = text.splitlines()
    for idx, line in enumerate(lines, start=1):
        for pattern in PROMPT_INJECTION_PATTERNS:
            if pattern.search(line):
                findings.append(
                    Finding(
                        type="prompt_injection",
                        severity="high",
                        message="Possible prompt injection or instruction override",
                        evidence=line.strip(),
                        path=path,
                        line=idx,
                    )
                )
        for pattern in HIDDEN_INSTRUCTION_PATTERNS:
            if pattern.search(line):
                findings.append(
                    Finding(
                        type="hidden_instruction",
                        severity="medium",
                        message="Hidden or obfuscated instruction",
                        evidence=line.strip(),
                        path=path,
                        line=idx,
                    )
                )
        for cmd in DANGEROUS_COMMANDS:
            if cmd.lower() in line.lower():
                sev: Severity = "high" if cmd.strip() in {"curl", "wget", "bash", "sh -c", "eval", "powershell", "rm -rf"} else "medium"
                findings.append(
                    Finding(
                        type="command_execution",
                        severity=sev,
                        message=f"Dangerous command reference: {cmd.strip()}",
                        evidence=line.strip(),
                        path=path,
                        line=idx,
                    )
                )
        if EXECUTION_CHAIN.search(line):
            findings.append(
                Finding(
                    type="execution_chain",
                    severity="high",
                    message="Remote fetch piped to shell detected",
                    evidence=line.strip(),
                    path=path,
                    line=idx,
                )
            )

    for match in EXTERNAL_URL.finditer(text):
        url = match.group(0)
        sev: Severity = "high" if any(k in url for k in ["ngrok", "pastebin", "gist", "ipfs"]) else "medium"
        findings.append(
            Finding(
                type="external_url",
                severity=sev,
                message="External network reference detected",
                evidence=url,
                path=path,
                line=None,
            )
        )

    return findings


__all__ = ["analyze_text"]
