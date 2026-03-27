"""Semantic analysis leveraging OpenAI API, with graceful degradation."""
from __future__ import annotations

import json
import os
import time
from typing import Optional

import httpx

from .utils import SemanticReport

OPENAI_URL = "https://api.openai.com/v1/chat/completions"
DEFAULT_MODEL = os.getenv("SKILLGUARD_MODEL", "gpt-4.1")


class SemanticAnalyzerError(Exception):
    """Raised when semantic analysis cannot be completed."""


def _fallback(message: str) -> SemanticReport:
    return SemanticReport(
        summary=message,
        risks=[],
        attack_vectors=[],
        confidence=0.0,
        raw={"error": message},
    )


def analyze_semantic(text: str, timeout: float = 20.0, retries: int = 2) -> SemanticReport:
    """Perform semantic analysis via OpenAI Chat Completions.

    Falls back gracefully when the API key is missing or network errors occur.
    """

    if os.getenv("SKILLGUARD_DISABLE_SEMANTIC"):
        return _fallback("Semantic analysis disabled by SKILLGUARD_DISABLE_SEMANTIC")

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return _fallback("Semantic analysis skipped: OPENAI_API_KEY is not set")

    payload = {
        "model": DEFAULT_MODEL,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a security auditor for AI agent skills. "
                    "Return ONLY valid JSON with keys summary, risks, attack_vectors, confidence."
                ),
            },
            {
                "role": "user",
                "content": (
                    "Analyze the following skill content for security risks. "
                    "Respond strictly in JSON. Content:\n" + text
                ),
            },
        ],
        "temperature": 0,
        "response_format": {"type": "json_object"},
    }

    last_error: Optional[str] = None
    for attempt in range(retries + 1):
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.post(
                    OPENAI_URL,
                    headers={"Authorization": f"Bearer {api_key}"},
                    json=payload,
                )
            response.raise_for_status()
            data = response.json()
            content = data["choices"][0]["message"]["content"]
            parsed = json.loads(content)
            return SemanticReport(
                summary=str(parsed.get("summary", "")),
                risks=[str(r) for r in parsed.get("risks", [])],
                attack_vectors=[str(a) for a in parsed.get("attack_vectors", [])],
                confidence=float(parsed.get("confidence", 0)),
                raw=parsed,
            )
        except Exception as exc:  # pragma: no cover - network/backoff
            last_error = str(exc)
            time.sleep(min(2 ** attempt, 5))

    return _fallback(f"Semantic analysis failed: {last_error}")


__all__ = ["analyze_semantic", "SemanticAnalyzerError"]
