from __future__ import annotations

from typing import Any


def score_scan(checks: list[dict[str, Any]]) -> dict[str, Any]:
    """Combine triggered 0-100 weights into a 1-10 score and verdict."""
    raw_score = sum(
        max(0, int(item.get("weight", 0)))
        for item in checks
        if item.get("triggered")
    )
    score = round(min(10.0, max(1.0, raw_score / 10)), 1)
    verdict = "Phishing" if score >= 6 else "Suspicious" if score > 3 else "Safe"
    return {"risk_score": score, "max_score": 10, "verdict": verdict}
