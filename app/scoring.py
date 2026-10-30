from __future__ import annotations

from typing import Any


def score_scan(checks: list[dict[str, Any]]) -> dict[str, Any]:
    """Combine triggered weights into a 0-5 risk score with consistent risk bands."""
    raw_score = sum(
        max(0, int(item.get("weight", 0)))
        for item in checks
        if item.get("triggered")
    )
    score = round(min(5.0, max(0.0, raw_score / 20.0)), 1)
    if score <= 1.4:
        verdict = "Low Risk"
    elif score <= 3.4:
        verdict = "Medium Risk"
    else:
        verdict = "High Risk"
    return {"risk_score": score, "max_score": 5, "verdict": verdict}
