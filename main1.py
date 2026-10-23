def calculate_verdict(flags: list[tuple[str, float]]) -> dict:
    """Calculate a risk score and verdict from scan flags."""
    score = min(sum(points for _, points in flags), 10)
    verdict = "Suspicious" if score > 3 else "Safe"

    return {
        "score": round(score, 1),
        "max_score": 10,
        "verdict": verdict,
        "reasons": [reason for reason, _ in flags],
    }


if __name__ == "__main__":
    flags = [
        ("Domain is only 12 days old", 2),
        ("Brand name 'paypal' in subdomain", 2),
        ("Password field posts to another domain", 2),
    ]
    print(calculate_verdict(flags))