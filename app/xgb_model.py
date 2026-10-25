from __future__ import annotations

import logging
import os
import threading
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from app.ml_model import read_labeled_csv, split_rows_by_host, url_host_group

FEATURE_VERSION = 2
FEATURE_NAMES = (
    "Have_IP",
    "Have_At",
    "URL_Length",
    "URL_Depth",
    "Redirection",
    "https_Domain",
    "TinyURL",
    "Prefix/Suffix",
    "Has_Punycode",
    "Suspicious_TLD",
    "Sensitive_Keywords",
    "Query_Count",
    "Digit_Count",
    "Percent_Encoding",
)
SHORTENERS = {
    "bit.ly", "goo.gl", "shorte.st", "go2l.ink", "x.co", "ow.ly", "t.co", "tinyurl.com",
    "tr.im", "is.gd", "cli.gs", "tiny.cc", "url4.eu", "twit.ac", "su.pr", "snipurl.com",
    "short.to", "post.ly", "snipr.com", "fic.kr", "loopt.us", "short.ie", "kl.am", "wp.me",
    "to.ly", "bit.do", "lnkd.in", "cur.lv", "q.gs", "po.st", "bc.vc", "u.to", "j.mp",
    "cutt.us", "v.gd", "1url.com",
}
SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "click", "country", "gq", "tk", "work", "support"}
SENSITIVE_KEYWORDS = {"login", "verify", "secure", "update", "account", "password", "signin", "wallet"}
logger = logging.getLogger(__name__)
_model_cache: tuple[str, int, Any] | None = None
_model_lock = threading.Lock()


def extract_url_features(url: str) -> list[float]:
    """Extract the ordered URL-only feature vector used by the PhishLens XGBoost model."""
    candidate = url.strip()
    if "://" not in candidate:
        candidate = "https://" + candidate
    parts = urlsplit(candidate)
    host = (parts.hostname or "").lower().rstrip(".")
    labels = host.split(".") if host else []
    try:
        import ipaddress

        has_ip = int(ipaddress.ip_address(host) is not None)
    except ValueError:
        has_ip = 0
    url_lower = candidate.lower()
    shortener = any(host == service or host.endswith("." + service) for service in SHORTENERS)
    redirect_position = candidate.rfind("//")
    return [
        float(has_ip),
        float("@" in candidate),
        float(len(candidate) >= 54),
        float(sum(bool(segment) for segment in parts.path.split("/"))),
        float(redirect_position > 7),
        float("https" in parts.netloc.lower()),
        float(shortener),
        float("-" in parts.netloc),
        float("xn--" in host),
        float(bool(labels and labels[-1] in SUSPICIOUS_TLDS)),
        float(sum(keyword in url_lower for keyword in SENSITIVE_KEYWORDS)),
        float(len([item for item in parts.query.split("&") if item])),
        float(sum(char.isdigit() for char in candidate)),
        float("%" in candidate),
    ]


def _domain_split(
    rows: list[tuple[str, int]],
    validation_fraction: float,
    seed: int,
) -> tuple[list[tuple[str, int]], list[tuple[str, int]]]:
    return split_rows_by_host(rows, validation_fraction, seed)


def _load_xgboost_model(model_path: Path) -> Any:
    global _model_cache
    from xgboost import XGBClassifier

    resolved_path = str(model_path.resolve())
    modified_ns = model_path.stat().st_mtime_ns
    with _model_lock:
        if _model_cache and _model_cache[:2] == (resolved_path, modified_ns):
            return _model_cache[2]
        model = XGBClassifier()
        model.load_model(resolved_path)
        attributes = model.get_booster().attributes()
        if attributes.get("phishlens_feature_version") != str(FEATURE_VERSION):
            raise ValueError("Unsupported or invalid PhishLens XGBoost model artifact.")
        if attributes.get("phishlens_feature_names") != ",".join(FEATURE_NAMES):
            raise ValueError("The XGBoost model feature schema does not match this PhishLens version.")
        _model_cache = (resolved_path, modified_ns, model)
        return model


def classify_url_xgboost(
    url: str,
    *,
    model_path: str | Path | None = None,
    threshold: float | None = None,
) -> dict[str, Any]:
    """Classify URL structure with an optional trained XGBoost model."""
    path = Path(model_path or os.getenv("PHISHLENS_XGBOOST_MODEL_PATH", "models/url_xgboost.json"))
    if not path.is_absolute():
        path = Path(__file__).resolve().parent.parent / path
    if not path.is_file():
        return {"status": "not_trained", "prediction": None, "phishing_probability": None, "confidence": None}
    try:
        cutoff = float(threshold if threshold is not None else os.getenv("XGBOOST_PHISHING_THRESHOLD", "0.8"))
    except ValueError as exc:
        raise ValueError("XGBOOST_PHISHING_THRESHOLD must be a number between 0.5 and 1.") from exc
    if not 0.5 <= cutoff <= 1:
        raise ValueError("XGBOOST_PHISHING_THRESHOLD must be between 0.5 and 1.")
    try:
        from xgboost.core import XGBoostError

        model = _load_xgboost_model(path)
        probability = float(model.predict_proba([extract_url_features(url)])[0][1])
        return {
            "status": "ready",
            "prediction": "phishing" if probability >= cutoff else "benign",
            "phishing_probability": round(probability, 4),
            "confidence": round(max(probability, 1 - probability), 4),
            "threshold": cutoff,
        }
    except ImportError:
        logger.warning("An XGBoost phishing model exists, but XGBoost is not installed.")
        return {"status": "dependency_missing", "prediction": None, "phishing_probability": None, "confidence": None}
    except (OSError, RuntimeError, ValueError, KeyError, TypeError, IndexError, XGBoostError) as exc:
        logger.exception("Could not load or run the XGBoost model at %s", path)
        return {
            "status": "error",
            "prediction": None,
            "phishing_probability": None,
            "confidence": None,
            "error": str(exc),
        }


def train_xgboost_model(
    csv_path: str | Path,
    output_path: str | Path,
    *,
    validation_fraction: float = 0.2,
    seed: int = 42,
) -> dict[str, float]:
    """Train XGBoost from URL,label rows and validate on hosts excluded from training."""
    try:
        from xgboost import XGBClassifier
    except ImportError as exc:
        raise RuntimeError("Install the optional ML dependencies with: python -m pip install -r requirements-ml.txt") from exc

    if not 0 < validation_fraction < 0.5:
        raise ValueError("validation_fraction must be greater than 0 and less than 0.5.")

    rows = read_labeled_csv(csv_path)
    train_rows, validation_rows = _domain_split(rows, validation_fraction, seed)
    class_counts = {label: sum(target == label for _, target in train_rows) for label in (0, 1)}
    model = XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.9,
        colsample_bytree=0.9,
        reg_lambda=1.0,
        scale_pos_weight=class_counts[0] / class_counts[1],
        objective="binary:logistic",
        eval_metric="logloss",
        random_state=seed,
        n_jobs=1,
    )
    model.fit(
        [extract_url_features(url) for url, _ in train_rows],
        [label for _, label in train_rows],
    )
    predictions = model.predict([extract_url_features(url) for url, _ in validation_rows])
    labels = [label for _, label in validation_rows]
    true_positive = sum(prediction == 1 and label == 1 for prediction, label in zip(predictions, labels))
    false_positive = sum(prediction == 1 and label == 0 for prediction, label in zip(predictions, labels))
    false_negative = sum(prediction == 0 and label == 1 for prediction, label in zip(predictions, labels))
    accuracy = sum(prediction == label for prediction, label in zip(predictions, labels)) / len(labels)
    precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 0.0
    recall = true_positive / (true_positive + false_negative) if true_positive + false_negative else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    model.get_booster().set_attr(
        phishlens_feature_version=str(FEATURE_VERSION),
        phishlens_feature_names=",".join(FEATURE_NAMES),
    )
    destination = Path(output_path)
    if not destination.is_absolute():
        destination = Path(__file__).resolve().parent.parent / destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    model.save_model(str(destination))
    metrics = {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "train_examples": float(len(train_rows)),
        "validation_examples": float(len(validation_rows)),
        "validation_hosts": float(len({url_host_group(url) for url, _ in validation_rows})),
    }
    print(
        f"saved model: {destination}\n"
        f"host-separated validation: accuracy={accuracy:.3f} precision={precision:.3f} "
        f"recall={recall:.3f} f1={f1:.3f} ({len(validation_rows)} URLs)"
    )
    return metrics


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Train the PhishLens XGBoost URL classifier from a labeled CSV.")
    parser.add_argument("csv", help="CSV with url,label columns; label is 0/1 or safe/phishing")
    parser.add_argument("--output", default="models/url_xgboost.json", help="XGBoost JSON model output path")
    parser.add_argument("--validation-fraction", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    train_xgboost_model(
        args.csv,
        args.output,
        validation_fraction=args.validation_fraction,
        seed=args.seed,
    )


if __name__ == "__main__":
    main()
