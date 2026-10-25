from __future__ import annotations

import csv
import logging
import os
import random
import threading
from collections import defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

MODEL_FORMAT_VERSION = 1
MAX_URL_BYTES = 512
logger = logging.getLogger(__name__)
_model_cache: tuple[str, int, Any, Any] | None = None
_model_lock = threading.Lock()


def read_labeled_csv(path: str | Path) -> list[tuple[str, int]]:
    """Read URL,label rows, accepting common safe/phishing label spellings."""
    rows: list[tuple[str, int]] = []
    with Path(path).open(newline="", encoding="utf-8-sig") as source:
        reader = csv.DictReader(source)
        if not reader.fieldnames or not {"url", "label"}.issubset(
            {field.strip().lower() for field in reader.fieldnames}
        ):
            raise ValueError("Training CSV must have 'url' and 'label' columns.")
        for line_number, row in enumerate(reader, start=2):
            normalized = {(key or "").strip().lower(): (value or "").strip() for key, value in row.items()}
            url = normalized.get("url", "")
            label_text = normalized.get("label", "").lower()
            if not url:
                raise ValueError(f"Training CSV row {line_number} has an empty URL.")
            if label_text in {"1", "phishing", "phish", "malicious"}:
                label = 1
            elif label_text in {"0", "safe", "benign", "legitimate", "legit"}:
                label = 0
            else:
                raise ValueError(
                    f"Training CSV row {line_number} has unsupported label {label_text!r}; "
                    "use 0/1 or safe/phishing."
                )
            rows.append((url, label))
    if not rows:
        raise ValueError("Training CSV contains no examples.")
    if {label for _, label in rows} != {0, 1}:
        raise ValueError("Training CSV must contain both safe (0) and phishing (1) examples.")
    return rows


def url_host_group(url: str) -> str:
    candidate = url.strip()
    if "://" not in candidate:
        candidate = "https://" + candidate
    host = (urlsplit(candidate).hostname or "").lower().rstrip(".")
    return host.removeprefix("www.") or candidate


def split_rows_by_host(
    rows: list[tuple[str, int]],
    validation_fraction: float = 0.2,
    seed: int = 42,
) -> tuple[list[tuple[str, int]], list[tuple[str, int]]]:
    """Split labeled URLs so a host cannot appear in both training and validation."""
    if not 0 < validation_fraction < 0.5:
        raise ValueError("validation_fraction must be greater than 0 and less than 0.5.")

    groups: dict[str, list[tuple[str, int]]] = defaultdict(list)
    for row in rows:
        groups[url_host_group(row[0])].append(row)
    hosts = list(groups)
    if len(hosts) < 4:
        raise ValueError("Provide at least four distinct URL hosts for a host-separated validation split.")

    validation_count = min(max(2, round(len(hosts) * validation_fraction)), len(hosts) - 2)
    rng = random.Random(seed)
    for _ in range(200):
        validation_hosts = set(rng.sample(hosts, validation_count))
        train_rows = [row for host, items in groups.items() if host not in validation_hosts for row in items]
        validation_rows = [row for host in validation_hosts for row in groups[host]]
        if {label for _, label in train_rows} == {0, 1} and {label for _, label in validation_rows} == {0, 1}:
            return train_rows, validation_rows
    raise ValueError(
        "Could not create a host-separated validation split containing both classes. "
        "Provide more distinct hosts for safe and phishing URLs."
    )


def encode_url(url: str, max_bytes: int = MAX_URL_BYTES) -> list[int]:
    """Encode a URL as UTF-8 byte IDs, reserving zero for padding."""
    if max_bytes < 1:
        raise ValueError("max_bytes must be positive.")
    return [byte + 1 for byte in url.encode("utf-8")[:max_bytes]]


def _build_network(torch: Any, max_bytes: int) -> Any:
    nn = torch.nn

    class URLClassifier(nn.Module):
        def __init__(self) -> None:
            super().__init__()
            self.embedding = nn.Embedding(257, 32, padding_idx=0)
            self.convolutions = nn.ModuleList(
                nn.Conv1d(32, 64, kernel_size=width, padding=width // 2)
                for width in (3, 5, 7)
            )
            self.classifier = nn.Sequential(
                nn.Linear(192, 64),
                nn.ReLU(),
                nn.Dropout(0.25),
                nn.Linear(64, 1),
            )
            self.max_bytes = max_bytes

        def forward(self, tokens: Any) -> Any:
            embedded = self.embedding(tokens).transpose(1, 2)
            pooled = [
                torch.amax(torch.relu(convolution(embedded)), dim=2)
                for convolution in self.convolutions
            ]
            return self.classifier(torch.cat(pooled, dim=1)).squeeze(1)

    return URLClassifier()


def _load_model(model_path: Path) -> tuple[Any, Any]:
    global _model_cache
    import torch

    resolved_path = str(model_path.resolve())
    modified_ns = model_path.stat().st_mtime_ns
    with _model_lock:
        if _model_cache and _model_cache[:2] == (resolved_path, modified_ns):
            return _model_cache[2], _model_cache[3]
        artifact = torch.load(model_path, map_location="cpu", weights_only=True)
        if not isinstance(artifact, dict) or artifact.get("format_version") != MODEL_FORMAT_VERSION:
            raise ValueError("Unsupported or invalid phishing model artifact.")
        max_bytes = int(artifact.get("max_bytes", MAX_URL_BYTES))
        if not 32 <= max_bytes <= 4096:
            raise ValueError("The phishing model has an invalid URL length setting.")
        model = _build_network(torch, max_bytes)
        model.load_state_dict(artifact["state_dict"], strict=True)
        model.eval()
        _model_cache = (resolved_path, modified_ns, model, torch)
        return model, torch


def classify_url(
    url: str,
    *,
    model_path: str | Path | None = None,
    threshold: float | None = None,
) -> dict[str, Any]:
    """Classify URL bytes using an optional trained local model."""
    path = Path(model_path or os.getenv("PHISHLENS_MODEL_PATH", "models/url_cnn.pt"))
    if not path.is_absolute():
        path = Path(__file__).resolve().parent.parent / path
    if not path.is_file():
        return {"status": "not_trained", "prediction": None, "phishing_probability": None, "confidence": None}
    try:
        cutoff = float(threshold if threshold is not None else os.getenv("ML_PHISHING_THRESHOLD", "0.8"))
    except ValueError as exc:
        raise ValueError("ML_PHISHING_THRESHOLD must be a number between 0.5 and 1.") from exc
    if not 0.5 <= cutoff <= 1:
        raise ValueError("ML_PHISHING_THRESHOLD must be between 0.5 and 1.")
    try:
        model, torch = _load_model(path)
        tokens = encode_url(url, model.max_bytes)
        tokens.extend([0] * (model.max_bytes - len(tokens)))
        with torch.inference_mode():
            probability = float(torch.sigmoid(model(torch.tensor([tokens], dtype=torch.long))).item())
        return {
            "status": "ready",
            "prediction": "phishing" if probability >= cutoff else "benign",
            "phishing_probability": round(probability, 4),
            "confidence": round(max(probability, 1 - probability), 4),
            "threshold": cutoff,
        }
    except ImportError:
        logger.warning("A trained phishing model exists, but PyTorch is not installed.")
        return {"status": "dependency_missing", "prediction": None, "phishing_probability": None, "confidence": None}
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as exc:
        logger.exception("Could not load or run the phishing model at %s", path)
        return {
            "status": "error",
            "prediction": None,
            "phishing_probability": None,
            "confidence": None,
            "error": str(exc),
        }
