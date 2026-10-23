from __future__ import annotations

import argparse
import copy
import random
from pathlib import Path
from typing import Any

from app.ml_model import (
    MAX_URL_BYTES,
    MODEL_FORMAT_VERSION,
    _build_network,
    encode_url,
    read_labeled_csv,
    split_rows_by_host,
)


def _batch(rows: list[tuple[str, int]], max_bytes: int, torch: Any) -> tuple[Any, Any]:
    tokens = [encode_url(url, max_bytes) for url, _ in rows]
    tokens = [item + [0] * (max_bytes - len(item)) for item in tokens]
    labels = [label for _, label in rows]
    return torch.tensor(tokens, dtype=torch.long), torch.tensor(labels, dtype=torch.float32)


def train(
    csv_path: str | Path,
    output_path: str | Path,
    *,
    epochs: int = 10,
    batch_size: int = 64,
    max_bytes: int = MAX_URL_BYTES,
    validation_fraction: float = 0.2,
    seed: int = 42,
) -> dict[str, float]:
    try:
        import torch
    except ImportError as exc:
        raise RuntimeError("Install the optional ML dependencies with: python -m pip install -r requirements-ml.txt") from exc

    if epochs < 1 or batch_size < 1:
        raise ValueError("epochs and batch_size must be positive.")
    if max_bytes < 32 or max_bytes > 4096:
        raise ValueError("max_bytes must be between 32 and 4096.")
    if not 0 < validation_fraction < 0.5:
        raise ValueError("validation_fraction must be greater than 0 and less than 0.5.")

    torch.manual_seed(seed)
    rows = read_labeled_csv(csv_path)
    train_rows, validation_rows = split_rows_by_host(rows, validation_fraction, seed)
    model = _build_network(torch, max_bytes)
    optimizer = torch.optim.AdamW(model.parameters(), lr=0.001)
    counts = {label: sum(1 for _, target in train_rows if target == label) for label in (0, 1)}
    positive_weight = torch.tensor([counts[0] / counts[1]], dtype=torch.float32)
    loss_function = torch.nn.BCEWithLogitsLoss(pos_weight=positive_weight)

    best_validation_loss = float("inf")
    best_state_dict: dict[str, Any] | None = None
    for epoch in range(epochs):
        model.train()
        random.Random(seed + epoch).shuffle(train_rows)
        total_loss = 0.0
        for start in range(0, len(train_rows), batch_size):
            batch_rows = train_rows[start:start + batch_size]
            inputs, labels = _batch(batch_rows, max_bytes, torch)
            optimizer.zero_grad()
            loss = loss_function(model(inputs), labels)
            loss.backward()
            optimizer.step()
            total_loss += loss.item() * len(batch_rows)
        model.eval()
        validation_loss = 0.0
        with torch.inference_mode():
            for start in range(0, len(validation_rows), batch_size):
                batch_rows = validation_rows[start:start + batch_size]
                inputs, labels = _batch(batch_rows, max_bytes, torch)
                validation_loss += loss_function(model(inputs), labels).item() * len(batch_rows)
        validation_loss /= len(validation_rows)
        if validation_loss < best_validation_loss:
            best_validation_loss = validation_loss
            best_state_dict = copy.deepcopy(model.state_dict())
        print(
            f"epoch {epoch + 1}/{epochs} "
            f"loss={total_loss / len(train_rows):.4f} validation_loss={validation_loss:.4f}"
        )

    if best_state_dict is None:
        raise RuntimeError("Training completed without a usable validation checkpoint.")
    model.load_state_dict(best_state_dict)
    model.eval()
    true_positive = false_positive = false_negative = correct = total = 0
    with torch.inference_mode():
        for start in range(0, len(validation_rows), batch_size):
            batch_rows = validation_rows[start:start + batch_size]
            inputs, labels = _batch(batch_rows, max_bytes, torch)
            predictions = torch.sigmoid(model(inputs)) >= 0.5
            expected = labels >= 0.5
            correct += int((predictions == expected).sum().item())
            true_positive += int((predictions & expected).sum().item())
            false_positive += int((predictions & ~expected).sum().item())
            false_negative += int((~predictions & expected).sum().item())
            total += len(batch_rows)
    accuracy = correct / total
    precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 0.0
    recall = true_positive / (true_positive + false_negative) if true_positive + false_negative else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    torch.save({
        "format_version": MODEL_FORMAT_VERSION,
        "max_bytes": max_bytes,
        "state_dict": model.state_dict(),
        "training": {
            "examples": len(rows),
            "train_examples": len(train_rows),
            "validation_examples": len(validation_rows),
            "validation_accuracy": accuracy,
            "validation_precision": precision,
            "validation_recall": recall,
            "validation_f1": f1,
            "seed": seed,
        },
    }, destination)
    metrics = {
        "validation_accuracy": accuracy,
        "validation_precision": precision,
        "validation_recall": recall,
        "validation_f1": f1,
        "validation_examples": float(total),
    }
    print(f"saved model: {destination}")
    print(
        f"host-separated validation: accuracy={accuracy:.1%} precision={precision:.1%} "
        f"recall={recall:.1%} f1={f1:.1%} ({total} examples)"
    )
    return metrics


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the PhishLens URL CNN from a labeled CSV.")
    parser.add_argument("csv", help="CSV with url,label columns; label is 0/1 or safe/phishing")
    parser.add_argument("--output", default="models/url_cnn.pt", help="Model artifact output path")
    parser.add_argument("--epochs", type=int, default=10)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--max-bytes", type=int, default=MAX_URL_BYTES)
    parser.add_argument("--validation-fraction", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    train(
        args.csv, args.output, epochs=args.epochs, batch_size=args.batch_size,
        max_bytes=args.max_bytes, validation_fraction=args.validation_fraction, seed=args.seed,
    )


if __name__ == "__main__":
    main()
