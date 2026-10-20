"""Train and evaluate a character-level CNN for DGA detection.

The CNN consumes the registrable domain as a character sequence. The input
format is shared with train.py, including the headerless label,family,domain
dataset format.
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path
from typing import Any

import numpy as np

from .features import registrable_domain
from .train import load_rows

VOCAB = "abcdefghijklmnopqrstuvwxyz0123456789_.-"
PAD = 0
UNK = 1
CHAR_TO_ID = {char: index + 2 for index, char in enumerate(VOCAB)}


def encode_domains(domains: list[str], max_length: int) -> np.ndarray:
    encoded = np.zeros((len(domains), max_length), dtype=np.int64)
    for row, domain in enumerate(domains):
        value = registrable_domain(domain)[:max_length]
        encoded[row, : len(value)] = [CHAR_TO_ID.get(char, UNK) for char in value]
    return encoded


def _torch():
    try:
        import torch
        from torch import nn
    except ImportError as error:
        raise RuntimeError("CNN training requires PyTorch") from error
    return torch, nn


def build_model(torch: Any, nn: Any, vocabulary_size: int) -> Any:
    class CharacterCNN(nn.Module):
        def __init__(self) -> None:
            super().__init__()
            self.embedding = nn.Embedding(vocabulary_size, 32, padding_idx=PAD)
            self.convolutions = nn.ModuleList(
                [nn.Conv1d(32, 64, kernel_size=size, padding=size // 2) for size in (3, 5, 7)]
            )
            self.dropout = nn.Dropout(0.25)
            self.output = nn.Linear(64 * 3, 1)

        def forward(self, inputs: Any) -> Any:
            embedded = self.embedding(inputs).transpose(1, 2)
            pooled = [nn.functional.adaptive_max_pool1d(nn.functional.relu(conv(embedded)), 1).squeeze(-1)
                      for conv in self.convolutions]
            return self.output(self.dropout(nn.functional.relu(torch.cat(pooled, dim=1)))).squeeze(1)

    return CharacterCNN()


def _metrics(labels: np.ndarray, probabilities: np.ndarray) -> dict[str, Any]:
    from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score

    predictions = (probabilities >= 0.5).astype(np.int64)
    return {
        "roc_auc": float(roc_auc_score(labels, probabilities)),
        "confusion_matrix": confusion_matrix(labels, predictions).tolist(),
        "classification_report": classification_report(
            labels, predictions, output_dict=True, zero_division=0
        ),
    }


def evaluate(model: Any, torch: Any, inputs: np.ndarray, labels: np.ndarray, batch_size: int) -> dict[str, Any]:
    model.eval()
    probabilities: list[np.ndarray] = []
    with torch.no_grad():
        for start in range(0, len(inputs), batch_size):
            batch = torch.from_numpy(inputs[start : start + batch_size])
            probabilities.append(torch.sigmoid(model(batch)).cpu().numpy())
    return _metrics(labels, np.concatenate(probabilities))


def train(
    train_rows: list[dict[str, str]],
    test_rows: list[dict[str, str]],
    output: Path,
    epochs: int,
    batch_size: int,
    max_length: int,
    seed: int,
) -> dict[str, Any]:
    torch, nn = _torch()
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    train_inputs = encode_domains([row["domain"] for row in train_rows], max_length)
    test_inputs = encode_domains([row["domain"] for row in test_rows], max_length)
    train_labels = np.array([int(row["label"]) for row in train_rows], dtype=np.float32)
    test_labels = np.array([int(row["label"]) for row in test_rows], dtype=np.int64)
    model = build_model(torch, nn, len(VOCAB) + 2)
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
    loss_fn = nn.BCEWithLogitsLoss()
    order = np.arange(len(train_inputs))
    for epoch in range(epochs):
        np.random.shuffle(order)
        model.train()
        total_loss = 0.0
        for start in range(0, len(order), batch_size):
            indices = order[start : start + batch_size]
            batch = torch.from_numpy(train_inputs[indices])
            targets = torch.from_numpy(train_labels[indices])
            optimizer.zero_grad()
            loss = loss_fn(model(batch), targets)
            loss.backward()
            optimizer.step()
            total_loss += float(loss.item()) * len(indices)
        print(json.dumps({"epoch": epoch + 1, "loss": total_loss / len(order)}), flush=True)
    metrics = evaluate(model, torch, test_inputs, test_labels, batch_size)
    output.parent.mkdir(parents=True, exist_ok=True)
    torch.save(
        {
            "state_dict": model.state_dict(),
            "vocab": VOCAB,
            "max_length": max_length,
            "features": "registrable_domain_characters",
            "metrics": metrics,
        },
        output,
    )
    return {
        "algorithm": "character_cnn",
        "train_samples": len(train_rows),
        "test_samples": len(test_rows),
        "epochs": epochs,
        "batch_size": batch_size,
        "max_length": max_length,
        **metrics,
        "model": str(output),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("train_dataset", type=Path)
    parser.add_argument("test_dataset", type=Path)
    parser.add_argument("--output", type=Path, default=Path("models/dga_char_cnn.pt"))
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--batch-size", type=int, default=2048)
    parser.add_argument("--max-length", type=int, default=128)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    result = train(
        load_rows(args.train_dataset),
        load_rows(args.test_dataset),
        args.output,
        args.epochs,
        args.batch_size,
        args.max_length,
        args.seed,
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
