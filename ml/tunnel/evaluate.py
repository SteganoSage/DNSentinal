"""Capture-aware Isolation Forest evaluation with a frozen validation threshold."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Iterable

from analyzer.detectors.tunnel import extract_features
from ml.tunnel.train import _session_windows


def _vectors(paths: Iterable[Path], size: int) -> tuple[list[list[float]], list[int], list[str]]:
    vectors: list[list[float]] = []
    labels: list[int] = []
    sessions: list[str] = []
    for path, label in paths:
        windows = _session_windows([path], size)
        vectors.extend(extract_features(window).vector() for window in windows)
        labels.extend([label] * len(windows))
        sessions.extend([path.name] * len(windows))
    return vectors, labels, sessions


def _scores(model: object, vectors: list[list[float]]) -> list[float]:
    return (-model.score_samples(vectors)).tolist()  # type: ignore[attr-defined]


def _thresholds(scores: list[float]) -> list[float]:
    values = sorted(set(scores))
    if len(values) < 2:
        return values or [0.5]
    return [(left + right) / 2 for left, right in zip(values, values[1:])]


def _window_metrics(labels: list[int], scores: list[float], threshold: float) -> dict[str, object]:
    from sklearn.metrics import (
        average_precision_score,
        confusion_matrix,
        f1_score,
        precision_score,
        recall_score,
        roc_auc_score,
    )

    predictions = [int(score >= threshold) for score in scores]
    negatives = sum(label == 0 for label in labels)
    false_positives = sum(prediction and not label for prediction, label in zip(predictions, labels))
    result: dict[str, object] = {
        "threshold": threshold,
        "precision": precision_score(labels, predictions, zero_division=0),
        "recall": recall_score(labels, predictions, zero_division=0),
        "f1": f1_score(labels, predictions, zero_division=0),
        "pr_auc": average_precision_score(labels, scores),
        "roc_auc": roc_auc_score(labels, scores),
        "confusion_matrix": confusion_matrix(labels, predictions).tolist(),
        "false_positive_rate": false_positives / negatives if negatives else None,
        "windows": len(labels),
    }
    return result


def _capture_metrics(
    labels: list[int], predictions: list[int], sessions: list[str]
) -> dict[str, object]:
    grouped: dict[str, list[int]] = {}
    grouped_labels: dict[str, int] = {}
    for label, prediction, session in zip(labels, predictions, sessions):
        grouped.setdefault(session, []).append(prediction)
        grouped_labels[session] = label
    malicious = [name for name, label in grouped_labels.items() if label]
    benign = [name for name, label in grouped_labels.items() if not label]
    malicious_detected = sum(any(grouped[name]) for name in malicious)
    benign_flagged = sum(any(grouped[name]) for name in benign)
    return {
        "malicious_captures": len(malicious),
        "malicious_captures_detected": malicious_detected,
        "malicious_capture_detection_rate": (
            malicious_detected / len(malicious) if malicious else None
        ),
        "benign_captures": len(benign),
        "benign_captures_flagged": benign_flagged,
        "benign_capture_false_positive_rate": (
            benign_flagged / len(benign) if benign else None
        ),
        "capture_names": sorted(grouped),
    }


def _choose_threshold(labels: list[int], scores: list[float]) -> tuple[float, dict[str, object]]:
    candidates = []
    for threshold in _thresholds(scores):
        metrics = _window_metrics(labels, scores, threshold)
        candidates.append((float(metrics["f1"]), -(metrics["false_positive_rate"] or 0.0), threshold, metrics))
    if not candidates:
        raise ValueError("validation sessions produced no windows")
    _, _, threshold, metrics = max(candidates)
    return threshold, metrics


def evaluate(
    benign_train: list[Path],
    benign_validation: list[Path],
    positive_validation: list[Path],
    benign_test: list[Path],
    positive_test: list[Path],
    output: Path,
    window_size: int = 6,
    seed: int = 42,
) -> dict[str, object]:
    if not benign_train or not benign_validation or not positive_validation:
        raise ValueError("training and validation require benign plus malicious sessions")
    if not benign_test or not positive_test:
        raise ValueError("testing requires at least one benign and one malicious session")

    from sklearn.ensemble import IsolationForest
    import joblib

    train_x, _, _ = _vectors([(path, 0) for path in benign_train], window_size)
    validation_x, validation_y, validation_sessions = _vectors(
        [(path, 1) for path in positive_validation]
        + [(path, 0) for path in benign_validation],
        window_size,
    )
    test_x, test_y, test_sessions = _vectors(
        [(path, 1) for path in positive_test] + [(path, 0) for path in benign_test],
        window_size,
    )
    if not train_x or len(set(validation_y)) != 2 or len(set(test_y)) != 2:
        raise ValueError("each split must contain the required classes and non-empty windows")

    model = IsolationForest(n_estimators=300, contamination="auto", random_state=seed, n_jobs=-1)
    model.fit(train_x)
    validation_scores = _scores(model, validation_x)
    threshold, validation_metrics = _choose_threshold(validation_y, validation_scores)
    test_scores = _scores(model, test_x)
    test_metrics = _window_metrics(test_y, test_scores, threshold)
    test_predictions = [int(score >= threshold) for score in test_scores]
    test_metrics["capture_level"] = _capture_metrics(test_y, test_predictions, test_sessions)

    artifact = {
        "model": model,
        "features": extract_features(_session_windows([benign_train[0]], window_size)[0]).names(),
        "window_size": window_size,
        "threshold": threshold,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, output.with_suffix(".joblib"))
    result = {
        "algorithm": "isolation_forest",
        "window_size": window_size,
        "threshold_selection": "validation_max_f1_then_lowest_false_positive_rate",
        "splits": {
            "train": {
                "benign_sessions": [
                    {"session_id": path.stem, "source": str(path), "label": "benign"}
                    for path in benign_train
                ]
            },
            "validation": {
                "benign_sessions": [
                    {"session_id": path.stem, "source": str(path), "label": "benign"}
                    for path in benign_validation
                ],
                "malicious_sessions": [
                    {"session_id": path.stem, "source": str(path), "label": "malicious"}
                    for path in positive_validation
                ],
                "windows": len(validation_y),
            },
            "test": {
                "benign_sessions": [
                    {"session_id": path.stem, "source": str(path), "label": "benign"}
                    for path in benign_test
                ],
                "malicious_sessions": [
                    {"session_id": path.stem, "source": str(path), "label": "malicious"}
                    for path in positive_test
                ],
                "windows": len(test_y),
            },
        },
        "validation": validation_metrics,
        "test": test_metrics,
        "model": str(output.with_suffix(".joblib")),
    }
    output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--train-benign", nargs="+", type=Path, required=True)
    parser.add_argument("--validation-benign", nargs="+", type=Path, required=True)
    parser.add_argument("--validation-positive", nargs="+", type=Path, required=True)
    parser.add_argument("--test-benign", nargs="+", type=Path, required=True)
    parser.add_argument("--test-positive", nargs="+", type=Path, required=True)
    parser.add_argument("--window-size", type=int, default=6)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(evaluate(
        args.train_benign,
        args.validation_benign,
        args.validation_positive,
        args.test_benign,
        args.test_positive,
        args.output,
        args.window_size,
        args.seed,
    ), indent=2))


if __name__ == "__main__":
    main()
