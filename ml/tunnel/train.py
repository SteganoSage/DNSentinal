"""Train and compare supervised and unsupervised tunnel detectors.

Each input CSV is one capture session. Query CSVs use the columns
``timestamp,src_ip,qname`` and may optionally include ``qtype``, ``rcode``,
and ``response_size``. Test sessions must be supplied separately from train
sessions; windows from the same capture are never randomly split.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from analyzer.detectors.tunnel import DnsEvent, TunnelFeatures, extract_features


def _events(path: Path) -> list[DnsEvent]:
    with path.open(newline="", encoding="utf-8-sig") as stream:
        reader = csv.DictReader(stream)
        required = {"timestamp", "qname"}
        if not required.issubset(reader.fieldnames or ()):
            raise ValueError(f"{path} must contain timestamp and qname columns")
        events = []
        for line_number, row in enumerate(reader, 2):
            try:
                events.append(DnsEvent.from_mapping({
                    "timestamp": float(row["timestamp"]),
                    "client_id": row.get("src_ip") or row.get("client_ip") or "unknown",
                    "qname": row["qname"],
                    "qtype": row.get("qtype") or "A",
                    "rcode": row.get("rcode") or "NOERROR",
                    "response_size": row.get("response_size") or 0,
                }))
            except (TypeError, ValueError) as error:
                raise ValueError(f"{path}:{line_number}: invalid query record: {error}") from error
    return sorted(events, key=lambda event: event.timestamp)


def _windows(path: Path, size: int) -> list[list[DnsEvent]]:
    events = _events(path)
    return [events[start : start + size] for start in range(0, len(events) - size + 1, size)]


def _session_windows(paths: list[Path], size: int) -> list[list[DnsEvent]]:
    return [window for path in paths for window in _windows(path, size)]


def _dataset(
    positive_paths: list[Path],
    benign_paths: list[Path],
    test_positive_paths: list[Path],
    test_benign_paths: list[Path],
    size: int,
) -> tuple[list[list[float]], list[int], list[list[float]], list[int]]:
    train_positive = _session_windows(positive_paths, size)
    train_benign = _session_windows(benign_paths, size)
    test_positive = _session_windows(test_positive_paths, size)
    test_benign = _session_windows(test_benign_paths, size)
    train_windows = train_positive + train_benign
    test_windows = test_positive + test_benign
    train_x = [extract_features(window).vector() for window in train_windows]
    test_x = [extract_features(window).vector() for window in test_windows]
    train_y = [1] * len(train_positive) + [0] * len(train_benign)
    test_y = [1] * len(test_positive) + [0] * len(test_benign)
    if not train_x or len(set(train_y)) != 2:
        raise ValueError("training sessions must produce windows for both classes")
    if not test_x or len(set(test_y)) != 2:
        raise ValueError("test sessions must produce windows for both classes")
    return train_x, train_y, test_x, test_y


def _classification_metrics(
    test_y: list[int], predictions: object, probabilities: object
) -> dict[str, object]:
    from sklearn.metrics import (
        accuracy_score,
        classification_report,
        confusion_matrix,
        f1_score,
        precision_score,
        recall_score,
        roc_auc_score,
    )

    false_alarm_count = int(sum(
        prediction == 1 and label == 0
        for prediction, label in zip(predictions, test_y)
    ))
    benign_test_count = sum(label == 0 for label in test_y)
    return {
        "accuracy": accuracy_score(test_y, predictions),
        "precision": precision_score(test_y, predictions, zero_division=0),
        "recall": recall_score(test_y, predictions, zero_division=0),
        "f1": f1_score(test_y, predictions, zero_division=0),
        "roc_auc": roc_auc_score(test_y, probabilities),
        "confusion_matrix": confusion_matrix(test_y, predictions).tolist(),
        "false_alarm_count": false_alarm_count,
        "false_alarm_rate": false_alarm_count / max(1, benign_test_count),
        "classification_report": classification_report(
            test_y, predictions, target_names=["benign", "tunnel"], zero_division=0
        ),
    }


def train(
    positive_paths: list[Path],
    benign_paths: list[Path],
    output: Path,
    size: int,
    seed: int,
    test_positive_paths: list[Path] | None = None,
    test_benign_paths: list[Path] | None = None,
) -> dict[str, object]:
    from sklearn.ensemble import RandomForestClassifier
    import joblib

    if not positive_paths or not benign_paths:
        raise ValueError("at least one training session is required for each class")
    if (test_positive_paths is None) != (test_benign_paths is None):
        raise ValueError("both test-positive and test-benign sessions are required")
    if test_positive_paths is None:
        from sklearn.model_selection import train_test_split
        train_positive = _session_windows(positive_paths, size)
        train_benign = _session_windows(benign_paths, size)
        windows = train_positive + train_benign
        labels = [1] * len(train_positive) + [0] * len(train_benign)
        vectors = [extract_features(window).vector() for window in windows]
        train_x, test_x, train_y, test_y = train_test_split(
            vectors, labels, test_size=0.25, random_state=seed, stratify=labels
        )
        test_session_count = 0
    else:
        train_x, train_y, test_x, test_y = _dataset(
            positive_paths, benign_paths, test_positive_paths, test_benign_paths or [], size
        )
        train_positive = _session_windows(positive_paths, size)
        train_benign = _session_windows(benign_paths, size)
        windows = train_positive + train_benign
        test_session_count = len(test_positive_paths or []) + len(test_benign_paths or [])
    if not train_x or len(set(train_y)) != 2:
        raise ValueError("training sessions must produce windows for both classes")
    if len(set(test_y)) != 2:
        raise ValueError("test sessions must produce windows for both classes")
    model = RandomForestClassifier(
        n_estimators=300, class_weight="balanced", random_state=seed, n_jobs=-1
    )
    model.fit(train_x, train_y)
    probabilities = model.predict_proba(test_x)[:, 1]
    predictions = (probabilities >= 0.5).astype(int)
    output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": model, "features": TunnelFeatures.names(), "window_size": size}, output)
    return {
        "algorithm": "random_forest",
        "window_size": size,
        "windows": len(windows),
        "positive_windows": len(train_positive),
        "benign_windows": len(train_benign),
        "train_windows": len(train_y),
        "test_windows": len(test_y),
        "train_sessions": len(positive_paths) + len(benign_paths),
        "test_sessions": test_session_count,
        **_classification_metrics(test_y, predictions, probabilities),
        "model": str(output),
    }


def train_isolation_forest(
    benign_paths: list[Path],
    test_positive_paths: list[Path],
    test_benign_paths: list[Path],
    output: Path,
    size: int,
    seed: int,
) -> dict[str, object]:
    """Fit only on benign windows and classify anomalous held-out windows."""
    from sklearn.ensemble import IsolationForest
    import joblib

    train_benign = _session_windows(benign_paths, size)
    test_positive = _session_windows(test_positive_paths, size)
    test_benign = _session_windows(test_benign_paths, size)
    train_x = [extract_features(window).vector() for window in train_benign]
    test_x = [extract_features(window).vector() for window in test_positive + test_benign]
    test_y = [1] * len(test_positive) + [0] * len(test_benign)
    if not train_x or not test_x or len(set(test_y)) != 2:
        raise ValueError("Isolation Forest requires benign training and both held-out classes")
    model = IsolationForest(
        n_estimators=300, contamination="auto", random_state=seed, n_jobs=-1
    )
    model.fit(train_x)
    anomaly_scores = -model.score_samples(test_x)
    predictions = (model.predict(test_x) == -1).astype(int)
    output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": model, "features": TunnelFeatures.names(), "window_size": size}, output)
    return {
        "algorithm": "isolation_forest",
        "window_size": size,
        "train_windows": len(train_x),
        "test_windows": len(test_y),
        "train_sessions": len(benign_paths),
        "test_sessions": len(test_positive_paths) + len(test_benign_paths),
        **_classification_metrics(test_y, predictions, anomaly_scores),
        "model": str(output),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--positive", nargs="+", type=Path, required=True, help="training tunnel sessions")
    parser.add_argument("--benign", nargs="+", type=Path, required=True, help="training normal sessions")
    parser.add_argument("--test-positive", nargs="+", type=Path, help="held-out tunnel sessions")
    parser.add_argument("--test-benign", nargs="+", type=Path, help="held-out normal sessions")
    parser.add_argument("--output", type=Path, default=Path("models/tunnel_rf.joblib"))
    parser.add_argument("--window-size", type=int, default=6)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    if args.test_positive is None or args.test_benign is None:
        raise SystemExit("--test-positive and --test-benign are required for comparison")
    random_forest = train(
        args.positive, args.benign, args.output, args.window_size, args.seed,
        args.test_positive, args.test_benign,
    )
    isolation_forest = train_isolation_forest(
        args.benign, args.test_positive, args.test_benign,
        args.output.with_name("tunnel_if.joblib"), args.window_size, args.seed,
    )
    print(json.dumps({
        "random_forest": random_forest,
        "isolation_forest": isolation_forest,
    }, indent=2))


if __name__ == "__main__":
    main()