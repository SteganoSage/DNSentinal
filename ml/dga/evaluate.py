"""Evaluate a saved DGA classifier, including a family-held-out report."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .train import load_rows
from .features import extract_features


def main() -> None:
    try:
        import joblib
        from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
    except ImportError as error:
        raise RuntimeError("evaluation requires scikit-learn and joblib") from error

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("model", type=Path)
    parser.add_argument("dataset", type=Path)
    args = parser.parse_args()
    bundle = joblib.load(args.model)
    rows = load_rows(args.dataset)
    x = [extract_features(row["domain"], bundle["ngram"]).vector() for row in rows]
    y = [int(row["label"]) for row in rows]
    probabilities = bundle["model"].predict_proba(x)[:, 1]
    predictions = (probabilities >= 0.5).astype(int)
    report = classification_report(y, predictions, output_dict=True, zero_division=0)
    print(json.dumps({
        "roc_auc": roc_auc_score(y, probabilities),
        "confusion_matrix": confusion_matrix(y, predictions).tolist(),
        "classification_report": report,
    }, indent=2))


if __name__ == "__main__":
    main()
