"""Train an XGBoost DGA classifier with the shared lexical features.

The input format is the same as train.py:
    domain,label,family

The loader also accepts the headerless label,family,domain dataset format.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .features import DomainFeatures, NgramModel, extract_features
from .train import load_rows


def _xgboost():
    try:
        from xgboost import XGBClassifier
    except ImportError as error:
        raise RuntimeError("training requires xgboost; install it in the project environment") from error
    return XGBClassifier


def train(rows: list[dict[str, str]], output: Path, trees: int, seed: int) -> dict[str, Any]:
    benign = [row["domain"] for row in rows if row["label"] == "0"]
    ngram = NgramModel().fit(benign)
    features = [extract_features(row["domain"], ngram).vector() for row in rows]
    labels = [int(row["label"]) for row in rows]
    classifier = _xgboost()(
        n_estimators=trees,
        max_depth=8,
        learning_rate=0.1,
        subsample=0.9,
        colsample_bytree=0.9,
        objective="binary:logistic",
        eval_metric="logloss",
        tree_method="hist",
        random_state=seed,
        n_jobs=-1,
    )
    classifier.fit(features, labels)
    output.parent.mkdir(parents=True, exist_ok=True)
    import joblib

    joblib.dump({"model": classifier, "ngram": ngram, "features": DomainFeatures.names()}, output)
    return {
        "samples": len(rows),
        "benign": labels.count(0),
        "dga": labels.count(1),
        "features": DomainFeatures.names(),
        "algorithm": "xgboost",
        "model": str(output),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", type=Path)
    parser.add_argument("--output", type=Path, default=Path("models/dga_xgb.joblib"))
    parser.add_argument("--trees", type=int, default=300)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    print(json.dumps(train(load_rows(args.dataset), args.output, args.trees, args.seed), indent=2))


if __name__ == "__main__":
    main()
