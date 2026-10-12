"""Train the feature-based DGA baseline.

Input CSV columns:
    domain,label,family

``family`` is required for family-held-out evaluation and should identify the
DGA family for malicious rows. Use ``benign`` for benign rows.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

from .features import DomainFeatures, NgramModel, extract_features


def load_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as stream:
        first = stream.readline()
        if not first:
            raise ValueError(f"{path} is empty")
        first_fields = next(csv.reader([first]))
        if {"domain", "label", "family"}.issubset(first_fields):
            stream.seek(0)
            rows = list(csv.DictReader(stream))
        else:
            stream.seek(0)
            rows = [
                {"label": label.strip().lower(), "family": family.strip(), "domain": domain.strip()}
                for label, family, domain in csv.reader(stream)
                if len((label, family, domain)) == 3
            ]
    required = {"domain", "label", "family"}
    if not rows or not required.issubset(rows[0]):
        raise ValueError(f"{path} must contain columns: {', '.join(sorted(required))}")
    for row in rows:
        if row["label"] not in {"0", "1", "legit", "dga"}:
            raise ValueError("label must be 0/legit (benign) or 1/dga (DGA)")
        row["label"] = "0" if row["label"] in {"0", "legit"} else "1"
    return rows


def _sklearn():
    try:
        from sklearn.ensemble import RandomForestClassifier
    except ImportError as error:
        raise RuntimeError(
            "training requires scikit-learn; install it in the project environment"
        ) from error
    return RandomForestClassifier


def train(rows: list[dict[str, str]], output: Path, trees: int, seed: int) -> dict[str, Any]:
    benign = [row["domain"] for row in rows if row["label"] == "0"]
    ngram = NgramModel().fit(benign)
    features = [extract_features(row["domain"], ngram).vector() for row in rows]
    labels = [int(row["label"]) for row in rows]
    classifier = _sklearn()(n_estimators=trees, random_state=seed, class_weight="balanced", n_jobs=-1)
    classifier.fit(features, labels)
    output.parent.mkdir(parents=True, exist_ok=True)
    import joblib

    joblib.dump({"model": classifier, "ngram": ngram, "features": DomainFeatures.names()}, output)
    return {
        "samples": len(rows),
        "benign": labels.count(0),
        "dga": labels.count(1),
        "features": DomainFeatures.names(),
        "model": str(output),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", type=Path)
    parser.add_argument("--output", type=Path, default=Path("models/dga_rf.joblib"))
    parser.add_argument("--trees", type=int, default=300)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    print(json.dumps(train(load_rows(args.dataset), args.output, args.trees, args.seed), indent=2))


if __name__ == "__main__":
    main()
