"""The deployed DGA classifier, one name at a time: the reference the C++ fast path must match.

    python -m ml.dga.scorer example.com x7kq2bzvdq.biz      # score names with models/dga
    python -m ml.dga.scorer --model some/run/final name ...  # or a pipeline run's final/ folder

The model is a pipeline run's `final/` folder (models/dga is the one the
resolver ships): dga_lgbm.txt (the trees), features.json (the fitted
feature tables) and model.json (feature order, threshold, provenance).
A name is flagged when its score is above the threshold, which was set
so that 0.1% of benign calibration names would be.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from .features import (WORDS_PATH, DomainFeatures, FeatureContext, NgramModel, TldPrior, default_words,
                       label_features, split_name)

MODEL_DIR = Path(__file__).resolve().parents[2] / "models" / "dga"


class Scorer:
    def __init__(self, folder: str | Path = MODEL_DIR) -> None:
        import lightgbm

        folder = Path(folder)
        card = json.loads((folder / "model.json").read_text())
        tables = json.loads((folder / "features.json").read_text())
        self.features: list[str] = card["features"]
        self.threshold: float = card["threshold"]
        if "label_in_allowlist" in self.features:
            raise ValueError("this model needs the allowlist's labels (feature F): not supported here")
        words = None
        if "word_coverage" in self.features:
            if card.get("words_sha256") and card["words_sha256"] != hashlib.sha256(WORDS_PATH.read_bytes()).hexdigest():
                raise ValueError(f"{WORDS_PATH} is not the word list this model was trained with")
            words = default_words()
        ngram = lambda key: NgramModel.from_state(tables[key]) if key in tables else None  # noqa: E731
        self.context = FeatureContext(ngram=ngram("ngram"), tld_prior=TldPrior.from_state(tables["tld_prior"]),
                                      words=words, bigram=ngram("bigram"), dga_ngram=ngram("dga_ngram"),
                                      rhythm=ngram("rhythm"))
        index = {name: i for i, name in enumerate(DomainFeatures.names())}
        self.columns = [index[name] for name in self.features]
        self.booster = lightgbm.Booster(model_file=str(folder / "dga_lgbm.txt"))

    def vector(self, domain: str) -> list[float]:
        """The model's inputs for a name, in its feature order."""
        label, suffix = split_name(domain)
        everything = label_features(label, suffix, self.context).vector()
        return [everything[i] for i in self.columns]

    def score(self, domain: str) -> float:
        return float(self.booster.predict([self.vector(domain)], num_threads=1)[0])

    def is_dga(self, domain: str) -> bool:
        return self.score(domain) > self.threshold


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("names", nargs="+")
    parser.add_argument("--model", type=Path, default=MODEL_DIR)
    args = parser.parse_args()
    scorer = Scorer(args.model)
    for name in args.names:
        score = scorer.score(name)
        print(f"{name:40} {score:.4f}  {'DGA' if score > scorer.threshold else 'ok'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
