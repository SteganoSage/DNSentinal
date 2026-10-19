"""The models E7 compares, behind one interface.

On the features (features.py):
  rf         a random forest, the classic DGA baseline.
  lgbm       gradient-boosted trees, LightGBM.
  xgboost    gradient-boosted trees, XGBoost.
  histgb     gradient-boosted trees, scikit-learn's HistGradientBoosting.
On the name's characters:
  cnn        a character-level CNN (charcnn.py; needs PyTorch, quick on a GPU).
Baselines (E7):
  entropy    flag labels whose character entropy is high.
  blocklist  flag names a public malware blocklist already lists.

The three boosting libraries start from comparable settings (300 trees,
learning rate 0.05, at most 31 leaves) so differences come from the
library, not the settings; the best is tuned afterwards. Every model sees a
Batch and returns one score per row, higher meaning more likely generated.
The pipeline picks each model's threshold.
"""

from __future__ import annotations

import io
import pickle
from dataclasses import dataclass

import numpy as np


@dataclass
class Batch:
    """Rows to fit or score: the selected features plus what some models read instead."""

    X: np.ndarray             # one row per name: the selected feature columns
    names: np.ndarray         # registrable domains ("example.co.uk"), for the CNN
    blocked: np.ndarray       # bool: is the name on the blocklist snapshot
    y: np.ndarray | None = None
    entropy: np.ndarray | None = None  # for the entropy baseline, whatever features are selected
    weight: np.ndarray | None = None   # per-row training weight (family balancing); None: all equal


class Model:
    name = ""
    title = ""
    fixed_threshold: float | None = None  # None: calibrated to the target false-positive rate

    def fit(self, batch: Batch) -> "Model":
        return self

    def score(self, batch: Batch) -> np.ndarray:
        raise NotImplementedError

    def size(self) -> dict:
        return {"bytes": 0}

    def single_thread(self) -> None:
        """Score with one thread from now on: no pool to start for a single name."""


def _pickled_size(model) -> int:
    stream = io.BytesIO()
    pickle.dump(model, stream, protocol=pickle.HIGHEST_PROTOCOL)
    return stream.tell()


class RandomForest(Model):
    name, title = "rf", "Random forest"

    def __init__(self, seed: int, threads: int, params: dict | None = None) -> None:
        self.params = dict(n_estimators=100, max_depth=20, min_samples_leaf=5, max_features="sqrt",
                           random_state=seed, n_jobs=threads) | (params or {})
        self.model = None

    def fit(self, batch: Batch) -> "RandomForest":
        from sklearn.ensemble import RandomForestClassifier

        self.model = RandomForestClassifier(**self.params).fit(batch.X, batch.y, sample_weight=batch.weight)
        return self

    def score(self, batch: Batch) -> np.ndarray:
        return self.model.predict_proba(batch.X)[:, 1]

    def single_thread(self) -> None:
        self.model.n_jobs = 1

    def size(self) -> dict:
        return {"bytes": _pickled_size(self.model), "trees": len(self.model.estimators_),
                "nodes": int(sum(tree.tree_.node_count for tree in self.model.estimators_))}


class LightGBM(Model):
    name, title = "lgbm", "LightGBM"

    def __init__(self, seed: int, threads: int, params: dict | None = None) -> None:
        self.params = dict(n_estimators=300, learning_rate=0.05, num_leaves=31, min_child_samples=50,
                           subsample=0.8, subsample_freq=1, reg_lambda=1.0, random_state=seed, n_jobs=threads,
                           verbose=-1) | (params or {})
        self.model = None

    def fit(self, batch: Batch) -> "LightGBM":
        from lightgbm import LGBMClassifier

        self.model = LGBMClassifier(**self.params).fit(batch.X, batch.y, sample_weight=batch.weight)
        return self

    def score(self, batch: Batch) -> np.ndarray:
        return self.model.booster_.predict(batch.X, num_threads=self.params["n_jobs"])

    def single_thread(self) -> None:
        self.params["n_jobs"] = 1

    def size(self) -> dict:
        booster = self.model.booster_
        leaves = sum(tree["num_leaves"] for tree in booster.dump_model()["tree_info"])
        return {"bytes": len(booster.model_to_string().encode()), "trees": booster.num_trees(),
                "nodes": 2 * leaves - booster.num_trees()}


class XGBoost(Model):
    name, title = "xgboost", "XGBoost"

    def __init__(self, seed: int, threads: int, params: dict | None = None) -> None:
        self.params = dict(n_estimators=300, learning_rate=0.05, max_leaves=31, max_depth=0, grow_policy="lossguide",
                           min_child_weight=1.0, subsample=0.8, reg_lambda=1.0, tree_method="hist",
                           random_state=seed, n_jobs=threads) | (params or {})
        self.model = None

    def fit(self, batch: Batch) -> "XGBoost":
        from xgboost import XGBClassifier

        self.model = XGBClassifier(**self.params).fit(batch.X, batch.y, sample_weight=batch.weight)
        return self

    def score(self, batch: Batch) -> np.ndarray:
        return self.model.predict_proba(batch.X)[:, 1]

    def single_thread(self) -> None:
        self.model.set_params(n_jobs=1)

    def size(self) -> dict:
        booster = self.model.get_booster()
        trees = booster.get_dump()
        return {"bytes": len(booster.save_raw("json")), "trees": len(trees),
                "nodes": sum(tree.count("\n") for tree in trees)}


class HistGradientBoosting(Model):
    name, title = "histgb", "HistGradientBoosting"

    def __init__(self, seed: int, threads: int, params: dict | None = None) -> None:
        self.params = dict(max_iter=300, learning_rate=0.05, max_leaf_nodes=31, min_samples_leaf=50,
                           l2_regularization=1.0, early_stopping=False, random_state=seed) | (params or {})
        self.model = None

    def fit(self, batch: Batch) -> "HistGradientBoosting":
        from sklearn.ensemble import HistGradientBoostingClassifier

        self.model = HistGradientBoostingClassifier(**self.params).fit(batch.X, batch.y, sample_weight=batch.weight)
        return self

    def score(self, batch: Batch) -> np.ndarray:
        return self.model.predict_proba(batch.X)[:, 1]

    def size(self) -> dict:
        predictors = [tree for stage in getattr(self.model, "_predictors", []) for tree in stage]  # private, may change
        return {"bytes": _pickled_size(self.model), "trees": len(predictors),
                "nodes": int(sum(len(tree.nodes) for tree in predictors))}


class EntropyRule(Model):
    name, title = "entropy", "Entropy threshold (baseline)"

    def score(self, batch: Batch) -> np.ndarray:
        return np.asarray(batch.entropy, dtype=float)


class Blocklist(Model):
    name, title = "blocklist", "Blocklist only (baseline)"
    fixed_threshold = 0.5

    def score(self, batch: Batch) -> np.ndarray:
        return batch.blocked.astype(float)


_TREES = {m.name: m for m in (RandomForest, LightGBM, XGBoost, HistGradientBoosting)}
_BASELINES = {m.name: m for m in (EntropyRule, Blocklist)}
NAMES = [*_TREES, "cnn", *_BASELINES]
_LIBRARY = {"rf": "sklearn", "lgbm": "lightgbm", "xgboost": "xgboost", "histgb": "sklearn", "cnn": "torch"}


def make(name: str, seed: int, threads: int, params: dict | None = None) -> Model:
    """A fresh model; params override a tree model's default settings (e.g. tuned ones)."""
    if name in _TREES:
        return _TREES[name](seed, threads, params)
    if name in _BASELINES:
        return _BASELINES[name]()
    if name == "cnn":
        from .charcnn import CharCNN

        return CharCNN(seed, threads)
    raise ValueError(f"unknown model {name!r} ({', '.join(NAMES)})")


def title(name: str) -> str:
    return "Character CNN" if name == "cnn" else {**_TREES, **_BASELINES}[name].title


def available(name: str) -> bool:
    """Is the library this model needs installed?"""
    if name not in _LIBRARY:
        return name in NAMES
    try:
        __import__(_LIBRARY[name])
    except ImportError:
        return False
    return True
