"""The detectors E8 compares, behind one interface.

On the window features (analyzer/detectors/tunnel.py):
  rf       a random forest                      } supervised, from the DGA
  lgbm     gradient-boosted trees, LightGBM     } pipeline's wrappers
  xgboost  gradient-boosted trees, XGBoost      } (ml/dga/models.py), so both
  histgb   scikit-learn's HistGradientBoosting  } detectors start from the same settings
  iforest  an Isolation Forest fitted on benign windows only: no tunnel
           examples needed, as in reality we would not have every tool's (README §7.8.3)
Baselines (E8):
  qpm      queries per minute to one domain over a threshold
  rules    the hand-written rules (score_features): its own "high" verdict

Every model returns one score per window, higher meaning more tunnel-like;
the pipeline sets each threshold for the target false-positive rate, except
the rules', which is fixed.
"""

from __future__ import annotations

import numpy as np

from analyzer.detectors.tunnel import TunnelFeatures, score_features

from ..dga import models as dga_models

TREES = ("rf", "lgbm", "xgboost", "histgb")
NAMES = [*TREES, "iforest", "qpm", "rules"]
TITLES = {"rf": "Random forest", "lgbm": "LightGBM", "xgboost": "XGBoost", "histgb": "HistGradientBoosting",
          "iforest": "Isolation Forest", "qpm": "Queries per minute", "rules": "Hand-written rules"}
_QUERY_COUNT = TunnelFeatures.names().index("query_count")
_NOTHING = np.empty(0)


class Model:
    name = ""
    fixed_threshold: float | None = None  # None: set for the target false-positive rate

    def fit(self, X: np.ndarray, y: np.ndarray, full: np.ndarray) -> "Model":
        """X: the selected feature columns; full: every feature (for the baselines)."""
        return self

    def score(self, X: np.ndarray, full: np.ndarray) -> np.ndarray:
        raise NotImplementedError

    def size(self) -> dict:
        return {"bytes": 0}


class Trees(Model):
    def __init__(self, name: str, seed: int, threads: int, params: dict | None = None) -> None:
        self.name = name
        self.inner = dga_models.make(name, seed, threads, params)

    @property
    def params(self) -> dict:
        return self.inner.params

    def fit(self, X, y, full):
        self.inner.fit(dga_models.Batch(X, _NOTHING, _NOTHING, y=y))
        return self

    def score(self, X, full):
        return self.inner.score(dga_models.Batch(X, _NOTHING, _NOTHING))

    def size(self) -> dict:
        return self.inner.size()


class IsolationForest(Model):
    name = "iforest"

    def __init__(self, seed: int, threads: int, params: dict | None = None) -> None:
        self.params = dict(n_estimators=200, max_samples=256, random_state=seed, n_jobs=threads) | (params or {})
        self.model = None

    def fit(self, X, y, full):
        from sklearn.ensemble import IsolationForest as Forest

        self.model = Forest(**self.params).fit(X[~np.asarray(y, dtype=bool)])
        return self

    def score(self, X, full):
        return -self.model.score_samples(X)

    def size(self) -> dict:
        return {"bytes": dga_models._pickled_size(self.model), "trees": len(self.model.estimators_)}


class QueriesPerMinute(Model):
    name = "qpm"

    def score(self, X, full):
        return full[:, _QUERY_COUNT].astype(float)


class Rules(Model):
    name = "rules"
    fixed_threshold = 0.75 - 1e-9  # flagged: score > threshold, so "high" (>= 0.75) is flagged

    def score(self, X, full):
        return np.array([score_features(TunnelFeatures(*row)).score for row in full.tolist()])


def make(name: str, seed: int, threads: int, params: dict | None = None) -> Model:
    if name in TREES:
        return Trees(name, seed, threads, params)
    if name == "iforest":
        return IsolationForest(seed, threads, params)
    if name == "qpm":
        return QueriesPerMinute()
    if name == "rules":
        return Rules()
    raise ValueError(f"unknown model {name!r} ({', '.join(NAMES)})")


def available(name: str) -> bool:
    return dga_models.available(name) if name in TREES else name in NAMES
