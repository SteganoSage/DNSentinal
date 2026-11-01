"""The trained tunnel model, as the analyzer runs it.

Reads a model folder: model.json and the model it names. models/tunnel is the
shipped one, or use a folder `python -m ml.tunnel.pipeline --mode final` wrote.
The model is one of three:
- a LightGBM text model (tunnel_lgbm.txt), as models/tunnel ships it;
- a pickled forest (tunnel_rf.pkl). A pickle runs code when it is loaded and
  needs the scikit-learn it was made with: load only models trained here;
- that forest exported as JSON trees (tunnel_rf.json, ml/tunnel/export.py),
  walked here with no library.
The model decides; the hand-written rules' reasons explain the verdict.

    python -m analyzer.tunnel_analyzer events.jsonl --model models/tunnel
"""

from __future__ import annotations

import json
import pickle
from pathlib import Path

import numpy as np

from analyzer.detectors.tunnel import TunnelFeatures, TunnelVerdict, score_features


class Forest:
    """A random forest exported by ml/tunnel/export.py, scored exactly as scikit-learn scores it:
    each feature compared as float32 (as scikit-learn casts them), and the trees' leaf
    probabilities added one after another, in order, then divided by their number."""

    def __init__(self, exported: dict) -> None:
        if exported.get("format") != "dnsentinel-forest-1":
            raise ValueError(f"not an exported forest: format {exported.get('format')!r}")
        self.features = int(exported["features"])
        self.trees = [(t["feature"], t["threshold"], t["left"], t["right"], [bool(m) for m in t["missing_left"]],
                       t["value"]) for t in exported["trees"]]

    def score(self, X) -> np.ndarray:
        rows = np.asarray(X, dtype=np.float32).astype(np.float64).reshape(-1, self.features).tolist()
        out = np.empty(len(rows))
        for i, row in enumerate(rows):
            total = 0.0
            for feature, threshold, left, right, missing_left, value in self.trees:
                node = 0
                f = feature[0]
                while f >= 0:
                    x = row[f]
                    if x != x:  # missing (NaN)
                        node = left[node] if missing_left[node] else right[node]
                    else:
                        node = left[node] if x <= threshold[node] else right[node]
                    f = feature[node]
                total += value[node]
            out[i] = total / len(self.trees)
        return out


class TunnelModel:
    def __init__(self, folder: str | Path) -> None:
        folder = Path(folder)
        self.card = json.loads((folder / "model.json").read_text())
        path = folder / self.card["model"]
        self.forest = None
        if path.suffix == ".json":
            self.booster, self.model = None, None
            self.forest = Forest(json.loads(path.read_text()))
        elif path.suffix == ".txt":
            import lightgbm

            self.booster, self.model = lightgbm.Booster(model_file=str(path)), None
        else:
            with open(path, "rb") as stream:
                self.booster, self.model = None, pickle.load(stream)
            if hasattr(getattr(self.model, "inner", None), "single_thread"):
                self.model.inner.single_thread()  # one window at a time: no thread pool to start
        names = TunnelFeatures.names()
        self.columns = [names.index(name) for name in self.card["features"]]
        self.threshold = float(self.card["threshold"])
        self.window_seconds = float(self.card["window_seconds"])
        self.step_seconds = float(self.card["step_seconds"])
        self.alert_after = int(self.card.get("alert_after", 1))

    def score(self, features: TunnelFeatures) -> float:
        vector = features.vector()
        selected = [[vector[i] for i in self.columns]]
        if self.forest is not None:
            return float(self.forest.score(selected)[0])
        if self.booster is not None:
            return float(self.booster.predict(selected, num_threads=1)[0])
        return float(self.model.score(np.array(selected), np.array([vector]))[0])

    def verdict(self, features: TunnelFeatures) -> TunnelVerdict:
        score = self.score(features)
        return TunnelVerdict(score, "high" if score > self.threshold else "low", score_features(features).reasons)
