"""The trained tunnel model, as the analyzer runs it.

Reads a folder written by `python -m ml.tunnel.pipeline --mode final` (or
models/tunnel once one is chosen): model.json and the model it names, a
LightGBM text model (tunnel_lgbm.txt) or a pickled one (tunnel_rf.pkl).
A pickle runs code when it is loaded: load only models trained here. The
model decides; the hand-written rules' reasons explain the verdict.

    python -m analyzer.tunnel_analyzer events.jsonl --model ml/runs/tunnel/main/w60-fVNR/final
"""

from __future__ import annotations

import json
import pickle
from pathlib import Path

import numpy as np

from analyzer.detectors.tunnel import TunnelFeatures, TunnelVerdict, score_features


class TunnelModel:
    def __init__(self, folder: str | Path) -> None:
        folder = Path(folder)
        self.card = json.loads((folder / "model.json").read_text())
        path = folder / self.card["model"]
        if path.suffix == ".txt":
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
        if self.booster is not None:
            return float(self.booster.predict(selected, num_threads=1)[0])
        return float(self.model.score(np.array(selected), np.array([vector]))[0])

    def verdict(self, features: TunnelFeatures) -> TunnelVerdict:
        score = self.score(features)
        return TunnelVerdict(score, "high" if score > self.threshold else "low", score_features(features).reasons)
