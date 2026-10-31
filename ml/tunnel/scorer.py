"""The trained tunnel model, as the analyzer runs it.

Reads a folder written by `python -m ml.tunnel.pipeline --mode final` (or
models/tunnel once one is chosen): tunnel_lgbm.txt and model.json. The
model decides; the hand-written rules' reasons explain the verdict.

    python -m analyzer.tunnel_analyzer events.jsonl --model ml/runs/tunnel/main/w60-fVNR/final
"""

from __future__ import annotations

import json
from pathlib import Path

from analyzer.detectors.tunnel import TunnelFeatures, TunnelVerdict, score_features


class TunnelModel:
    def __init__(self, folder: str | Path) -> None:
        import lightgbm

        folder = Path(folder)
        self.card = json.loads((folder / "model.json").read_text())
        self.booster = lightgbm.Booster(model_file=str(folder / self.card["model"]))
        names = TunnelFeatures.names()
        self.columns = [names.index(name) for name in self.card["features"]]
        self.threshold = float(self.card["threshold"])
        self.window_seconds = float(self.card["window_seconds"])
        self.step_seconds = float(self.card["step_seconds"])

    def score(self, features: TunnelFeatures) -> float:
        vector = features.vector()
        return float(self.booster.predict([[vector[i] for i in self.columns]], num_threads=1)[0])

    def verdict(self, features: TunnelFeatures) -> TunnelVerdict:
        score = self.score(features)
        return TunnelVerdict(score, "high" if score > self.threshold else "low", score_features(features).reasons)
