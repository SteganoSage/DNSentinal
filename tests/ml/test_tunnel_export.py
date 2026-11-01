"""The exported forest (ml/tunnel/export.py) scores exactly as scikit-learn does, a LightGBM model is
shipped as it is, and the shipped model (models/tunnel) loads and catches a tunnel."""

import contextlib
import io
import json
import pickle
import random
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import numpy as np

from ml.tunnel import data
from ml.tunnel.scorer import Forest, TunnelModel

ROOT = Path(__file__).resolve().parents[2]

try:
    import sklearn  # noqa: F401
except ImportError:
    sklearn = None
try:
    import lightgbm
except ImportError:
    lightgbm = None


def tunnel_events(path: Path, count: int = 200) -> Path:
    """Two TXT queries a second of fresh base32 names under one domain: a tunnel."""
    lines = [json.dumps({"timestamp": 1000 + i * 0.5, "client_ip": "10.1.1.1",
                         "qname": f"{data._base32(random.Random(i), 40)}.t.evil-tunnel.test",
                         "qtype": "TXT", "response_size": 300}) for i in range(count)]
    path.write_text("\n".join(lines) + "\n")
    return path


@unittest.skipIf(sklearn is None, "needs scikit-learn (ml/requirements.txt)")
class ExportedForest(unittest.TestCase):
    def setUp(self):
        from sklearn.ensemble import RandomForestClassifier

        rng = np.random.default_rng(3)
        self.X = rng.normal(size=(2000, 6)) * [1, 10, 100, 1e-3, 1e4, 1]
        self.X[rng.random(self.X.shape) < 0.05] = np.nan  # missing values take a side of their own
        self.y = (np.nan_to_num(self.X[:, 0]) + np.nan_to_num(self.X[:, 1]) / 10 > 0.3) ^ (rng.random(2000) < 0.1)
        self.forest = RandomForestClassifier(n_estimators=25, max_depth=8, random_state=1, n_jobs=1).fit(self.X, self.y)

    def test_scores_bit_for_bit_as_scikit_learn(self):
        from ml.tunnel.export import edge_windows, forest_json

        exported = forest_json(self.forest)
        walker = Forest(json.loads(json.dumps(exported)))  # through JSON text, as shipped
        rng = np.random.default_rng(9)
        for X in (self.X, rng.normal(size=(3000, 6)) * 50, edge_windows(exported, 3000, 4)):
            np.testing.assert_array_equal(walker.score(X), self.forest.predict_proba(X)[:, 1])
        self.assertTrue(np.isnan(self.X).any())

    def test_thresholds_are_compared_as_float32(self):
        """scikit-learn casts features to float32: a float64 just above a threshold that rounds to it goes left."""
        from ml.tunnel.export import forest_json

        tree = self.forest.estimators_[0].tree_
        feature, threshold = int(tree.feature[0]), float(tree.threshold[0])
        row = np.zeros((1, 6))
        row[0, feature] = np.nextafter(threshold, np.inf)
        if np.float32(row[0, feature]) <= threshold:  # this threshold has a float64 neighbour above it that rounds down
            walker = Forest(forest_json(self.forest))
            np.testing.assert_array_equal(walker.score(row), self.forest.predict_proba(row)[:, 1])

    def test_export_writes_the_json_model_and_refuses_a_mismatch(self):
        from ml.tunnel import export
        from ml.tunnel.models import Trees
        from analyzer.detectors.tunnel import TunnelFeatures

        names = TunnelFeatures.names()[:6]
        X = np.nan_to_num(self.X)
        model = Trees("rf", seed=1, threads=1, params={"n_estimators": 20, "max_depth": 6}).fit(X, self.y, X)
        with tempfile.TemporaryDirectory() as tmp:
            source, out = Path(tmp) / "final", Path(tmp) / "shipped"
            source.mkdir()
            with open(source / "tunnel_rf.pkl", "wb") as stream:
                pickle.dump(model, stream)
            card = {"model": "tunnel_rf.pkl", "kind": "rf", "features": names, "threshold": 0.5,
                    "window_seconds": 60.0, "step_seconds": 10.0, "alert_after": 2}
            (source / "model.json").write_text(json.dumps(card))

            written = export.export(source, out, edges=500)
            self.assertEqual(written["model"], "tunnel_rf.json")
            self.assertEqual(written["exported"]["from"], "tunnel_rf.pkl")
            self.assertTrue(written["exported"]["identical"])
            self.assertEqual(written["exported"]["checked"]["edge"]["windows"], 500)
            self.assertFalse((out / "tunnel_rf.pkl").exists())  # no pickle shipped
            shipped = TunnelModel(out)
            self.assertIsNone(shipped.model)
            np.testing.assert_array_equal(shipped.forest.score(X), model.score(X, X))

            other = Path(tmp) / "other"
            with mock.patch.object(Forest, "score", lambda self, X: np.zeros(len(X))), \
                    self.assertRaises(SystemExit) as stopped:
                export.export(source, other, edges=500)
            self.assertIn("scored differently", str(stopped.exception))
            self.assertFalse((other / "tunnel_rf.json").exists())

    @unittest.skipIf(lightgbm is None, "needs lightgbm (ml/requirements.txt)")
    def test_a_lightgbm_model_is_shipped_as_it_is(self):
        from ml.tunnel import export
        from analyzer.detectors.tunnel import TunnelFeatures

        X = np.nan_to_num(self.X)
        booster = lightgbm.train({"objective": "binary", "num_leaves": 8, "verbose": -1}, lightgbm.Dataset(X, self.y),
                                 num_boost_round=20)
        with tempfile.TemporaryDirectory() as tmp:
            source, out = Path(tmp) / "final", Path(tmp) / "shipped"
            source.mkdir()
            out.mkdir()
            (out / "tunnel_rf.json").write_text("{}")  # an earlier export: must not stay beside the new one
            booster.save_model(str(source / "tunnel_lgbm.txt"))
            card = {"model": "tunnel_lgbm.txt", "kind": "lgbm", "features": TunnelFeatures.names()[:6],
                    "threshold": 0.5, "window_seconds": 60.0, "step_seconds": 10.0, "alert_after": 2}
            (source / "model.json").write_text(json.dumps(card))
            (source / "run_info_final.json").write_text("{}")
            export.export(source, out)
            self.assertEqual(sorted(f.name for f in out.iterdir()),
                             ["model.json", "run_info_final.json", "tunnel_lgbm.txt"])
            shipped = TunnelModel(out)
            np.testing.assert_array_equal(shipped.booster.predict(X), booster.predict(X))


@unittest.skipIf(lightgbm is None, "needs lightgbm (ml/requirements.txt)")
class ShippedModel(unittest.TestCase):
    """models/tunnel: LightGBM's text model, no pickle."""

    @classmethod
    def setUpClass(cls):
        cls.model = TunnelModel(ROOT / "models" / "tunnel")

    def test_the_card(self):
        card = self.model.card
        self.assertEqual((card["model"], card["kind"]), ("tunnel_lgbm.txt", "lgbm"))
        self.assertEqual(card["groups"], ["V", "N", "R", "D"])
        self.assertEqual((card["alert_after"], card["window_seconds"], card["step_seconds"]), (2, 60.0, 10.0))
        self.assertEqual(len(card["trained_on"]["tools"]), 10)
        self.assertIsNone(self.model.model)  # nothing unpickled
        self.assertEqual(self.model.booster.num_feature(), len(card["features"]))

    def test_catches_a_tunnel_and_not_ordinary_lookups(self):
        from analyzer.tunnel_analyzer import analyze

        with tempfile.TemporaryDirectory() as tmp:
            tunnel = tunnel_events(Path(tmp) / "tunnel.jsonl")
            with contextlib.redirect_stdout(io.StringIO()):
                results = [r for r in analyze(tunnel, model=ROOT / "models" / "tunnel") if r["signal"] == "tunnel"]
            self.assertEqual(results[-1]["verdict"]["label"], "high")
            self.assertTrue(any(r["alert"] for r in results))

            names = ["www", "mail", "api", "cdn", "static", "login"]
            ordinary = Path(tmp) / "ordinary.jsonl"
            ordinary.write_text("".join(json.dumps({"timestamp": 1000 + i * 7.0, "client_ip": "10.1.1.2",
                                                    "qname": f"{names[i % len(names)]}.example.com", "qtype": "A",
                                                    "response_size": 80}) + "\n" for i in range(60)))
            with contextlib.redirect_stdout(io.StringIO()):
                results = [r for r in analyze(ordinary, model=ROOT / "models" / "tunnel") if r["signal"] == "tunnel"]
            self.assertTrue(results)
            self.assertFalse(any(r["alert"] for r in results))


if __name__ == "__main__":
    unittest.main()
