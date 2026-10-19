"""Every pipeline mode runs end to end on the smoke dataset."""

import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ml.dga import data

try:
    import lightgbm  # noqa: F401
    import matplotlib  # noqa: F401
    import sklearn  # noqa: F401
except ImportError:
    lightgbm = None


@unittest.skipIf(lightgbm is None, "needs lightgbm, scikit-learn and matplotlib (ml/requirements.txt)")
class Pipeline(unittest.TestCase):
    def test_all_modes(self):
        from ml.dga import pipeline

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data.build_smoke(root / "data", per_family=100, benign=1000)
            with contextlib.redirect_stdout(io.StringIO()):
                pipeline.main(["--mode", "all", "--data", str(root / "data"), "--out", str(root / "runs"),
                               "--folds", "3", "--bootstrap", "50", "--bootstrap-curve", "5",
                               "--cutoff", "2022-01-01", "--threads", "2", "--features", "A", "A,B,C,D,E,F",
                               "--models", "lgbm,rf,entropy,blocklist"])
            for groups in ("f-A", "f-ABCDEF"):
                for mode in pipeline.MODES:
                    info = json.loads((root / "runs" / "main" / groups / mode / f"run_info_{mode}.json").read_text())
                    self.assertEqual(info["mode"], mode)
            runs = root / "runs" / "main" / "f-ABCDEF"
            cv = json.loads((runs / "cv" / "metrics.json").read_text())
            self.assertGreater(cv["models"]["lgbm"]["roc_auc"]["value"], 0.95)  # smoke data is easy
            self.assertIn("lgbm vs rf", cv["mcnemar"])
            for figure in ("cv/F8_roc_pr.png", "lofo/F9_lofo_recall.png", "cv/T4_model_comparison.md",
                           "final/dga_lgbm.txt", "final/features.json", "final/model.json"):
                self.assertTrue((runs / figure).exists(), figure)
            leaderboard = subprocess.run([sys.executable, "-m", "ml.dga.leaderboard", str(root / "runs")],
                                         capture_output=True, text=True)
            self.assertEqual(leaderboard.returncode, 0, leaderboard.stderr)
            self.assertIn("| main | ABCDEF | stable | lgbm |", (root / "runs" / "leaderboard.md").read_text())


@unittest.skipIf(lightgbm is None, "needs lightgbm, scikit-learn and matplotlib (ml/requirements.txt)")
class Tuning(unittest.TestCase):
    def test_family_weights_even_out_families(self):
        import numpy as np

        from ml.dga import pipeline

        family = np.array(["benign"] * 4 + ["big"] * 6 + ["small"] * 2, dtype=object)
        y = np.array([0] * 4 + [1] * 8, dtype=np.int8)
        data = type("D", (), {"family": family, "y": y})()
        rows = np.arange(12)
        self.assertIsNone(pipeline.family_weights(data, rows, 0.0))
        w = pipeline.family_weights(data, rows, 1.0)
        self.assertTrue(np.all(w[:4] == 1))
        self.assertAlmostEqual(w[4:10].sum(), w[10:].sum())  # equal total weight per family
        self.assertAlmostEqual(w[4:].sum(), 8)               # DGA total unchanged

    def test_tune_then_use_the_settings(self):
        try:
            import optuna  # noqa: F401
        except ImportError:
            self.skipTest("needs optuna (ml/requirements.txt)")
        from ml.dga import pipeline

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data.build_smoke(root / "data", per_family=60, benign=600)
            with contextlib.redirect_stdout(io.StringIO()):
                pipeline.main(["--mode", "tune", "--data", str(root / "data"), "--out", str(root / "runs"),
                               "--models", "lgbm", "--trials", "3", "--threads", "2"])
                best = root / "runs" / "main" / "f-ABCDE" / "tune" / "best_params.json"
                self.assertIn("lgbm", json.loads(best.read_text()))
                pipeline.main(["--mode", "dictionary", "--data", str(root / "data"), "--out", str(root / "runs"),
                               "--models", "lgbm", "--params", str(best), "--bootstrap", "20",
                               "--bootstrap-curve", "5", "--threads", "2"])
            info = json.loads((root / "runs" / "main" / "f-ABCDE" / "dictionary" / "run_info_dictionary.json")
                              .read_text())
            self.assertEqual(info["params"]["lgbm"], json.loads(best.read_text())["lgbm"])


if __name__ == "__main__":
    unittest.main()
