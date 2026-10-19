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


if __name__ == "__main__":
    unittest.main()
