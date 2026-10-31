"""Every tunnel pipeline mode runs end to end on the smoke dataset, and no capture leaks across a split."""

import argparse
import contextlib
import io
import json
import random
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import numpy as np

from ml.tunnel import data

try:
    import lightgbm  # noqa: F401
    import matplotlib  # noqa: F401
    import sklearn  # noqa: F401
except ImportError:
    lightgbm = None


@unittest.skipIf(lightgbm is None, "needs lightgbm, scikit-learn and matplotlib (ml/requirements.txt)")
class Pipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        data.build_smoke(cls.root / "data")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_all_modes_then_the_analyzer_runs_the_final_model(self):
        from analyzer.tunnel_analyzer import analyze
        from ml.tunnel import pipeline

        runs = self.root / "runs"
        with contextlib.redirect_stdout(io.StringIO()):
            pipeline.main(["--mode", "all", "--data", str(self.root / "data"), "--out", str(runs),
                           "--folds", "3", "--bootstrap", "20", "--bootstrap-curve", "5", "--threads", "2",
                           "--models", "lgbm,rf,iforest,qpm,rules"])
        for mode in pipeline.MODES:
            info = json.loads((runs / "main" / "w60-fVNR" / mode / f"run_info_{mode}.json").read_text())
            self.assertEqual(info["mode"], mode)
        base = runs / "main" / "w60-fVNR"
        rates = json.loads((base / "rates" / "metrics.json").read_text())
        self.assertEqual([r["slowdown"] for r in rates["models"]["lgbm"]["rates"]], [1, 2, 10, 100])
        for name in ("F10_recall_vs_rate.png", "F11_detection_delay.png", "T5_exfiltration.md"):
            self.assertTrue((base / "rates" / name).exists(), name)
        cv = json.loads((base / "cv" / "metrics.json").read_text())
        self.assertGreater(cv["models"]["lgbm"]["recall"]["value"], 0.9)
        self.assertIn("browsing", cv["models"]["lgbm"]["false_alerts"])
        self.assertIn("alerts_per_day_allowlisted", cv["models"]["lgbm"]["false_alerts"]["browsing"])
        self.assertIn("wildcard", cv["models"]["lgbm"]["false_alerts"])  # reported, though never trained on
        tool = json.loads((base / "tool" / "metrics.json").read_text())
        self.assertEqual(set(tool["models"]["lgbm"]["tool_recall"]), {"alpha", "bravo", "charlie"})

        lines = [json.dumps({"timestamp": 1000 + i * 0.5, "client_ip": "10.1.1.1",
                             "qname": f"{data._base32(random.Random(i), 40)}.t.evil-tunnel.test",
                             "qtype": "TXT", "response_size": 300}) for i in range(200)]
        events = self.root / "events.jsonl"
        events.write_text("\n".join(lines) + "\n")
        results = [r for r in analyze(events, model=base / "final") if r["signal"] == "tunnel"]
        self.assertTrue(results)
        self.assertTrue(all(r["verdict"]["label"] in ("high", "low") for r in results))
        self.assertEqual(results[-1]["verdict"]["label"], "high")

        from ml.tunnel import leaderboard

        with contextlib.redirect_stdout(io.StringIO()), mock.patch("sys.argv", ["leaderboard", str(runs)]):
            self.assertEqual(leaderboard.main(), 0)
        self.assertIn("lgbm", (runs / "leaderboard.md").read_text())

    def test_folds_spread_each_tool(self):
        from ml.tunnel.pipeline import _deal

        tools = {0: "dnspot", 1: "dns-shell", 2: "tuns", **{i: "iodine" for i in range(3, 20)}}
        folds = _deal(list(tools), 5, np.random.default_rng(0), tools.get)
        self.assertEqual(sorted(i for f in folds for i in f), list(tools))
        where = {i: k for k, f in enumerate(folds) for i in f}
        self.assertEqual(len({where[0], where[1], where[2]}), 3)  # single-capture tools: different folds
        self.assertTrue(all(any(tools[i] == "iodine" for i in f) for f in folds))

    def test_no_capture_is_on_both_sides_of_a_split(self):
        from ml.tunnel import pipeline

        args = argparse.Namespace(data=self.root / "data", out=self.root / "leak", cache=None, fraction=1.0, seed=42,
                                  step=10.0, train_slowdowns=[1, 2], test_slowdowns=[1, 10], threads=2, folds=3,
                                  calibration=0.1, benign_test=0.2, test_only={"wildcard"})
        with contextlib.redirect_stdout(io.StringIO()):
            captures, table = pipeline.load(args, 60.0)
        rows = pipeline.Rows(table)
        for mode in ("cv", "tool", "unknown", "rates", "final"):
            for split in pipeline.splits_for(mode, captures, rows, args):
                sides = [set(table.capture[part].tolist()) for part in (split.train, split.calibration, split.test)]
                self.assertFalse(sides[0] & sides[1] or sides[0] & sides[2] or sides[1] & sides[2], (mode, split.name))
                self.assertFalse(table.y[split.calibration].any())
                trained = {captures[c]["set"] for c in table.capture[np.r_[split.train, split.calibration]]}
                self.assertNotIn("wildcard", trained, (mode, split.name))
                if mode != "final":
                    self.assertTrue(table.y[split.test].any() and (~table.y[split.test]).any(), (mode, split.name))
                if mode == "rates":
                    self.assertEqual(set(np.unique(table.slowdown[split.test][table.y[split.test]])), {1.0, 10.0})
                if mode == "unknown":
                    tested = {captures[c]["set"] for c in table.capture[split.test] if captures[c]["label"] == "tunnel"}
                    self.assertEqual(tested, {"unknown", "android"})


if __name__ == "__main__":
    unittest.main()
