"""The metrics match scikit-learn's, and the bootstrap intervals hold the value."""

import unittest

import numpy as np

from ml.dga.metrics import Curve, evaluate, mcnemar, threshold_at_fpr

try:
    from sklearn.metrics import average_precision_score, roc_auc_score, roc_curve
except ImportError:
    roc_auc_score = None


class CurveMetrics(unittest.TestCase):
    def setUp(self):
        rng = np.random.default_rng(1)
        self.y = rng.random(5000) < 0.2
        self.score = np.round(rng.normal(self.y * 1.5, 1.0), 2)  # rounded: plenty of ties

    @unittest.skipIf(roc_auc_score is None, "scikit-learn is not installed")
    def test_same_as_scikit_learn(self):
        roc_auc, pr_auc, at_target, at_1pct = Curve(self.y, self.score).summary(0.01)
        self.assertAlmostEqual(roc_auc, roc_auc_score(self.y, self.score), places=10)
        self.assertAlmostEqual(pr_auc, average_precision_score(self.y, self.score), places=10)
        # drop_intermediate=False: by default it can drop the very point that answers this
        fpr, tpr, _ = roc_curve(self.y, self.score, drop_intermediate=False)
        self.assertAlmostEqual(at_target, tpr[fpr <= 0.01].max(), places=10)
        self.assertEqual(at_target, at_1pct)

    def test_unit_weights_change_nothing(self):
        curve = Curve(self.y, self.score)
        self.assertEqual(curve.summary(0.001), curve.summary(0.001, np.ones(len(self.y))))

    def test_intervals_hold_the_value(self):
        result = evaluate(self.y, self.score, self.score > 1.0, np.where(self.y, "fam", "benign"), 0.01,
                          np.random.default_rng(2), n_boot=200, n_boot_curve=50)
        for key in ("recall", "fpr", "precision", "roc_auc", "pr_auc"):
            low, high = result[key]["ci95"]
            self.assertLessEqual(low, result[key]["value"], key)
            self.assertGreaterEqual(high, result[key]["value"], key)
        self.assertEqual(result["families"]["fam"]["rows"], int(self.y.sum()))


class Threshold(unittest.TestCase):
    def test_flags_at_most_the_target_share(self):
        benign = np.arange(10000) / 10000
        threshold = threshold_at_fpr(benign, 0.001)
        self.assertLessEqual((benign > threshold).sum(), 10)
        self.assertGreaterEqual((benign > threshold).sum(), 9)


class McNemar(unittest.TestCase):
    def test_no_disagreement(self):
        same = np.array([True, False, True])
        self.assertEqual(mcnemar(same, same)["p_value"], 1.0)

    def test_exact_for_few_disagreements(self):
        a = np.array([True] * 10 + [False] * 2)
        b = np.array([False] * 10 + [True] * 2)
        result = mcnemar(a, b)
        self.assertEqual(result["test"], "exact")
        self.assertAlmostEqual(result["p_value"], 2 * (1 + 12 + 66) / 2**12)

    def test_chi_squared_for_many(self):
        a = np.r_[np.ones(60, bool), np.zeros(40, bool)]
        result = mcnemar(a, ~a)
        self.assertEqual(result["test"], "chi2")
        self.assertAlmostEqual(result["statistic"], 19**2 / 100)


if __name__ == "__main__":
    unittest.main()
