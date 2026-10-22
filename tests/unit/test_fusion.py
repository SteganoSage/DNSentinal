import unittest

from analyzer.fusion import combine_scores, nxdomain_signal_score


class FusionTests(unittest.TestCase):
    def test_nxdomain_score_requires_both_volume_and_ratio(self):
        self.assertEqual(nxdomain_signal_score(2, 1.0, 60, 10), 0.2)
        self.assertEqual(nxdomain_signal_score(10, 0.5, 60, 10), 0.5)

    def test_combined_score_is_weighted_and_explainable(self):
        verdict = combine_scores(1.0, 0.75, 0.5)
        self.assertAlmostEqual(verdict.score, 0.8)
        self.assertEqual(verdict.label, "medium")
        self.assertEqual(
            verdict.reasons,
            ("DGA-like domain activity", "tunnel-like query behavior"),
        )

    def test_invalid_signal_is_rejected(self):
        with self.assertRaises(ValueError):
            combine_scores(1.1, 0.0, 0.0)


if __name__ == "__main__":
    unittest.main()
