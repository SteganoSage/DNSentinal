"""The pipeline's whole-dataset n-gram scoring equals NgramModel's, one label at a time."""

import random
import string
import unittest

import numpy as np

from ml.dga.features import NgramModel
from ml.dga.grams import GramIndex


class SameAsReference(unittest.TestCase):
    def setUp(self):
        rng = random.Random(3)
        self.labels = ["".join(rng.choice(string.ascii_lowercase + "0123-") for _ in range(rng.randint(1, 18)))
                       for _ in range(800)]
        self.labels += self.labels[:20]  # repeated labels
        self.fit_rows = np.arange(0, len(self.labels), 3)

    def test_scores_and_saved_state(self):
        for n in (2, 3):
            fitted = GramIndex(self.labels, n).fit(self.fit_rows)
            reference = NgramModel(n).fit(self.labels[i] for i in self.fit_rows)
            members = set(self.fit_rows.tolist())
            expected = [reference.score(label, exclude_self=i in members) for i, label in enumerate(self.labels)]
            np.testing.assert_allclose(fitted.score(), expected, rtol=0, atol=1e-12)
            self.assertEqual(fitted.model().state(), reference.state())

    def test_needs_labels(self):
        with self.assertRaises(ValueError):
            GramIndex(self.labels, 3).fit(np.array([], dtype=int))


if __name__ == "__main__":
    unittest.main()
