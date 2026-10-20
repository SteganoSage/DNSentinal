"""The model the resolver ships (models/dga) loads and judges clear cases correctly."""

import unittest

try:
    import lightgbm  # noqa: F401
except ImportError:
    lightgbm = None


@unittest.skipIf(lightgbm is None, "needs lightgbm (ml/requirements.txt)")
class ShippedModel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from ml.dga.scorer import Scorer

        cls.scorer = Scorer()

    def test_one_input_per_feature(self):
        self.assertEqual(len(self.scorer.vector("example.com")), len(self.scorer.features))

    def test_popular_sites_pass(self):
        for name in ["google.com", "wikipedia.org", "github.io", "plasticbags.com", "travelinsurance.co.uk"]:
            self.assertFalse(self.scorer.is_dga(name), name)

    def test_generated_names_are_flagged(self):
        # sisron, murofet, necurs and zloader names from the dataset: scores above 0.99
        for name in ["mdexmtiwmjia.info", "vsknusavcbmhkfvkfeqhrpbdql.biz", "lcafyatwxd.sc",
                     "jiisjjqjiebothmrrpay.com"]:
            self.assertTrue(self.scorer.is_dga(name), name)


if __name__ == "__main__":
    unittest.main()
