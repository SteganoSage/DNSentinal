import unittest

from ml.dga.features import NgramModel, extract_features, registrable_domain


class DgaFeatureTests(unittest.TestCase):
    def test_registrable_domain_handles_common_multi_label_suffix(self):
        self.assertEqual(registrable_domain("x7.example.co.uk."), "example.co.uk")

    def test_registrable_domain_rejects_invalid_input(self):
        with self.assertRaises(ValueError):
            registrable_domain("bad..example.com")

    def test_features_are_stable_and_numeric(self):
        features = extract_features("login.example.com")
        self.assertEqual(features.label_length, len("example"))
        self.assertEqual(len(features.vector()), len(features.names()))
        self.assertTrue(all(isinstance(value, float) for value in features.vector()))

    def test_ngram_likelihood_is_available(self):
        model = NgramModel().fit(["google.com", "example.com", "python.org"])
        self.assertLess(extract_features("google.com", model).ngram_log_likelihood, 0)


if __name__ == "__main__":
    unittest.main()
