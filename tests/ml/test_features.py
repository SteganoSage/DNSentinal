"""Features are computed on the registrable label, and the fitted models only
know what they were fitted on."""

import unittest

from ml.dga.features import (FEATURE_GROUPS, DomainFeatures, FeatureContext, NgramModel, TldPrior, WordList,
                             default_words, extract_features, normalise, split_name)


class RegistrableLabel(unittest.TestCase):
    def test_the_label_left_of_the_public_suffix(self):
        self.assertEqual(split_name("x7kq2.example.co.uk."), ("example", "co.uk"))
        self.assertEqual(split_name("WWW.Example.COM"), ("example", "com"))

    def test_dynamic_dns_names_score_the_generated_part(self):
        # The old two-suffix fallback scored "ddns" for every one of these.
        self.assertEqual(split_name("cvyh1po636avyrsxebwbkn7.ddns.net")[0], "cvyh1po636avyrsxebwbkn7")

    def test_a_bare_public_suffix_still_gets_a_label(self):
        self.assertEqual(split_name("blogspot.com.br")[0], "blogspot")

    def test_invalid_names_are_rejected(self):
        for bad in ["bad..example.com", "", "-", "a" * 64 + ".com", "spaces in.com"]:
            with self.assertRaises(ValueError, msg=bad):
                normalise(bad)


class Features(unittest.TestCase):
    def test_vector_is_stable_and_numeric(self):
        features = extract_features("login.example.com")
        self.assertEqual(features.label_length, len("example"))
        self.assertEqual(len(features.vector()), len(DomainFeatures.names()))
        self.assertTrue(all(isinstance(value, float) for value in features.vector()))
        for fitted in FEATURE_GROUPS["B"] + FEATURE_GROUPS["E"]:  # no models given: zero
            self.assertEqual(getattr(features, fitted), 0.0, fitted)

    def test_groups_cover_every_feature_once(self):
        self.assertEqual(sum(FEATURE_GROUPS.values(), []), DomainFeatures.names())

    def test_random_label_looks_random(self):
        word = extract_features("examples.com")
        noise = extract_features("xkqzvtrwpl8m.com")
        self.assertGreater(noise.entropy, word.entropy)
        self.assertGreater(noise.longest_consonant_run, word.longest_consonant_run)
        self.assertLess(noise.vowel_ratio, word.vowel_ratio)

    def test_structure(self):
        f = extract_features("a3kvau184uea-x.com")
        self.assertEqual((f.letter_digit_switches, f.hyphens, f.longest_digit_run, f.is_idn), (4, 1, 3, 0))
        self.assertEqual(extract_features("xn--o3cdo0fyd3b.net").is_idn, 1)

    def test_words(self):
        context = FeatureContext(words=WordList(["plastic", "bags", "bag", "river"]))
        words = extract_features("plasticbags.com", context)
        self.assertEqual((words.word_coverage, words.longest_word), (1.0, 7))
        self.assertEqual(extract_features("xkqzvtrw.com", context).word_coverage, 0.0)

    def test_committed_word_list(self):
        words = default_words()
        self.assertGreater(len(words), 40000)
        self.assertEqual(words.cover("travelinsurance")[0], len("travelinsurance"))

    def test_allowlisted_label(self):
        context = FeatureContext(allow_labels=frozenset({"google"}))
        self.assertEqual(extract_features("google.de", context).label_in_allowlist, 1)
        self.assertEqual(extract_features("gooogle.de", context).label_in_allowlist, 0)


class FittedModels(unittest.TestCase):
    def test_ngram_model_prefers_what_it_was_fitted_on(self):
        model = NgramModel().fit(["google", "example", "python", "facebook", "wikipedia"])
        context = FeatureContext(ngram=model)
        benign = extract_features("example.org", context).ngram_log_likelihood
        random = extract_features("qxzjvk.org", context).ngram_log_likelihood
        self.assertLess(benign, 0)
        self.assertGreater(benign, random)

    def test_ngram_model_needs_data(self):
        with self.assertRaises(ValueError):
            NgramModel().fit([])

    def test_leave_one_out_scores_a_training_label_as_if_unseen(self):
        others = ["example", "jukebox", "quiz", "vivid"]  # every letter of zqxjvk, so the alphabet stays the same
        model = NgramModel().fit(others + ["zqxjvk"])
        unseen = NgramModel().fit(others)
        self.assertGreater(model.score("zqxjvk"), model.score("zqxjvk", exclude_self=True))
        self.assertAlmostEqual(model.score("zqxjvk", exclude_self=True), unseen.score("zqxjvk"), places=10)

    def test_dga_likelihood_ratio(self):
        context = FeatureContext(ngram=NgramModel().fit(["example", "google", "python"]),
                                 dga_ngram=NgramModel().fit(["xkqzvt", "qzvxkt", "zvqxtk"]))
        self.assertGreater(extract_features("examp.com", context).dga_likelihood_ratio,
                           extract_features("qzxkvt.com", context).dga_likelihood_ratio)

    def test_saved_models_score_the_same(self):
        ngram = NgramModel().fit(["example", "google"])
        prior = TldPrior().fit(["com", "com", "co.uk"])
        self.assertEqual(NgramModel.from_state(ngram.state()).score("exam"), ngram.score("exam"))
        self.assertEqual(TldPrior.from_state(prior.state()).score("biz"), prior.score("biz"))

    def test_rare_tlds_score_lower(self):
        prior = TldPrior().fit(["com"] * 90 + ["co.uk"] * 9 + ["kz"])
        self.assertGreater(prior.score("com"), prior.score("uk"))  # co.uk counts as .uk
        self.assertGreater(prior.score("kz"), prior.score("biz"))  # never seen: lowest
        context = FeatureContext(tld_prior=prior)
        self.assertLess(extract_features("x.example.kz", context).tld_log_share,
                        extract_features("example.com", context).tld_log_share)


if __name__ == "__main__":
    unittest.main()
