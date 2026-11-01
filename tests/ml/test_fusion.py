"""Score fusion (analyzer/fusion.py): the decision table, row by row."""

import unittest

from analyzer.fusion import FusionPolicy, Signals, fuse

POLICY = FusionPolicy(dga_threshold=0.95)


def risk(**signals):
    result = fuse(Signals(**signals), POLICY)
    return result.level, result.kind


class Fusion(unittest.TestCase):
    def test_a_tunnel_alert_is_high_on_its_own(self):
        self.assertEqual(risk(tunnel_alert=True), ("high", "tunnel"))  # not diluted by the signals that are quiet
        self.assertEqual(risk(tunnel_score=0.99), ("low", ""))  # one high window: the alert rule decides, not fusion

    def test_a_flagged_domain_that_resolves_in_a_burst_is_the_command_server(self):
        self.assertEqual(risk(dga=0.97, resolved=True, burst=True), ("high", "dga_c2"))
        self.assertEqual(risk(dga=0.97, resolved=True), ("low", ""))  # the resolver reports every flagged name itself
        self.assertEqual(risk(dga=0.97, burst=True), ("low", ""))  # failed: one of the many tries, the burst alert's
        self.assertEqual(risk(dga=0.9, resolved=True, burst=True), ("low", ""))  # below the classifier's threshold
        self.assertEqual(risk(resolved=True, burst=True), ("low", ""))  # never scored: a popular site
        self.assertEqual(risk(burst=True), ("low", ""))  # client-wide: reported as a burst, not per domain

    def test_the_verdict_explains_itself(self):
        c2 = fuse(Signals(dga=0.99, resolved=True, burst=True), POLICY)
        self.assertEqual(c2.reasons[0], "a generated-looking domain (DGA score 0.990) that resolved")
        self.assertIn("likely the live command server", c2.reasons[1])
        self.assertEqual(c2.as_dict()["signals"], {"tunnel_alert": False, "tunnel_score": None, "dga": 0.99,
                                                   "burst": True, "resolved": True})

    def test_a_bad_threshold_is_refused(self):
        for bad in (0.0, 1.0, 1.5):
            with self.assertRaises(ValueError):
                FusionPolicy(dga_threshold=bad)


if __name__ == "__main__":
    unittest.main()
