import unittest

from analyzer.detectors.tunnel import (
    DnsEvent,
    NxdomainBurstDetector,
    SlidingWindowDetector,
    extract_features,
    score_features,
)


class TunnelDetectorTests(unittest.TestCase):
    def test_features_capture_unique_high_entropy_queries(self):
        events = [
            DnsEvent(i * 1.0, "client-1", f"{'a1b2c3d4e5f6' * 3}{i}.tunnel.example", "TXT", "NXDOMAIN", 300)
            for i in range(40)
        ]
        features = extract_features(events)
        self.assertEqual(features.query_count, 40)
        self.assertEqual(features.unique_subdomain_count, 40)
        self.assertGreater(features.mean_subdomain_length, 20)
        self.assertGreater(features.query_rate_per_second, 1.0)
        self.assertGreater(features.mean_query_name_length, 20)
        self.assertGreater(features.max_query_name_length, 20)
        self.assertGreater(features.mean_query_label_length, 10)
        self.assertGreater(features.mean_query_name_entropy, 3.0)
        self.assertGreater(score_features(features).score, 0.75)

    def test_behavioral_features_include_timing_and_nxdomain_ratio(self):
        events = [
            DnsEvent(10.0, "client-1", "aa.example.com", rcode="3"),
            DnsEvent(12.0, "client-1", "bbb.example.com", rcode="NOERROR"),
            DnsEvent(16.0, "client-1", "cccc.example.com", rcode="NXDOMAIN"),
        ]
        features = extract_features(events)
        self.assertEqual(features.query_count, 3)
        self.assertAlmostEqual(features.query_rate_per_second, 0.5)
        self.assertAlmostEqual(features.mean_interquery_seconds, 3.0)
        self.assertAlmostEqual(features.interquery_variance, 1.0)
        self.assertAlmostEqual(features.nxdomain_ratio, 2 / 3)

    def test_repeated_normal_queries_score_low(self):
        events = [
            DnsEvent(i * 5.0, "client-1", "www.example.com", "A", "NOERROR", 80)
            for i in range(12)
        ]
        verdict = score_features(extract_features(events))
        self.assertEqual(verdict.label, "low")
        self.assertEqual(verdict.score, 0.0)

    def test_sliding_detector_emits_after_window(self):
        detector = SlidingWindowDetector(window_seconds=10, step_seconds=5)
        results = []
        for i in range(13):
            results.extend(detector.add(DnsEvent(float(i), "client-1", f"x{i}.example.com")))
        self.assertGreaterEqual(len(results), 1)
        self.assertEqual(results[0][0:2], ("client-1", "example.com"))

    def test_event_mapping_accepts_client_ip(self):
        event = DnsEvent.from_mapping({
            "timestamp": 1,
            "client_ip": "192.0.2.1",
            "qname": "www.example.com",
            "rcode": 3,
        })
        self.assertEqual(event.client_id, "192.0.2.1")
        self.assertEqual(event.rcode, "3")

    def test_encoded_wire_label_is_accepted(self):
        event = DnsEvent(
            1.0,
            "client-1",
            "AAAAAH7wQA.=auth.dns2tcp.hsc.fr",
        )
        features = extract_features([event])
        self.assertEqual(features.query_count, 1)
        self.assertEqual(features.unique_subdomain_count, 1)

    def test_nxdomain_burst_is_client_wide_and_thresholded(self):
        detector = NxdomainBurstDetector(
            window_seconds=10, step_seconds=5, min_count=3, min_ratio=0.5
        )
        events = [
            DnsEvent(0, "client-1", "a.one.example", rcode="NXDOMAIN"),
            DnsEvent(2, "client-1", "b.two.example", rcode="3"),
            DnsEvent(4, "client-1", "www.three.example", rcode="NOERROR"),
            DnsEvent(10, "client-1", "c.four.example", rcode="NXDOMAIN"),
        ]
        bursts = []
        for event in events:
            bursts.extend(detector.add(event))
        self.assertEqual(len(bursts), 1)
        self.assertEqual(bursts[0].nxdomain_count, 3)
        self.assertEqual(bursts[0].query_count, 4)
        self.assertTrue(bursts[0].alert)

    def test_nxdomain_burst_expires_old_events(self):
        detector = NxdomainBurstDetector(
            window_seconds=10, step_seconds=5, min_count=2, min_ratio=0.5
        )
        events = [
            DnsEvent(0, "client-1", "a.example", rcode="NXDOMAIN"),
            DnsEvent(1, "client-1", "b.example", rcode="NXDOMAIN"),
            DnsEvent(11, "client-1", "www.example", rcode="NOERROR"),
            DnsEvent(16, "client-1", "www.example", rcode="NOERROR"),
        ]
        bursts = []
        for event in events:
            bursts.extend(detector.add(event))
        self.assertEqual(bursts[-1].nxdomain_count, 0)
        self.assertFalse(bursts[-1].alert)


if __name__ == "__main__":
    unittest.main()
