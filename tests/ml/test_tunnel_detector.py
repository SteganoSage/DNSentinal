"""The tunnel detector: names, features, the sliding windows and the NXDOMAIN-burst signal."""

import json
import tempfile
import unittest
from pathlib import Path

from analyzer.detectors.tunnel import (
    FEATURE_GROUPS,
    DnsEvent,
    NxdomainBurstDetector,
    SlidingWindowDetector,
    TunnelFeatures,
    extract_features,
    labels_of,
    registrable_domain,
    score_features,
    windows,
)
from analyzer.tunnel_analyzer import analyze


class Names(unittest.TestCase):
    def test_registrable_domain_uses_the_public_suffix_list(self):
        self.assertEqual(registrable_domain("a.b.example.co.uk"), "example.co.uk")
        self.assertEqual(registrable_domain("x7k2.ddns.net"), "x7k2.ddns.net")  # a private suffix
        self.assertEqual(registrable_domain("co.uk"), "co.uk")
        self.assertEqual(registrable_domain("WWW.Example.COM."), "example.com")

    def test_encoded_labels_are_decoded_not_sanitised(self):
        self.assertEqual(registrable_domain("rb\\217h.\\193\\.x.www.ggy666.tk"), "ggy666.tk")
        self.assertEqual(labels_of("ab\\255.c\\.d.example.com"), [b"ab\xff", b"c.d", b"example", b"com"])
        self.assertEqual(registrable_domain("AAAAAH7wQA.=auth.dns2tcp.hsc.fr"), "hsc.fr")


class Features(unittest.TestCase):
    def test_groups_cover_every_feature_once(self):
        self.assertEqual([n for g in FEATURE_GROUPS.values() for n in g], TunnelFeatures.names())

    def test_unique_high_entropy_queries_look_like_a_tunnel(self):
        events = [DnsEvent(i * 1.0, "client-1", f"{'a1b2c3d4e5f6' * 3}{i}.tunnel.example", "TXT", "NXDOMAIN", 300)
                  for i in range(40)]
        features = extract_features(events)
        self.assertEqual(features.query_count, 40)
        self.assertEqual(features.unique_subdomain_count, 40)
        self.assertGreater(features.mean_subdomain_length, 36)
        self.assertGreater(features.mean_subdomain_entropy, 3.0)
        self.assertEqual(features.data_type_ratio, 1.0)
        self.assertEqual(features.nxdomain_ratio, 1.0)
        verdict = score_features(features)
        self.assertGreaterEqual(verdict.score, 0.75)
        self.assertEqual(verdict.label, "high")

    def test_timing(self):
        events = [DnsEvent(10.0, "c", "aa.example.com", rcode="3"),
                  DnsEvent(12.0, "c", "bbb.example.com"),
                  DnsEvent(16.0, "c", "cccc.example.com", rcode="NXDOMAIN")]
        features = extract_features(events)
        self.assertEqual(features.active_seconds, 6.0)
        self.assertAlmostEqual(features.mean_interval, 3.0)
        self.assertAlmostEqual(features.interval_cv, 1 / 3)  # gaps 2 and 4: std 1, mean 3
        self.assertAlmostEqual(features.nxdomain_ratio, 2 / 3)
        self.assertAlmostEqual(features.mean_subdomain_length, 3.0)

    def test_lengths_count_wire_bytes_not_escapes(self):
        features = extract_features([DnsEvent(0.0, "c", "\\255\\000x.example.com")])
        self.assertEqual(features.mean_subdomain_length, 3)
        self.assertEqual(features.unusual_character_ratio, 2 / 3)

    def test_unanswered_queries_do_not_count_as_empty_responses(self):
        events = [DnsEvent(0.0, "c", "a.example.com", response_size=100),
                  DnsEvent(1.0, "c", "b.example.com", rcode="NONE")]
        self.assertEqual(extract_features(events).mean_response_size, 100)

    def test_repeated_normal_queries_score_low(self):
        events = [DnsEvent(i * 5.0, "c", "www.example.com", "A", "NOERROR", 80) for i in range(12)]
        verdict = score_features(extract_features(events))
        self.assertEqual((verdict.label, verdict.score), ("low", 0.0))


class Windows(unittest.TestCase):
    def test_windows_end_on_the_grid_and_hold_the_last_minute(self):
        events = [DnsEvent(float(t), "c", f"x{t}.example.com") for t in range(3, 125)]
        found = windows(events, 60, 10)
        self.assertEqual([w.end for w in found][:3], [10.0, 20.0, 30.0])
        self.assertEqual(found[0].features.query_count, 8)  # 3..10
        late = next(w for w in found if w.end == 100.0)
        self.assertEqual(late.features.query_count, 60)  # (40, 100]
        self.assertEqual(found[-1].end, 130.0)  # the rest, at the end of input

    def test_quiet_keys_are_not_judged_again_and_are_forgotten(self):
        detector = SlidingWindowDetector(60, 10, scorer=None)
        out = detector.add(DnsEvent(1.0, "c", "a.quiet.example"))
        out += detector.add(DnsEvent(500.0, "c", "b.other.example"))
        self.assertEqual([(w.domain, w.end) for w in out], [("quiet.example", 10.0)])
        self.assertEqual(list(detector._keys), [("c", "other.example")])

    def test_keys_are_client_and_registrable_domain(self):
        events = [DnsEvent(1.0, "a", "x.example.com"), DnsEvent(2.0, "b", "y.example.com"),
                  DnsEvent(3.0, "a", "z.www.example.com"), DnsEvent(4.0, "a", "other.org")]
        found = windows(events)
        self.assertEqual(sorted((w.client_id, w.domain, w.features.query_count) for w in found),
                         [("a", "example.com", 2), ("a", "other.org", 1), ("b", "example.com", 1)])

    def test_online_and_offline_agree(self):
        events = [DnsEvent(i * 0.7, f"c{i % 3}", f"q{i}.d{i % 5}.example") for i in range(400)]
        detector = SlidingWindowDetector(30, 5, scorer=None)
        online = [w for e in events for w in detector.add(e)] + detector.flush()
        self.assertEqual([(w.client_id, w.domain, w.end, w.features) for w in online],
                         [(w.client_id, w.domain, w.end, w.features) for w in windows(events, 30, 5)])

    def test_flush_waits_for_the_window_end(self):
        detector = SlidingWindowDetector(60, 10)
        detector.add(DnsEvent(1.0, "c", "a.example.com"))
        self.assertEqual(detector.flush(9.0), [])
        self.assertEqual(len(detector.flush(11.0)), 1)

    def test_event_mapping(self):
        event = DnsEvent.from_mapping({"timestamp": "1.5", "client_ip": "192.0.2.1", "qname": "www.example.com",
                                       "rcode": 3})
        self.assertEqual((event.timestamp, event.client_id, event.rcode), (1.5, "192.0.2.1", "3"))
        with self.assertRaises(ValueError):
            DnsEvent.from_mapping({"timestamp": 1, "qname": "x.com"})

    def test_analyzer_reads_jsonl(self):
        lines = [json.dumps({"timestamp": 1000 + i, "client_ip": "10.0.0.5", "qname": f"{'ab12cd34' * 4}{i}.t.example",
                             "qtype": "TXT", "rcode": "NOERROR", "response_size": 250}) for i in range(60)]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            path.write_text("\n".join(lines) + "\n")
            results = analyze(path)
        tunnel = [r for r in results if r["signal"] == "tunnel"]
        self.assertEqual(tunnel[-1]["registrable_domain"], "t.example")
        self.assertEqual(tunnel[-1]["verdict"]["label"], "high")


class NxdomainBursts(unittest.TestCase):
    def test_bursts_are_client_wide_and_thresholded(self):
        detector = NxdomainBurstDetector(window_seconds=10, step_seconds=5, min_count=3, min_ratio=0.5)
        events = [DnsEvent(0, "client-1", "a.one.example", rcode="NXDOMAIN"),
                  DnsEvent(2, "client-1", "b.two.example", rcode="3"),
                  DnsEvent(4, "client-1", "www.three.example", rcode="NOERROR"),
                  DnsEvent(10, "client-1", "c.four.example", rcode="NXDOMAIN")]
        bursts = [b for e in events for b in detector.add(e)]
        self.assertEqual(len(bursts), 1)
        self.assertEqual((bursts[0].nxdomain_count, bursts[0].query_count), (3, 4))
        self.assertTrue(bursts[0].alert)

    def test_old_events_expire(self):
        detector = NxdomainBurstDetector(window_seconds=10, step_seconds=5, min_count=2, min_ratio=0.5)
        events = [DnsEvent(0, "client-1", "a.example", rcode="NXDOMAIN"),
                  DnsEvent(1, "client-1", "b.example", rcode="NXDOMAIN"),
                  DnsEvent(11, "client-1", "www.example", rcode="NOERROR"),
                  DnsEvent(16, "client-1", "www.example", rcode="NOERROR")]
        bursts = [b for e in events for b in detector.add(e)]
        self.assertEqual(bursts[-1].nxdomain_count, 0)
        self.assertFalse(bursts[-1].alert)


if __name__ == "__main__":
    unittest.main()
