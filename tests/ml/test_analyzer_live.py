"""The live slow path: events in from the resolver's stream, alerts and block rules out."""

import io
import json
import os
import random
import socket
import tempfile
import threading
import unittest

from analyzer.fusion import FusionPolicy
from analyzer.live import LiveAnalyzer, Stream, run

FUSION = FusionPolicy(dga_threshold=0.95)


def query(t, qname, client="192.168.1.23", qtype="TXT", rcode="NOERROR", size=250, action="answer"):
    return {"type": "query", "timestamp": t, "client": client, "transport": "udp", "qname": qname, "qtype": qtype,
            "rcode": rcode, "answers": 1, "response_size": size, "latency_us": 900, "action": action}


def tunnel(seconds=60, start=1000.0, client="192.168.1.23"):
    """A tunnel as the hand-written rules see it: many unique, long, encoded names in TXT queries."""
    return [query(start + i, f"{'ab12cd34' * 4}{i:04d}.t.tunnel.example", client) for i in range(seconds)]


class Decisions(unittest.TestCase):
    def feed_all(self, analyzer, records):
        alerts, commands = [], []
        for record in records:
            a, c = analyzer.feed(record)
            alerts += a
            commands += c
        a, c = analyzer.tick(now=records[-1]["timestamp"] + 30)
        return alerts + a, commands + c

    def test_monitor_mode_only_reports(self):
        analyzer = LiveAnalyzer(clock=lambda: 0.0)
        alerts, commands = self.feed_all(analyzer, tunnel())
        tunnel_alerts = [a for a in alerts if a["alert"] == "tunnel"]
        self.assertTrue(tunnel_alerts)
        self.assertEqual(commands, [])
        first = tunnel_alerts[0]
        self.assertEqual((first["client"], first["domain"], first["action"]), ("192.168.1.23", "tunnel.example", "alert"))
        self.assertIn("mostly unique subdomains", first["reasons"])

    def test_enforce_mode_asks_for_one_rule_for_that_client_and_renews_it_late(self):
        now = [0.0]
        analyzer = LiveAnalyzer(enforce=True, rule_ttl=600, clock=lambda: now[0])
        alerts, commands = self.feed_all(analyzer, tunnel())
        self.assertEqual(commands, [{"op": "add_rule", "domain": "tunnel.example", "client": "192.168.1.23",
                                     "ttl": 600, "reason": "tunnel", "score": commands[0]["score"],
                                     "source": "analyzer.live"}])
        actions = [a["action"] for a in alerts if a["alert"] == "tunnel"]
        self.assertEqual(actions[0], "block")
        self.assertTrue(all(a == "blocked already" for a in actions[1:]))
        now[0] = 400.0  # past half the rule's life: the next alert renews it
        _, again = self.feed_all(analyzer, tunnel(start=2000.0))
        self.assertEqual(len(again), 1)

    def test_normal_lookups_raise_nothing(self):
        analyzer = LiveAnalyzer(enforce=True, clock=lambda: 0.0)
        records = [query(1000.0 + 3 * i, "www.example.com", qtype="A", size=80) for i in range(40)]
        self.assertEqual(self.feed_all(analyzer, records), ([], []))

    def test_unanswered_queries_and_lost_events(self):
        analyzer = LiveAnalyzer(clock=lambda: 0.0)
        self.assertEqual(analyzer.feed(query(1.0, "x.example.com", action="refused")), ([], []))
        self.assertEqual(analyzer.counts["events"], 0)
        alerts, _ = analyzer.feed({"type": "dropped", "count": 12})
        self.assertEqual(alerts[0]["alert"], "events_lost")
        self.assertEqual(analyzer.counts["dropped"], 12)
        self.assertEqual(analyzer.feed({"type": "reply", "op": "ping", "ok": True}), ([], []))

    def test_an_nxdomain_burst_is_reported_once(self):
        analyzer = LiveAnalyzer(enforce=True, clock=lambda: 0.0)
        records = [query(1000.0 + i * 0.5, f"q{i}.example{i}.com", qtype="A", rcode="NXDOMAIN", size=90)
                   for i in range(200)]
        alerts, commands = self.feed_all(analyzer, records)
        bursts = [a for a in alerts if a["alert"] == "nxdomain_burst"]
        self.assertEqual(len(bursts), 1)
        self.assertEqual(bursts[0]["client_id"], "192.168.1.23")
        self.assertEqual(commands, [])  # client-wide, not about one domain: no rule


def dga_query(t, qname, score, rcode="NOERROR", answers=1, client="192.168.1.23"):
    return {**query(t, qname, client, qtype="A", rcode=rcode, size=90), "answers": answers, "dga": score}


def tries_then_server(start=1000.0, client="192.168.1.23"):
    """DGA malware: 20 generated names that don't exist, then the one that answers. Then it goes quiet."""
    rng = random.Random(5)
    tries = [dga_query(start + i * 0.5, "".join(rng.choice("bcdfghjklmnpqrstvwxz") for _ in range(12)) + ".info",
                       0.98, rcode="NXDOMAIN", answers=0, client=client) for i in range(20)]
    return tries + [dga_query(start + 10.5, "www.kqzvbnrtyxwe.info", 0.99, client=client)]


class FusedDecisions(unittest.TestCase):
    feed_all = Decisions.feed_all

    def test_the_command_server_found_in_a_burst_is_blocked_for_that_client(self):
        analyzer = LiveAnalyzer(enforce=True, rule_ttl=600, clock=lambda: 0.0, fusion=FUSION)
        alerts, commands = self.feed_all(analyzer, tries_then_server())
        c2 = [a for a in alerts if a["alert"] == "dga_c2"]
        self.assertEqual(len(c2), 1)
        self.assertEqual((c2[0]["domain"], c2[0]["action"], c2[0]["score"]), ("kqzvbnrtyxwe.info", "block", 0.99))
        self.assertTrue(c2[0]["risk"]["signals"]["burst"] and c2[0]["risk"]["signals"]["resolved"])
        self.assertIn("likely the live command server", c2[0]["reasons"][-1])
        self.assertEqual(commands, [{"op": "add_rule", "domain": "kqzvbnrtyxwe.info", "client": "192.168.1.23",
                                     "ttl": 600, "reason": "dga_c2", "score": 0.99, "source": "analyzer.live"}])
        # the client went quiet: its burst is still reported, once its window ends
        later, _ = analyzer.tick(now=1100.0)
        self.assertEqual([a["alert"] for a in later], ["nxdomain_burst"])
        self.assertEqual((analyzer.counts["dga_c2_alerts"], analyzer.counts["burst_alerts"]), (1, 1))

    def test_monitor_mode_reports_the_command_server(self):
        analyzer = LiveAnalyzer(clock=lambda: 0.0, fusion=FUSION)
        alerts, commands = self.feed_all(analyzer, tries_then_server())
        self.assertEqual([a["action"] for a in alerts if a["alert"] == "dga_c2"], ["alert"])
        self.assertEqual(commands, [])

    def test_a_flagged_domain_that_resolves_without_a_burst_raises_nothing_here(self):
        analyzer = LiveAnalyzer(enforce=True, clock=lambda: 0.0, fusion=FUSION)
        records = [dga_query(1000.0 + 20 * i, "www.kqzvbnrtyxwe.info", 0.99) for i in range(5)]
        self.assertEqual(self.feed_all(analyzer, records), ([], []))  # the resolver reports every flagged name itself

    def test_a_random_looking_domain_doesnt_hurry_the_tunnel_alert(self):
        def first_alert(score):
            analyzer = LiveAnalyzer(clock=lambda: 0.0, fusion=FUSION)
            records = [{**r, "dga": score} if score is not None else r for r in tunnel()]
            alerts, _ = self.feed_all(analyzer, records)
            return [a for a in alerts if a["alert"] == "tunnel"][0]["window_end"]

        self.assertEqual(first_alert(0.99), first_alert(None))  # the alert rule's two windows, either way


class PopularSites(unittest.TestCase):
    feed_all = Decisions.feed_all

    def test_popular_sites_and_cdn_names_are_never_alerted_on(self):
        from analyzer.live import read_allowlist

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "top.csv")
            with open(path, "w") as f:
                f.write("# rank,domain\n1,google.com\n2,Tunnel.Example.\n")
            allow = read_allowlist(__import__("pathlib").Path(path))
        self.assertEqual(allow, {"google.com", "tunnel.example"})
        analyzer = LiveAnalyzer(enforce=True, clock=lambda: 0.0, allowlist=allow)
        self.assertEqual(self.feed_all(analyzer, tunnel()), ([], []))  # wildcard DNS under a popular site
        self.assertGreater(analyzer.counts["popular_windows"], 0)
        cdn = [{**r, "qname": r["qname"].replace("t.tunnel.example", "d1bxh8uas1mnw7.cloudfront.net")}
               for r in tunnel()]
        self.assertEqual(self.feed_all(LiveAnalyzer(enforce=True, clock=lambda: 0.0), cdn), ([], []))
        dynamic = [{**r, "qname": r["qname"].replace("t.tunnel.example", "x7k2.ddns.net")} for r in tunnel()]
        alerts, _ = self.feed_all(LiveAnalyzer(clock=lambda: 0.0, allowlist=frozenset({"ddns.net"})), dynamic)
        self.assertEqual({a["domain"] for a in alerts if a["alert"] == "tunnel"}, {"x7k2.ddns.net"})  # still judged


class AgainstAResolver(unittest.TestCase):
    """The socket side, against a stand-in for the resolver's event stream."""

    def test_events_in_rules_out(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "events.sock")
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(path)
            server.listen(1)
            received, done = [], threading.Event()

            def resolver():
                conn, _ = server.accept()
                lines = "".join(json.dumps(r) + "\n" for r in tunnel()) + '{"type":"dropped","count":3}\n'
                conn.sendall(lines.encode())
                buffer = b""
                conn.settimeout(10)
                while b"\n" not in buffer:
                    buffer += conn.recv(4096)
                command = json.loads(buffer.split(b"\n")[0])
                received.append(command)
                reply = {"type": "reply", "op": "add_rule", "ok": True, "id": 1, "ttl": 600, "renewed": False}
                conn.sendall((json.dumps(reply) + "\n").encode())
                done.set()
                conn.close()

            thread = threading.Thread(target=resolver, daemon=True)
            thread.start()
            out, log = io.StringIO(), []
            analyzer = LiveAnalyzer(enforce=True, rule_ttl=600)
            run(Stream(path, retry=0.1, log=log.append), analyzer, out, log.append, stop=done.is_set)
            thread.join(5)
            server.close()
        self.assertEqual(received[0]["op"], "add_rule")
        self.assertEqual((received[0]["domain"], received[0]["client"]), ("tunnel.example", "192.168.1.23"))
        kinds = [json.loads(line)["alert"] for line in out.getvalue().splitlines()]
        self.assertIn("tunnel", kinds)
        self.assertIn("events_lost", kinds)
        self.assertTrue(any(line.startswith("connected to") for line in log))


if __name__ == "__main__":
    unittest.main()
