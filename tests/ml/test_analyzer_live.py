"""The live slow path: events in from the resolver's stream, alerts and block rules out."""

import io
import json
import os
import socket
import tempfile
import threading
import unittest

from analyzer.live import LiveAnalyzer, Stream, run


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
