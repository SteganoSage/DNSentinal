#!/usr/bin/env python3
"""A DNS tunnel through the real daemon, caught by the trained model and blocked, end to end.

    ~/venvs/dnsentinel-ml/bin/python tests/integration/tunnel_e2e.py build/dnsentinel    # the shipped model
    python3 tests/integration/tunnel_e2e.py build/dnsentinel --rules-only                # no ML libraries (ctest)

It runs in a private network namespace, as offline_e2e.py does, with offline_e2e's fake
root and `lab.` servers. The `lab.` server also answers anything under tunnel.lab: TXT
queries get TXT records of hex data, as a tunnel's server sends.

The daemon streams its events to analyzer/live.py, in enforce mode with the trained model.
One client (127.0.0.10) tunnels: two TXT queries a second, fresh base32 names under
tunnel.lab. Another client (127.0.0.11) looks up ordinary names.

The checks:
- the tunnel is alerted on and blocked for its client only: NXDOMAIN, nothing sent upstream;
- the other client is never alerted on, and still resolves tunnel.lab names;
- /metrics and the query log record the blocking.

The shipped model needs the libraries of ml/requirements.txt (LightGBM); --rules-only
needs none: the hand-written rules judge alone, as without a model. Exit status:
0 if every check passed, 1 if one failed, 77 if it can't run here.
"""

import argparse
import base64
import json
import os
import random
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import offline_e2e as lab  # noqa: E402  the fake servers, the daemon runner, the checks

TUNNEL_CLIENT, OTHER_CLIENT = "127.0.0.10", "127.0.0.11"
TUNNEL_DOMAIN = "tunnel.lab"
METRICS = 9153
NXDOMAIN = 3

_plain_answer = lab.authoritative_answer


def answer_with_tunnel(zone, qname, qtype):
    """The `lab.` server, plus a tunnel's: every name under tunnel.lab exists; TXT gets hex data."""
    if zone.get("origin") == "lab" and lab.under(qname, TUNNEL_DOMAIN):
        if qtype == lab.TXT:
            data = random.Random(qname).randbytes(55).hex().encode()  # 110 characters, as dnscat2 answers
            return lab.NOERROR, True, [lab.encode_rr(qname, lab.TXT, bytes([len(data)]) + data, 0)], [], []
        return lab.NOERROR, True, [], [lab.soa_rr("lab")], []  # exists, no data: QNAME minimisation goes on
    return _plain_answer(zone, qname, qtype)


def ask_from(source, qname, qtype=lab.A, timeout=3):
    qid, query = lab.make_query(qname, qtype)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((source, 0))
        sock.settimeout(timeout)
        sock.sendto(query, lab.DAEMON)
        try:
            return lab.Response(sock.recv(65535))
        except socket.timeout:
            return None


def tunnel_name(rng):
    payload = base64.b32encode(rng.randbytes(25)).decode().rstrip("=").lower()  # 40 characters
    return f"{payload}.t.{TUNNEL_DOMAIN}"


def scrape():
    with urllib.request.urlopen(f"http://127.0.0.1:{METRICS}/metrics", timeout=3) as response:
        return response.read().decode()


def value(text, sample):
    for line in text.splitlines():
        if line.startswith(sample + " "):
            return float(line.rsplit(" ", 1)[1])
    return 0.0


class Analyzer:
    """analyzer/live.py as a process: its alerts (stdout) and its log (stderr), kept as they come."""

    def __init__(self, socket_path, model):
        command = [sys.executable, "-m", "analyzer.live", "--socket", socket_path, "--enforce", "--rule-ttl", "300"]
        if model:
            command += ["--model", str(model)]
        self.process = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                        env=dict(os.environ, PYTHONUNBUFFERED="1"))  # each alert as it comes
        self.alerts, self.log = [], []
        threading.Thread(target=self._read, args=(self.process.stdout, self.alerts, True), daemon=True).start()
        threading.Thread(target=self._read, args=(self.process.stderr, self.log, False), daemon=True).start()

    @staticmethod
    def _read(stream, into, parse):
        for line in stream:
            into.append((time.monotonic(), json.loads(line) if parse else line.rstrip()))

    def stop(self):
        self.process.send_signal(2)  # Ctrl-C: it prints its summary
        try:
            self.process.wait(10)
        except subprocess.TimeoutExpired:
            self.process.kill()
        time.sleep(0.2)


def reexec_in_netns():
    """This script again, as root of a new user + network namespace (offline_e2e's way)."""
    unshare = ["unshare", "--user", "--map-root-user", "--net"]
    if subprocess.run(unshare + ["true"], capture_output=True).returncode != 0:
        print("skipped: can't create a user + network namespace here")
        return lab.SKIP
    env = dict(os.environ, **{lab.IN_NETNS: "1"})
    return subprocess.run(unshare + [sys.executable, os.path.abspath(__file__), *sys.argv[1:]], env=env).returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("binary")
    parser.add_argument("--model", default=str(ROOT / "models" / "tunnel"), help="a model folder (default: the shipped one)")
    parser.add_argument("--rules-only", action="store_true", help="no model: the hand-written rules judge alone")
    parser.add_argument("--seconds", type=int, default=90, help="how long the tunnel runs at most")
    args = parser.parse_args()
    binary = os.path.abspath(args.binary)
    if args.rules_only:
        args.model = ""
    if os.environ.get(lab.IN_NETNS) != "1":
        return reexec_in_netns()
    if args.model:
        try:
            import lightgbm  # noqa: F401
        except ImportError:
            print("skipped: the shipped model needs lightgbm (run with the venv of ml/requirements.txt)")
            return lab.SKIP

    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    lab.authoritative_answer = answer_with_tunnel
    servers = lab.FakeServers()
    check = lab.check
    with tempfile.TemporaryDirectory() as tmp:
        sock = os.path.join(tmp, "run", "events.sock")
        logs = os.path.join(tmp, "querylog")
        telemetry = (f"  events:\n    socket: {sock}\n  prometheus:\n    addr: \"127.0.0.1:{METRICS}\"\n"
                     f"  query_log:\n    enabled: true\n    path: {logs}/queries.jsonl\n")
        daemon = lab.Daemon(binary, lab.write_config(tmp, telemetry=telemetry))
        analyzer = None
        try:
            check(daemon.wait_for("listening on udp", timeout=15) and daemon.wait_for("primed the root name servers"),
                  "the daemon starts and primes the root")
            analyzer = Analyzer(sock, args.model)
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and not any("connected to" in line for _, line in analyzer.log):
                time.sleep(0.1)
            check(any("connected to" in line for _, line in analyzer.log), "the analyzer connects to the event stream")

            r = ask_from(TUNNEL_CLIENT, tunnel_name(random.Random(0)), lab.TXT)
            check(r is not None and r.rcode == lab.NOERROR and r.answers, "a tunnel query resolves at first (TXT data)")

            rng, started, blocked_at, sent = random.Random(1), time.monotonic(), None, 0
            ordinary = ["www.example.lab", "alias.example.lab", "short.example.lab", "nothing.example.lab"]
            while time.monotonic() - started < args.seconds:
                for _ in range(2):  # two a second
                    r = ask_from(TUNNEL_CLIENT, tunnel_name(rng), lab.TXT)
                    sent += 1
                    if blocked_at is None and r is not None and r.rcode == NXDOMAIN:
                        blocked_at = time.monotonic()
                    time.sleep(0.5)
                if sent % 6 == 0:  # an ordinary lookup every 3 s from the other client
                    ask_from(OTHER_CLIENT, ordinary[(sent // 6) % len(ordinary)])
                if blocked_at is not None and time.monotonic() - blocked_at > 12:
                    break
            tunnel_alerts = [(t, a) for t, a in analyzer.alerts if a.get("alert") == "tunnel"]
            first = tunnel_alerts[0] if tunnel_alerts else None
            check(first is not None and first[1].get("client") == TUNNEL_CLIENT
                  and first[1].get("domain") == TUNNEL_DOMAIN,
                  f"the analyzer alerts on the tunnel, {first[0] - started:.0f} s in" if first else
                  "the analyzer alerts on the tunnel")
            check(first is not None and first[1].get("action") == "block", "...and, enforcing, asks for a rule")
            check(daemon.wait_for(f"dynamic rule added, rule 1: {TUNNEL_DOMAIN} and below for {TUNNEL_CLIENT}/32"),
                  "the daemon adds the rule for that client")
            check(blocked_at is not None, f"the tunnel's queries get NXDOMAIN from then on "
                                          f"({blocked_at - started:.0f} s in)" if blocked_at else
                  "the tunnel's queries get NXDOMAIN from then on")

            before = len(servers.seen)
            names = [tunnel_name(rng) for _ in range(5)]
            answers = [ask_from(TUNNEL_CLIENT, name, lab.TXT) for name in names]
            check(all(a is not None and a.rcode == NXDOMAIN for a in answers), "...every one")
            check(not any(lab.under(seen[1], TUNNEL_DOMAIN) for seen in servers.seen[before:]),
                  "...and none of them is sent upstream")
            other = ask_from(OTHER_CLIENT, tunnel_name(rng), lab.TXT)
            check(other is not None and other.rcode == lab.NOERROR and other.answers,
                  "the other client still resolves tunnel.lab: the rule is the tunnel client's")
            www = ask_from(TUNNEL_CLIENT, "www.example.lab")
            check(www is not None and www.rcode == lab.NOERROR, "...and the tunnel client resolves other names")
            check(not any(a.get("client") == OTHER_CLIENT for _, a in analyzer.alerts),
                  "the other client is never alerted on")

            text = scrape()
            check(value(text, "dnsentinel_dynamic_rules") == 1 and value(text, "dnsentinel_dynamic_rules_added_total") == 1,
                  "/metrics: one dynamic rule in force")
            check(value(text, 'dnsentinel_queries_total{transport="udp",qtype="TXT",rcode="NXDOMAIN",'
                              'action="dynamic_rule"}') >= 5, "/metrics: the queries it answered")
        finally:
            if analyzer:
                analyzer.stop()
            status = daemon.stop()
        check(status == 0, "the daemon shuts down cleanly")
        if analyzer:
            summary = [line for _, line in analyzer.log if "since startup" in line]
            check(bool(summary), "the analyzer sums up at exit" + (f": {summary[-1].split(': ', 1)[-1]}" if summary else ""))
        lines = [json.loads(line) for f in sorted(Path(logs).glob("queries-*.jsonl")) for line in open(f)]
        check(any(line["client"] == TUNNEL_CLIENT and line["action"] == "dynamic_rule" for line in lines),
              "the query log records the blocked queries, with the rule")
        if lab.failures:
            print("  daemon log:\n" + "\n".join("    " + line for line in daemon.log))
            if analyzer:
                print("  analyzer log:\n" + "\n".join("    " + line for _, line in analyzer.log))
    print(f"\n{len(lab.failures)} check(s) failed" if lab.failures else "\nall checks passed")
    return 1 if lab.failures else 0


if __name__ == "__main__":
    sys.exit(main())
