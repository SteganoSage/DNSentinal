#!/usr/bin/env python3
"""Offline end-to-end test of the dnsentinel daemon.

Runs the real binary against a tiny DNS hierarchy served by this script: a
root server (127.0.0.2) and a server for `lab.` (127.0.0.3), over UDP and
TCP; like some real servers, they send at most 512 bytes over UDP and set TC
when an answer needs more. It all happens
in a private network namespace (`unshare -rn`), so the test needs neither
internet access nor root: inside the namespace it may bind port 53, and
nothing it sends can leave the machine. Use it where outbound DNS is blocked
(e.g. a college LAN); only experiment E1 needs the real internet.

    python3 tests/integration/offline_e2e.py build/dnsentinel

Exit status: 0 if every check passes, 1 if one fails, 77 if the test can't
run here (no unshare / ip, or unprivileged user namespaces are disabled, as
on stock Ubuntu 24.04). ctest runs it as `offline_e2e` and reports 77 as
skipped.
"""

import os
import queue
import selectors
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

IN_NETNS = "DNSENTINEL_E2E_IN_NETNS"
SKIP = 77

A, NS, CNAME, SOA, TXT, AAAA = 1, 2, 5, 6, 16, 28
CLASS_IN, CLASS_CH = 1, 3
NOERROR, SERVFAIL, NXDOMAIN, REFUSED = 0, 2, 3, 5

ROOT_IP, LAB_IP = "127.0.0.2", "127.0.0.3"
DEAD_IP = "127.0.0.9"  # delegated to, but nothing listens there
DAEMON = ("127.0.0.1", 5353)

# The hierarchy. Names are lower-case, without the trailing dot; "" is the root.
ZONES = {
    ROOT_IP: {
        "origin": "",
        "records": {("", NS): ["a.root-servers.test"], ("a.root-servers.test", A): [ROOT_IP]},
        "delegations": {"lab": ("ns.lab", LAB_IP), "dead": ("ns.dead", DEAD_IP)},
    },
    LAB_IP: {
        "origin": "lab",
        "records": {
            ("www.example.lab", A): ["192.0.2.1"],
            ("big.example.lab", A): [f"192.0.2.{i}" for i in range(1, 101)],  # ~1.6 KB: needs TCP
            ("slow.example.lab", A): ["192.0.2.7"],  # answered late: see SLOW_NAMES
            ("spoofed.example.lab", A): ["192.0.2.8"],  # raced by forged replies: see SPOOFED_NAMES
            ("collect.tracker.lab", A): ["192.0.2.66"],
            ("ns.lab", A): [LAB_IP],
        },
        "cnames": {"alias.example.lab": "www.example.lab",
                   "metrics.shop.lab": "collect.tracker.lab"},  # a tracker cloaked as a first-party name
    },
}

# Answered over UDP only after this delay, so identical queries pile up meanwhile.
# Kept under the resolver's 100 ms minimum timeout for a server it has measured as fast.
SLOW_NAMES, SLOW_DELAY = {"slow.example.lab"}, 0.05

# Over UDP, these get forged replies (wrong IDs) first, from the server's own
# address: what an off-path spoofer racing the real answer sends (plan §5.4).
SPOOFED_NAMES, FORGED_REPLIES = {"spoofed.example.lab"}, 5

# ─── Wire format ─────────────────────────────────────────────────────────────


def encode_name(name):
    return b"".join(bytes([len(label)]) + label.encode() for label in name.split(".") if label) + b"\0"


def encode_rr(name, rtype, rdata, ttl=300):
    return encode_name(name) + struct.pack(">HHIH", rtype, CLASS_IN, ttl, len(rdata)) + rdata


def rdata_for(rtype, value):
    return socket.inet_aton(value) if rtype == A else encode_name(value)


def soa_rr(origin):
    rdata = encode_name("ns." + origin) + encode_name("hostmaster." + origin)
    return encode_rr(origin, SOA, rdata + struct.pack(">IIIII", 1, 3600, 600, 86400, 300))


def read_name(buf, off):
    """Decode a possibly compressed name, keeping its case: (name, next offset)."""
    labels, resume = [], None
    for _ in range(128):
        length = buf[off]
        if length & 0xC0 == 0xC0:
            resume = off + 2 if resume is None else resume
            off = ((length & 0x3F) << 8) | buf[off + 1]
        elif length == 0:
            return ".".join(labels) + ".", off + 1 if resume is None else resume
        else:
            labels.append(buf[off + 1 : off + 1 + length].decode("ascii", "replace"))
            off += 1 + length
    raise ValueError("compression pointer loop")


class Response:
    """The parts of a DNS response the checks look at."""

    def __init__(self, buf):
        self.id, flags, qdcount, ancount, nscount, _ = struct.unpack(">HHHHHH", buf[:12])
        self.rcode = flags & 0x000F
        self.aa = bool(flags & 0x0400)
        self.tc = bool(flags & 0x0200)
        self.ra = bool(flags & 0x0080)
        off = 12
        self.questions = []  # names exactly as sent back
        for _ in range(qdcount):
            name, off = read_name(buf, off)
            self.questions.append(name)
            off += 4
        self.answers, self.authority = [], []  # (lower-case name, type, address / target name)
        for section, count in ((self.answers, ancount), (self.authority, nscount)):
            for _ in range(count):
                name, off = read_name(buf, off)
                rtype, _, _, rdlength = struct.unpack(">HHIH", buf[off : off + 10])
                off += 10
                if rtype == A:
                    data = socket.inet_ntoa(buf[off : off + rdlength])
                elif rtype == AAAA:
                    data = socket.inet_ntop(socket.AF_INET6, buf[off : off + rdlength])
                elif rtype in (NS, CNAME):
                    data = read_name(buf, off)[0]
                else:
                    data = None
                section.append((name.lower(), rtype, data))
                off += rdlength

    def types(self, section):
        return [rtype for _, rtype, _ in section]


def recv_exact(sock, count):
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise ConnectionError("connection closed early")
        data += chunk
    return data


def make_query(qname, qtype=A, qclass=CLASS_IN):
    """A query with a random ID, RD set and no EDNS: (id, bytes)."""
    qid = struct.unpack(">H", os.urandom(2))[0]
    return qid, struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + encode_name(qname) + struct.pack(">HH", qtype, qclass)


def ask(qname, qtype=A, qclass=CLASS_IN, tcp=False, timeout=5):
    """Send one query to the daemon and return its Response."""
    qid, query = make_query(qname, qtype, qclass)
    if tcp:
        with socket.create_connection(DAEMON, timeout=5) as sock:
            sock.sendall(struct.pack(">H", len(query)) + query)
            length = struct.unpack(">H", recv_exact(sock, 2))[0]
            response = Response(recv_exact(sock, length))
    else:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(query, DAEMON)
            response = Response(sock.recv(65535))
    response.id_matches = response.id == qid
    return response


def ask_many(qname, count):
    """Send `count` identical queries at once, each from its own socket, and
    return their Responses."""
    sent = []
    for _ in range(count):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        qid, query = make_query(qname)
        sock.sendto(query, DAEMON)
        sent.append((sock, qid))
    responses = []
    for sock, qid in sent:
        with sock:
            response = Response(sock.recv(65535))
        response.id_matches = response.id == qid
        responses.append(response)
    return responses


# ─── The fake authoritative servers ──────────────────────────────────────────


def under(name, zone):
    return zone == "" or name == zone or name.endswith("." + zone)


def authoritative_answer(zone, qname, qtype):
    """(rcode, aa, answer, authority, additional) for one query to `zone`'s server."""
    for child, (ns_name, ns_ip) in zone.get("delegations", {}).items():
        if under(qname, child):  # referral, with glue
            return (NOERROR, False, [], [encode_rr(child, NS, encode_name(ns_name), 3600)],
                    [encode_rr(ns_name, A, socket.inet_aton(ns_ip), 3600)])

    records, cnames = zone["records"], zone.get("cnames", {})
    answer, name = [], qname
    for _ in range(8):
        if (name, qtype) in records:
            values = records[(name, qtype)]
            answer += [encode_rr(name, qtype, rdata_for(qtype, v)) for v in values]
            glue = [encode_rr(v, A, rdata_for(A, ip)) for v in values if qtype == NS for ip in records.get((v, A), [])]
            return NOERROR, True, answer, [], glue
        if name not in cnames or qtype == CNAME:
            break
        answer.append(encode_rr(name, CNAME, encode_name(cnames[name])))
        name = cnames[name]

    exists = name in cnames or any(under(owner, name) for owner, _ in records)  # empty non-terminals exist
    return (NOERROR if exists else NXDOMAIN), True, answer, [soa_rr(zone["origin"])], []


class FakeServers:
    """ZONES served on port 53, UDP and TCP, from a background thread. Every
    query is recorded."""

    def __init__(self):
        self.seen = []      # (server address, lower-case qname, qtype)
        self.seen_tcp = []  # the ones that came over TCP
        self.selector = selectors.DefaultSelector()
        for ip in ZONES:
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.bind((ip, 53))
            self.selector.register(udp, selectors.EVENT_READ, (ip, "udp"))
            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp.bind((ip, 53))
            tcp.listen()
            self.selector.register(tcp, selectors.EVENT_READ, (ip, "tcp"))
        threading.Thread(target=self._serve, daemon=True).start()

    def queries_to(self, ip):
        return [q for q in self.seen if q[0] == ip]

    def _serve(self):
        while True:
            for key, _ in self.selector.select():
                server, transport = key.data
                try:
                    if transport == "udp":
                        data, peer = key.fileobj.recvfrom(4096)
                        reply = self._reply(server, data, tcp=False)
                        if self.seen[-1][1] in SPOOFED_NAMES:
                            qid = struct.unpack(">H", reply[:2])[0]
                            for i in range(FORGED_REPLIES):
                                key.fileobj.sendto(struct.pack(">H", (qid + 1 + i) & 0xFFFF) + reply[2:], peer)
                        if self.seen[-1][1] in SLOW_NAMES:
                            threading.Timer(SLOW_DELAY, key.fileobj.sendto, (reply, peer)).start()
                        else:
                            key.fileobj.sendto(reply, peer)
                    else:  # one query per connection is all the resolver sends
                        conn, _ = key.fileobj.accept()
                        with conn:
                            conn.settimeout(2)
                            length = struct.unpack(">H", recv_exact(conn, 2))[0]
                            reply = self._reply(server, recv_exact(conn, length), tcp=True)
                            conn.sendall(struct.pack(">H", len(reply)) + reply)
                except (OSError, IndexError, struct.error, UnicodeDecodeError):
                    continue  # a query we don't understand, or a client that went away

    def _reply(self, server, query, tcp):
        qid, flags = struct.unpack(">HH", query[:4])
        off, labels = 12, []
        while query[off]:
            labels.append(query[off + 1 : off + 1 + query[off]].decode("ascii").lower())
            off += 1 + query[off]
        qtype = struct.unpack(">H", query[off + 1 : off + 3])[0]
        qname = ".".join(labels)
        self.seen.append((server, qname, qtype))
        if tcp:
            self.seen_tcp.append((server, qname, qtype))

        rcode, aa, answer, authority, additional = authoritative_answer(ZONES[server], qname, qtype)
        flags = 0x8000 | (0x0400 if aa else 0) | (flags & 0x0100) | rcode
        header = struct.pack(">HHHHHH", qid, flags, 1, len(answer), len(authority), len(additional))
        question = query[12 : off + 5]  # echoed byte for byte, case included
        reply = header + question + b"".join(answer + authority + additional)
        if not tcp and len(reply) > 512:  # doesn't fit: just the question, with TC
            reply = struct.pack(">HHHHHH", qid, flags | 0x0200, 1, 0, 0, 0) + question
        return reply


# ─── The daemon ──────────────────────────────────────────────────────────────


class Daemon:
    """The dnsentinel binary, with its log collected while it runs."""

    def __init__(self, binary, config):
        self.proc = subprocess.Popen([binary, "-c", config], stderr=subprocess.PIPE, text=True)
        self.log = []
        self._lines = queue.Queue()
        self._ended = False
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for line in self.proc.stderr:
            self._lines.put(line.rstrip("\n"))
        self._lines.put(None)

    def wait_for(self, text, timeout=5.0):
        """True once a log line containing `text` appears; False on timeout or exit."""
        deadline = time.monotonic() + timeout
        while not self._ended and (left := deadline - time.monotonic()) > 0:
            try:
                line = self._lines.get(timeout=left)
            except queue.Empty:
                return False
            if line is None:
                self._ended = True
                return False
            self.log.append(line)
            if text in line:
                return True
        return False

    def stop(self):
        """Ctrl-C it; returns the exit status."""
        self.proc.send_signal(signal.SIGINT)
        try:
            status = self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            status = self.proc.wait()
        self.wait_for("\0", timeout=2)  # collect the rest of the log
        return status


def write_config(tmp, stub_zone=False, access=None, policy=None):
    """access: (allowed subnets, deny action), or None for the default (localhost).
    policy: the policy section's settings (indented YAML), or None for none."""
    hints = os.path.join(tmp, "lab.root")
    with open(hints, "w") as f:
        f.write(f".  NS  a.root-servers.test.\na.root-servers.test.  A  {ROOT_IP}\n")
    name = "stub" if stub_zone else f"access-{access[1]}" if access else "policy" if policy else "root"
    path = os.path.join(tmp, name + ".yaml")
    with open(path, "w") as f:
        f.write(f'listen:\n  udp: "{DAEMON[0]}:{DAEMON[1]}"\n')
        f.write(f"resolver:\n  root_hints: {hints}\n  overall_deadline_ms: 2000\n")
        if stub_zone:
            f.write(f'  stub_zones:\n    lab.: ["{LAB_IP}"]\n')
        if access:
            subnets = ", ".join(f'"{s}"' for s in access[0])
            f.write(f"access:\n  allow: [{subnets}]\n  deny_action: {access[1]}\n")
        if policy:
            f.write("policy:\n" + policy)
    return path


# ─── Checks ──────────────────────────────────────────────────────────────────

failures = []


def check(ok, what):
    print(("  ok    " if ok else "  FAIL  ") + what)
    if not ok:
        failures.append(what)


def run_daemon(binary, config, body):
    """Start the daemon, run `body(daemon)` against it, then check it shuts down cleanly."""
    daemon = Daemon(binary, config)
    failed_before = len(failures)
    try:
        check(daemon.wait_for("listening on udp"), "daemon starts listening")
        check(daemon.wait_for("primed the root name servers"), "root priming succeeds")
        body(daemon)
    finally:
        status = daemon.stop()
    check(status == 0 and "dnsentinel: shutting down" in daemon.log, "Ctrl-C shuts it down cleanly")
    if len(failures) > failed_before:
        print("  daemon log:\n" + "\n".join("    " + line for line in daemon.log))


def resolving_from_the_root(binary, servers, tmp):
    def body(daemon):
        check(servers.queries_to(ROOT_IP) == [(ROOT_IP, "", NS)], "priming asks the root for . NS")

        r = ask("www.example.lab")
        check(r.id_matches and r.ra and not r.aa, "response has the query's ID, RA set, AA clear")
        check(r.rcode == NOERROR and r.answers == [("www.example.lab.", A, "192.0.2.1")],
              "A record found via the root's referral to lab.")

        r = ask("alias.example.lab")
        check(r.types(r.answers) == [CNAME, A] and r.answers[-1][2] == "192.0.2.1", "CNAME chain followed")

        r = ask("nope.example.lab")
        check(r.rcode == NXDOMAIN and not r.answers and r.types(r.authority) == [SOA], "NXDOMAIN comes with the SOA")

        r = ask("www.example.lab", TXT)
        check(r.rcode == NOERROR and not r.answers and r.types(r.authority) == [SOA], "NODATA comes with the SOA")

        before = len(servers.seen)
        r = ask("WwW.ExAmPlE.LaB")
        check(r.answers[-1:] == [("www.example.lab.", A, "192.0.2.1")] and len(servers.seen) == before,
              "repeat query answered from the cache")
        check(r.questions == ["WwW.ExAmPlE.LaB."], "question echoed in the client's case")
        check(len(servers.queries_to(ROOT_IP)) == 2, "root asked only twice: priming, then the lab. referral")

        before = len(servers.seen)
        rs = ask_many("slow.example.lab", 10)
        check(all(r.id_matches and r.answers == [("slow.example.lab.", A, "192.0.2.7")] for r in rs),
              "10 identical queries in flight at once all get the answer")
        check(servers.seen[before:] == [(LAB_IP, "slow.example.lab", A)],
              "...from one upstream query (in-flight deduplication)")

        r = ask("spoofed.example.lab")
        check(r.rcode == NOERROR and r.answers == [("spoofed.example.lab.", A, "192.0.2.8")],
              "right answer while forged replies race it")
        check((LAB_IP, "spoofed.example.lab", A) in servers.seen_tcp,
              "...because the resolver switched that query to TCP")
        check(daemon.wait_for("possible spoofing"), "the daemon logs a spoofing alert")

        check(ask("www.dead").rcode == SERVFAIL, "unreachable name server gives SERVFAIL")

        before = len(servers.seen)
        r = ask("version.bind", TXT, CLASS_CH)
        check(r.rcode == REFUSED and len(servers.seen) == before, "CHAOS query refused without going upstream")

        r = ask("www.example.lab", tcp=True)
        check(r.id_matches and r.answers == [("www.example.lab.", A, "192.0.2.1")], "answers over TCP")

        r = ask("big.example.lab")
        check(r.rcode == NOERROR and r.tc and not r.answers, "answer too big for UDP comes back truncated (TC)")
        check((LAB_IP, "big.example.lab", A) in servers.seen_tcp,
              "upstream truncated it too, so the resolver asked again over TCP")
        r = ask("big.example.lab", tcp=True)
        check(not r.tc and len(r.answers) == 100, "the client's retry over TCP gets all 100 records")

    run_daemon(binary, write_config(tmp), body)


def resolving_a_stub_zone(binary, servers, tmp):
    servers.seen.clear()

    def body(daemon):
        r = ask("www.example.lab")
        check(r.rcode == NOERROR and r.answers == [("www.example.lab.", A, "192.0.2.1")], "A record found")
        check(servers.queries_to(ROOT_IP) == [(ROOT_IP, "", NS)], "root asked only for priming")
        check(servers.queries_to(LAB_IP)[:1] == [(LAB_IP, "www.example.lab", A)],
              "lab. names go straight to the stub zone's server")

    run_daemon(binary, write_config(tmp, stub_zone=True), body)


def rejecting_a_bad_config(binary, servers, tmp):
    path = os.path.join(tmp, "bad.yaml")
    with open(path, "w") as f:
        f.write("resolver:\n  edns_buffer: 9000\n")
    r = subprocess.run([binary, "-c", path], capture_output=True, text=True, timeout=5)
    check(r.returncode == 1 and "line 2: resolver.edns_buffer" in r.stderr, "startup stops and names the bad line")

    missing = os.path.join(tmp, "missing.txt")
    path = write_config(tmp, policy=f"  blocklists: [{missing}]\n")
    r = subprocess.run([binary, "-c", path], capture_output=True, text=True, timeout=5)
    check(r.returncode == 1 and f"cannot open {missing}" in r.stderr, "a block list that can't be read stops startup")


def blocking_listed_names(binary, servers, tmp):
    block, allow = os.path.join(tmp, "block.txt"), os.path.join(tmp, "allow.txt")
    with open(block, "w") as f:
        f.write("# a hosts file\n0.0.0.0 example.lab\n0.0.0.0 tracker.lab\n127.0.0.1 localhost\nnot a domain\n")
    with open(allow, "w") as f:
        f.write("www.example.lab\n")
    policy = f"  blocklists: [{block}]\n  allowlist: {allow}\n  reload_check_seconds: 1\n"

    def body(daemon):
        check(any(f"block {block}: 2 domains (1 unusable lines skipped)" in line for line in daemon.log)
              and any("lists: 3 distinct domains" in line for line in daemon.log),
              "startup log counts the domains on each list")

        before = len(servers.seen)
        r = ask("ads.example.lab")
        check(r.id_matches and r.rcode == NOERROR and r.answers == [("ads.example.lab.", A, "0.0.0.0")],
              "a name under a blocked domain gets 0.0.0.0")
        r = ask("ads.example.lab", AAAA)
        check(r.answers == [("ads.example.lab.", AAAA, "::")], "...and :: for AAAA")
        check(len(servers.seen) == before, "...without any upstream query")
        r = ask("www.example.lab")
        check(r.answers == [("www.example.lab.", A, "192.0.2.1")], "an allowlisted name under it is resolved")

        r = ask("metrics.shop.lab")
        check(r.answers == [("metrics.shop.lab.", A, "0.0.0.0")],
              "a name whose CNAME leads to a blocked domain gets 0.0.0.0 (CNAME cloaking)")
        check((LAB_IP, "metrics.shop.lab", A) in servers.seen, "...which only resolving it could show")
        check(daemon.wait_for(f"blocked a cloaked name: metrics.shop.lab. -> collect.tracker.lab. "
                              f"(rule tracker.lab. in {block})"), "...and the daemon logs the chain and the rule")

        daemon.proc.send_signal(signal.SIGHUP)
        check(daemon.wait_for("reloading the lists (SIGHUP)") and daemon.wait_for("lists: 3 distinct domains"),
              "SIGHUP reloads the lists")

        with open(block, "a") as f:
            f.write("dead\n")
        check(daemon.wait_for("reloading the lists (a list file changed)")
              and daemon.wait_for("lists: 4 distinct domains"), "an edited list is reloaded without a restart")
        r = ask("www.dead")
        check(r.answers == [("www.dead.", A, "0.0.0.0")], "...and its new rule applies at once")

        os.remove(allow)
        check(daemon.wait_for("reload failed, still using the previous lists"), "a list that disappears is reported")
        r = ask("www.example.lab")
        check(r.answers == [("www.example.lab.", A, "192.0.2.1")], "...and the lists in use stay as they were")

    run_daemon(binary, write_config(tmp, policy=policy), body)


# ─── Main ────────────────────────────────────────────────────────────────────


def reexec_in_netns():
    """Run this script again as root of a new user + network namespace."""
    unshare = ["unshare", "--user", "--map-root-user", "--net"]
    if not shutil.which("unshare") or not shutil.which("ip"):
        print("skipped: needs unshare(1) and ip(8) (util-linux, iproute2)")
        return SKIP
    probe = subprocess.run(unshare + ["true"], capture_output=True, text=True)
    if probe.returncode != 0:
        print(f"skipped: can't create a user + network namespace here ({probe.stderr.strip()})")
        return SKIP
    env = dict(os.environ, **{IN_NETNS: "1"})
    return subprocess.run(unshare + [sys.executable, os.path.abspath(__file__), *sys.argv[1:]], env=env).returncode


def refusing_clients_outside_the_allowed_subnets(binary, servers, tmp):
    # We query from 127.0.0.1, which these configs leave out.
    def refused(daemon):
        check(any("answering clients in 10.0.0.0/8; others are refused" in line for line in daemon.log),
              "startup log says who is answered")
        before = len(servers.seen)
        r = ask("www.example.lab")
        check(r.id_matches and r.rcode == REFUSED and not r.answers, "a client outside access.allow is refused")
        check(len(servers.seen) == before, "...without any upstream query")

    run_daemon(binary, write_config(tmp, access=(["10.0.0.0/8"], "refuse")), refused)

    def dropped(daemon):
        try:
            ask("www.example.lab", timeout=1)
            answered = True
        except TimeoutError:
            answered = False
        check(not answered, "with deny_action: drop it gets no reply at all")

    run_daemon(binary, write_config(tmp, access=(["10.0.0.0/8"], "drop")), dropped)


def main():
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <path to the dnsentinel binary>", file=sys.stderr)
        return 2
    binary = os.path.abspath(sys.argv[1])
    if not os.access(binary, os.X_OK):
        print(f"{binary}: not an executable (build it first)", file=sys.stderr)
        return 2
    if os.environ.get(IN_NETNS) != "1":
        return reexec_in_netns()

    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    servers = FakeServers()
    with tempfile.TemporaryDirectory() as tmp:
        for scenario in (resolving_from_the_root, resolving_a_stub_zone,
                         refusing_clients_outside_the_allowed_subnets, blocking_listed_names,
                         rejecting_a_bad_config):
            print(scenario.__name__.replace("_", " ") + ":")
            try:
                scenario(binary, servers, tmp)
            except Exception as e:  # a timeout or a malformed reply: report it, keep going
                check(False, f"{scenario.__name__} crashed: {e!r}")

    print(f"\n{len(failures)} check(s) failed" if failures else "\nall checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
