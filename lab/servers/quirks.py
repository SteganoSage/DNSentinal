#!/usr/bin/env python3
"""The lab's misbehaving authoritative servers: what NSD won't do (EVALUATION.md §3.1).

    python3 lab/servers/quirks.py                  # in the lab's quirks container (10.53.2.30-.35)

One process, UDP and TCP, one socket per address. What a server does depends on the zone asked:

  slow.lab      answers after --delay ms (default 800): server selection, SRTT (E18), timeouts
  nocase.lab    answers with the question in lower case: breaks 0x20 randomisation, so a
                resolver must fall back rather than reject every answer
  attacker.lab  answers with out-of-bailiwick records that try to take over bank.lab
                (www.bank.lab -> 6.6.6.6): bailiwick checking must drop them (E5 part C)
  nxns.lab      refers every query to --fanout name servers under nxns-victim.lab without glue:
                the NXNSAttack amplification a resolver must cap (E10)
  deep.lab      a delegation chain five cuts deep, one address per level (10.53.2.30 for
                deep.lab, .31 for a.deep.lab, ... .35 answering www.e.d.c.b.a.deep.lab)
  exfil.lab     a tunnel's server: every TXT query under it gets 110 hex characters of "data"
                (the pipeline experiment's synthetic tunnels)

Every query is logged on stderr: who asked what (EVALUATION.md E6 reads these too).
"""

from __future__ import annotations

import argparse
import socket
import struct
import sys
import threading
import time

A, NS, CNAME, SOA, TXT, AAAA = 1, 2, 5, 6, 16, 28
NOERROR, NXDOMAIN, REFUSED = 0, 3, 5
DEEP = ["deep.lab", "a.deep.lab", "b.a.deep.lab", "c.b.a.deep.lab", "d.c.b.a.deep.lab", "e.d.c.b.a.deep.lab"]
BASE = "10.53.2.3"  # level i of the deep chain listens on 10.53.2.3{i}, quirks' others on .30


def encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        if label:
            out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def read_name(buf: bytes, off: int) -> tuple[str, int]:
    labels, jumped, end = [], False, off
    for _ in range(128):
        length = buf[off]
        if length & 0xC0 == 0xC0:
            if not jumped:
                end = off + 2
            off, jumped = ((length & 0x3F) << 8) | buf[off + 1], True
            continue
        if length == 0:
            return ".".join(labels), (end if jumped else off + 1)
        labels.append(buf[off + 1:off + 1 + length].decode("latin-1"))
        off += 1 + length
    raise ValueError("compression loop")


def rr(name: str, rtype: int, rdata: bytes, ttl: int = 300) -> bytes:
    return encode_name(name) + struct.pack(">HHIH", rtype, 1, ttl, len(rdata)) + rdata


def a(ip: str) -> bytes:
    return socket.inet_aton(ip)


def soa(zone: str) -> bytes:
    rdata = encode_name(f"ns.{zone}") + encode_name(f"hostmaster.{zone}") + struct.pack(">IIIII", 1, 3600, 600, 86400, 60)
    return rr(zone, SOA, rdata, 60)


def response(qid: int, question: bytes, rcode: int, answer=(), authority=(), additional=(), aa=True) -> bytes:
    flags = 0x8000 | (0x0400 if aa else 0) | rcode
    head = struct.pack(">HHHHHH", qid, flags, 1, len(answer), len(authority), len(additional))
    return head + question + b"".join(answer) + b"".join(authority) + b"".join(additional)


def hashlib_hex(text: str) -> str:
    import hashlib
    return "".join(hashlib.sha256(f"{text}{i}".encode()).hexdigest() for i in range(2))


def under(name: str, zone: str) -> bool:
    return name == zone or name.endswith("." + zone)


class Quirks:
    def __init__(self, delay_ms: int, fanout: int) -> None:
        self.delay, self.fanout = delay_ms / 1000, fanout

    def answer(self, packet: bytes, local_ip: str) -> tuple[bytes | None, float]:
        """The reply, and how long to wait before sending it."""
        qid, _flags, qdcount = struct.unpack(">HHH", packet[:6])
        if qdcount != 1:
            return None, 0
        asked, off = read_name(packet, 12)
        qtype, _qclass = struct.unpack(">HH", packet[off:off + 4])
        question = packet[12:off + 4]
        name = asked.lower()

        if local_ip.startswith(BASE) and local_ip != BASE + "0":  # a deeper level of the chain
            return self.deep(qid, question, name, qtype, int(local_ip[-1])), 0
        if under(name, "deep.lab"):
            return self.deep(qid, question, name, qtype, 0), 0
        if under(name, "slow.lab"):
            if qtype == A and name in ("slow.lab", "www.slow.lab"):
                return response(qid, question, NOERROR, [rr(name, A, a("192.0.2.120"))]), self.delay
            return response(qid, question, NXDOMAIN, authority=[soa("slow.lab")]), self.delay
        if under(name, "nocase.lab"):
            lowered = encode_name(name) + question[-4:]  # the question as asked, but in lower case
            if qtype == A and name in ("nocase.lab", "www.nocase.lab"):
                return response(qid, lowered, NOERROR, [rr(name, A, a("192.0.2.121"))]), 0
            return response(qid, lowered, NXDOMAIN, authority=[soa("nocase.lab")]), 0
        if under(name, "attacker.lab"):
            if qtype == A and name in ("attacker.lab", "www.attacker.lab"):
                return response(qid, question, NOERROR, [rr(name, A, a("192.0.2.66"))],
                                authority=[rr("bank.lab", NS, encode_name("ns.attacker.lab"), 86400)],
                                additional=[rr("ns.attacker.lab", A, a("10.53.2.30"), 86400),
                                            rr("www.bank.lab", A, a("6.6.6.6"), 86400)]), 0
            return response(qid, question, NXDOMAIN, authority=[soa("attacker.lab")]), 0
        if under(name, "exfil.lab"):
            if qtype == TXT and name != "exfil.lab":
                data = hashlib_hex(name)[:110].encode()
                return response(qid, question, NOERROR, [rr(name, TXT, bytes([len(data)]) + data, 0)]), 0
            return response(qid, question, NOERROR, authority=[soa("exfil.lab")]), 0
        if under(name, "nxns.lab"):
            if name in ("nxns.lab", "ns.nxns.lab") and qtype in (A, NS):
                return response(qid, question, NOERROR, [rr(name, A, a("10.53.2.30"))] if qtype == A else
                                [rr(name, NS, encode_name("ns.nxns.lab"))]), 0
            # a referral to many name servers nobody can resolve without asking the victim
            authority = [rr(name, NS, encode_name(f"ns{i}.{name.split('.')[0]}.nxns-victim.lab"), 60)
                         for i in range(self.fanout)]
            return response(qid, question, NOERROR, authority=authority, aa=False), 0
        return response(qid, question, REFUSED, aa=False), 0

    def deep(self, qid: int, question: bytes, name: str, qtype: int, level: int) -> bytes:
        zone = DEEP[level]
        if level == len(DEEP) - 1:
            if qtype == A and name == "www." + zone:
                return response(qid, question, NOERROR, [rr(name, A, a("192.0.2.110"))])
            return response(qid, question, NXDOMAIN, authority=[soa(zone)])
        child = DEEP[level + 1]
        if under(name, child):  # a referral one cut down, with glue
            ns = f"ns.{child}"
            return response(qid, question, NOERROR, authority=[rr(child, NS, encode_name(ns), 86400)],
                            additional=[rr(ns, A, a(f"{BASE}{level + 1}"), 86400)], aa=False)
        if name == f"ns.{zone}" and qtype == A:
            return response(qid, question, NOERROR, [rr(name, A, a(f"{BASE}{level}"))])
        return response(qid, question, NXDOMAIN, authority=[soa(zone)])


def serve_udp(sock: socket.socket, quirks: Quirks, ip: str) -> None:
    while True:
        packet, peer = sock.recvfrom(4096)
        try:
            reply, wait = quirks.answer(packet, ip)
        except (ValueError, IndexError, struct.error):
            continue
        log(peer[0], ip, packet)
        if reply is not None:
            if wait:
                threading.Timer(wait, sock.sendto, (reply, peer)).start()
            else:
                sock.sendto(reply, peer)


def serve_tcp(sock: socket.socket, quirks: Quirks, ip: str) -> None:
    while True:
        conn, peer = sock.accept()
        threading.Thread(target=_tcp_client, args=(conn, peer, quirks, ip), daemon=True).start()


def _tcp_client(conn: socket.socket, peer, quirks: Quirks, ip: str) -> None:
    with conn:
        conn.settimeout(10)
        try:
            length = struct.unpack(">H", _exact(conn, 2))[0]
            packet = _exact(conn, length)
            reply, wait = quirks.answer(packet, ip)
            log(peer[0], ip, packet, "tcp")
            if reply is not None:
                time.sleep(wait)
                conn.sendall(struct.pack(">H", len(reply)) + reply)
        except (OSError, ValueError, IndexError, struct.error):
            pass


def _exact(conn: socket.socket, count: int) -> bytes:
    data = b""
    while len(data) < count:
        chunk = conn.recv(count - len(data))
        if not chunk:
            raise OSError("closed")
        data += chunk
    return data


def log(client: str, server: str, packet: bytes, transport: str = "udp") -> None:
    try:
        name, off = read_name(packet, 12)
        qtype = struct.unpack(">H", packet[off:off + 2])[0]
    except (ValueError, IndexError, struct.error):
        return
    print(f"{time.time():.6f} {transport} {client} -> {server} {name} {qtype}", file=sys.stderr, flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--delay", type=int, default=800, help="slow.lab's delay in ms")
    parser.add_argument("--fanout", type=int, default=20, help="name servers in each nxns.lab referral")
    parser.add_argument("--addresses", default=",".join(f"{BASE}{i}" for i in range(len(DEEP))))
    args = parser.parse_args()
    quirks = Quirks(args.delay, args.fanout)
    threads = []
    for ip in args.addresses.split(","):
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.bind((ip, 53))
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp.bind((ip, 53))
        tcp.listen(32)
        threads += [threading.Thread(target=serve_udp, args=(udp, quirks, ip), daemon=True),
                    threading.Thread(target=serve_tcp, args=(tcp, quirks, ip), daemon=True)]
    for thread in threads:
        thread.start()
    print(f"quirks: serving slow.lab nocase.lab attacker.lab nxns.lab deep.lab exfil.lab on {args.addresses}",
          file=sys.stderr, flush=True)
    for thread in threads:
        thread.join()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
