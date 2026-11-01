#!/usr/bin/env python3
"""A small DNS client for the experiment drivers: the standard library only, so it runs in any lab container.

    python3 lab/tools/dnsq.py 10.53.1.2 www.example.lab A        # one query, printed as JSON
    python3 lab/tools/dnsq.py --dot --ca CA --hostname dns.lab 10.53.1.2 www.example.lab   # over TLS
    python3 lab/tools/dnsq.py --doh --ca CA --hostname dns.lab 10.53.1.2 www.example.lab   # over HTTPS

query() sends one query over UDP (falling back to TCP when the answer is truncated), or over DoT
(RFC 7858) or DoH (RFC 8484, POST, HTTP/1.1), and returns what the experiments compare: the rcode,
the answer records, the final CNAME target, the addresses, the latency, and the transport used.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import random
import socket
import ssl
import struct
import sys
import time

TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33, "HTTPS": 65}
NAMES = {v: k for k, v in TYPES.items()}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


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
            return ".".join(labels).lower(), (end if jumped else off + 1)
        labels.append(buf[off + 1:off + 1 + length].decode("latin-1"))
        off += 1 + length
    raise ValueError("compression loop")


def make_query(name: str, qtype: int, rd: bool = True) -> tuple[int, bytes]:
    qid = random.getrandbits(16)
    # EDNS0 with a 1232-byte buffer, as stub resolvers send today
    opt = b"\x00" + struct.pack(">HHIH", 41, 1232, 0, 0)
    head = struct.pack(">HHHHHH", qid, 0x0100 if rd else 0, 1, 0, 0, 1)
    return qid, head + encode_name(name) + struct.pack(">HH", qtype, 1) + opt


def parse(buf: bytes) -> dict:
    qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", buf[:12])
    off = 12
    for _ in range(qd):
        _, off = read_name(buf, off)
        off += 4
    sections = []
    for count in (an, ns):
        records = []
        for _ in range(count):
            name, off = read_name(buf, off)
            rtype, _cls, ttl, length = struct.unpack(">HHIH", buf[off:off + 10])
            off += 10
            rdata = buf[off:off + length]
            if rtype == 1 and length == 4:
                data = socket.inet_ntoa(rdata)
            elif rtype == 28 and length == 16:
                data = socket.inet_ntop(socket.AF_INET6, rdata)
            elif rtype in (2, 5, 12):
                data = read_name(buf, off)[0]
            elif rtype == 15:
                data = f"{struct.unpack('>H', rdata[:2])[0]} {read_name(buf, off + 2)[0]}"
            else:
                data = rdata.hex()
            records.append((name, NAMES.get(rtype, str(rtype)), ttl, data))
            off += length
        sections.append(records)
    return {"id": qid, "rcode": RCODES.get(flags & 0xF, str(flags & 0xF)), "tc": bool(flags & 0x0200),
            "aa": bool(flags & 0x0400), "answers": sections[0], "authority": sections[1]}


def _udp(server: str, port: int, packet: bytes, qid: int, timeout: float) -> bytes:
    with socket.socket(socket.AF_INET6 if ":" in server else socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(packet, (server, port))
        deadline = time.monotonic() + timeout
        while True:
            sock.settimeout(max(0.001, deadline - time.monotonic()))
            data, _ = sock.recvfrom(65535)
            if len(data) >= 12 and struct.unpack(">H", data[:2])[0] == qid:
                return data


def _tcp(server: str, port: int, packet: bytes, timeout: float) -> bytes:
    with socket.create_connection((server, port), timeout=timeout) as sock:
        sock.sendall(struct.pack(">H", len(packet)) + packet)
        need, data = 2, b""
        while len(data) < need:
            chunk = sock.recv(65535)
            if not chunk:
                raise OSError("closed")
            data += chunk
            if len(data) >= 2:
                need = 2 + struct.unpack(">H", data[:2])[0]
        return data[2:need]


def _tls_context(ca: str | None) -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=ca) if ca else ssl.create_default_context()
    return context


def _dot(server: str, port: int, packet: bytes, timeout: float, ca: str | None, hostname: str) -> bytes:
    with socket.create_connection((server, port), timeout=timeout) as raw:
        with _tls_context(ca).wrap_socket(raw, server_hostname=hostname) as sock:
            sock.sendall(struct.pack(">H", len(packet)) + packet)
            need, data = 2, b""
            while len(data) < need:
                chunk = sock.recv(65535)
                if not chunk:
                    raise OSError("closed")
                data += chunk
                if len(data) >= 2:
                    need = 2 + struct.unpack(">H", data[:2])[0]
            return data[2:need]


def _doh(server: str, port: int, packet: bytes, timeout: float, ca: str | None, hostname: str, path: str) -> bytes:
    connection = http.client.HTTPSConnection(server, port, timeout=timeout, context=_tls_context(ca))
    connection._tunnel_host = None
    try:  # the certificate names `hostname`; the address is `server`
        connection.sock = _tls_context(ca).wrap_socket(socket.create_connection((server, port), timeout=timeout),
                                                       server_hostname=hostname)
        connection.request("POST", path, body=packet, headers={"Host": hostname, "Content-Type": "application/dns-message",
                                                              "Accept": "application/dns-message"})
        reply = connection.getresponse()
        body = reply.read()
        if reply.status != 200:
            raise OSError(f"HTTP {reply.status}")
        return body
    finally:
        connection.close()


def query(server: str, name: str, qtype: str = "A", port: int = 53, timeout: float = 5.0, rd: bool = True,
          transport: str = "udp", ca: str | None = None, hostname: str = "", path: str = "/dns-query") -> dict:
    """One query: rcode, answers, the final CNAME target, addresses, latency (ms) and transport used.
    transport: udp (TCP if truncated), tcp, dot or doh. rcode is "TIMEOUT" if nothing came back."""
    code = TYPES[qtype]
    qid, packet = make_query(name, code, rd)
    start = time.perf_counter()
    try:
        if transport == "dot":
            result = parse(_dot(server, port if port != 53 else 853, packet, timeout, ca, hostname or server))
        elif transport == "doh":
            result = parse(_doh(server, port if port != 53 else 443, packet, timeout, ca, hostname or server, path))
        elif transport == "tcp":
            result = parse(_tcp(server, port, packet, timeout))
        else:
            result = parse(_udp(server, port, packet, qid, timeout))
            if result["tc"]:
                transport = "tcp"
                result = parse(_tcp(server, port, packet, timeout))
    except (OSError, socket.timeout, ssl.SSLError):
        return {"name": name, "type": qtype, "server": server, "rcode": "TIMEOUT", "answers": [], "cname": "",
                "addresses": [], "latency_ms": (time.perf_counter() - start) * 1000, "transport": transport}
    latency = (time.perf_counter() - start) * 1000
    cname = ""
    for owner, rtype, _ttl, data in result["answers"]:
        if rtype == "CNAME":
            cname = data
    addresses = sorted({data for _o, rtype, _t, data in result["answers"] if rtype == qtype})
    return {"name": name, "type": qtype, "server": server, "rcode": result["rcode"], "answers": result["answers"],
            "cname": cname, "addresses": addresses, "latency_ms": latency, "transport": transport}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("server")
    parser.add_argument("name")
    parser.add_argument("type", nargs="?", default="A")
    parser.add_argument("--tcp", action="store_const", dest="transport", const="tcp", default="udp")
    parser.add_argument("--dot", action="store_const", dest="transport", const="dot")
    parser.add_argument("--doh", action="store_const", dest="transport", const="doh")
    parser.add_argument("--ca", help="CA certificate for DoT/DoH")
    parser.add_argument("--hostname", default="", help="the name the server's certificate is for")
    parser.add_argument("--port", type=int, default=53)
    args = parser.parse_args()
    random.seed(os.getpid())
    print(json.dumps(query(args.server, args.name, args.type, port=args.port, transport=args.transport,
                           ca=args.ca, hostname=args.hostname)))
