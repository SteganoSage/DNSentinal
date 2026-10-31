"""DNS query events from packet captures (pcap or pcapng), with no dependencies.

The tunnel detector reads one event per query (analyzer/detectors/tunnel.py
DnsEvent): when, which client, the name and type asked, and the answer's
rcode and size. The resolver will produce these itself; here they come from
captures, so the training data and the deployed detector see the same thing:

- the client is the query's source address;
- the name is in the resolver's text form (Name::to_string): lower case,
  a backslash before . \\ " ( ) ; @ $ and \\DDD for other bytes outside
  0x21-0x7e, without the trailing dot;
- the type is its mnemonic ("TXT"; "TYPE65399" for one without);
- rcode and response_size (bytes of DNS message) come from the response
  with the same client address and port, server, ID, name and type. A
  query whose response is not in the capture gets rcode "NONE" and size 0.

UDP on port 53 only (Ethernet, Linux cooked v1/v2, raw IP, BSD loopback;
IPv4 and IPv6). DNS over TCP and later IP fragments are counted and skipped.

    python -m ml.tunnel.pcap capture.pcapng      # prints the events as CSV
"""

from __future__ import annotations

import csv
import ipaddress
import re
import struct
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Iterator

TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 10: "NULL", 12: "PTR", 13: "HINFO", 15: "MX", 16: "TXT",
         17: "RP", 24: "SIG", 25: "KEY", 28: "AAAA", 29: "LOC", 33: "SRV", 35: "NAPTR", 39: "DNAME",
         43: "DS", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 52: "TLSA", 64: "SVCB", 65: "HTTPS", 99: "SPF",
         251: "IXFR", 252: "AXFR", 255: "ANY", 256: "URI", 257: "CAA"}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
NO_RESPONSE = "NONE"
MATCH_SLACK = 2.0  # seconds a response may seem to precede its query (merged captures aren't in time order)
COLUMNS = ["timestamp", "client", "qname", "qtype", "rcode", "response_size"]

_SECTION = b"\x0a\x0d\x0d\x0a"  # pcapng section header block: the same bytes in either byte order
_ESCAPED = frozenset(b'.\\"();@$')
_SPECIAL = re.compile(rb'[^\x21-\x7e]|[.\\"();@$]')  # bytes that Name::to_string escapes
_LINKS = (0, 1, 12, 14, 101, 113, 228, 229, 276)


@dataclass(frozen=True)
class Query:
    timestamp: float
    client: str
    qname: str
    qtype: str
    rcode: str = NO_RESPONSE
    response_size: int = 0


@dataclass
class Stats:
    packets: int = 0
    dns: int = 0
    queries: int = 0
    responses: int = 0
    matched: int = 0
    tcp_dns: int = 0
    fragments: int = 0
    malformed: int = 0
    other_links: dict = field(default_factory=dict)  # link types we can't read: packets of each


# ─── Capture files ──────────────────────────────────────────────────────────


def packets(stream: BinaryIO) -> Iterator[tuple[float, int, bytes]]:
    """(timestamp, link type, frame) for every packet of a pcap or pcapng stream."""
    head = stream.read(4)
    if len(head) < 4:
        return
    if head == _SECTION:
        yield from _pcapng(stream)
        return
    order = {b"\xd4\xc3\xb2\xa1": ("<", 1e-6), b"\xa1\xb2\xc3\xd4": (">", 1e-6),
             b"\x4d\x3c\xb2\xa1": ("<", 1e-9), b"\xa1\xb2\x3c\x4d": (">", 1e-9)}.get(head)
    if order is None:
        raise ValueError("not a pcap or pcapng file")
    endian, unit = order
    rest = stream.read(20)
    if len(rest) < 20:
        return
    link = struct.unpack(endian + "I", rest[16:20])[0] & 0xFFFF
    record = struct.Struct(endian + "IIII")
    while True:
        header = stream.read(16)
        if len(header) < 16:
            return
        seconds, fraction, captured, _ = record.unpack(header)
        frame = stream.read(captured)
        if len(frame) < captured:
            return
        yield seconds + fraction * unit, link, frame


def _pcapng(stream: BinaryIO) -> Iterator[tuple[float, int, bytes]]:
    endian = "<"
    interfaces: list[tuple[int, float]] = []  # (link type, seconds per timestamp unit)
    kind = _SECTION  # the first block's type, already read
    while True:
        raw_length = stream.read(4)
        if len(kind) < 4 or len(raw_length) < 4:
            return
        if kind == _SECTION:  # its byte-order magic says how to read everything after it
            magic = stream.read(4)
            endian = "<" if magic == b"\x4d\x3c\x2b\x1a" else ">"
            length = struct.unpack(endian + "I", raw_length)[0]
            body = magic + stream.read(max(length - 12, 0))
            interfaces = []
        else:
            length = struct.unpack(endian + "I", raw_length)[0]
            body = stream.read(max(length - 8, 0))
        if length < 12 or len(body) < length - 8:
            return
        block = struct.unpack(endian + "I", kind)[0]
        body = body[:-4]  # without the trailing copy of the length
        if block == 1:  # interface description
            interfaces.append((struct.unpack(endian + "H", body[:2])[0], _resolution(body[8:], endian)))
        elif block == 6 and len(body) >= 20:  # enhanced packet
            interface, high, low, captured = struct.unpack(endian + "IIII", body[:16])
            if interface < len(interfaces):
                link, unit = interfaces[interface]
                yield ((high << 32) | low) * unit, link, body[20:20 + captured]
        elif block == 2 and len(body) >= 20:  # obsolete packet block
            interface, _, high, low, captured = struct.unpack(endian + "HHIII", body[:16])
            if interface < len(interfaces):
                link, unit = interfaces[interface]
                yield ((high << 32) | low) * unit, link, body[20:20 + captured]
        # simple packet blocks have no timestamp, and the other blocks no packets
        kind = stream.read(4)


def _resolution(options: bytes, endian: str) -> float:
    """if_tsresol from an interface's options; microseconds by default."""
    position = 0
    while position + 4 <= len(options):
        code, size = struct.unpack(endian + "HH", options[position:position + 4])
        if code == 0:
            break
        if code == 9 and size >= 1:
            value = options[position + 4]
            return 2.0 ** -(value & 0x7F) if value & 0x80 else 10.0 ** -value
        position += 4 + (size + 3) // 4 * 4
    return 1e-6


# ─── Packets ────────────────────────────────────────────────────────────────


def _network(link: int, frame: bytes) -> tuple[int, bytes] | None:
    """(IP version, IP packet) of a link-layer frame, or None."""
    if link == 1:  # Ethernet, with any VLAN tags
        offset, ethertype = 14, frame[12:14]
        while ethertype in (b"\x81\x00", b"\x88\xa8") and len(frame) >= offset + 4:
            ethertype, offset = frame[offset + 2:offset + 4], offset + 4
        protocol, packet = ethertype, frame[offset:]
    elif link == 113:  # Linux cooked capture v1
        protocol, packet = frame[14:16], frame[16:]
    elif link == 276:  # Linux cooked capture v2
        protocol, packet = frame[0:2], frame[20:]
    elif link == 0:  # BSD loopback: the address family, in the capturing host's byte order
        family = max(frame[0], frame[3]) if len(frame) >= 4 else 0
        version = 4 if family == 2 else 6 if family in (24, 28, 30) else 0
        return (version, frame[4:]) if version else None
    else:  # raw IP
        version = frame[0] >> 4 if frame else 0
        return (version, frame) if version in (4, 6) else None
    return (4, packet) if protocol == b"\x08\x00" else (6, packet) if protocol == b"\x86\xdd" else None


def _transport(version: int, packet: bytes, stats: Stats) -> tuple[str, str, int, bytes] | None:
    """(source, destination, protocol, segment) of an IP packet; None for a later fragment."""
    if version == 4:
        if len(packet) < 20:
            return None
        if struct.unpack("!H", packet[6:8])[0] & 0x1FFF:  # a later fragment: no UDP header in it
            stats.fragments += packet[9] == 17
            return None
        source, destination = ".".join(map(str, packet[12:16])), ".".join(map(str, packet[16:20]))
        return source, destination, packet[9], packet[(packet[0] & 0x0F) * 4:]
    if len(packet) < 40:
        return None
    protocol, offset = packet[6], 40
    while protocol in (0, 43, 44, 60) and len(packet) >= offset + 8:  # extension headers
        if protocol == 44 and struct.unpack("!H", packet[offset + 2:offset + 4])[0] & 0xFFF8:
            stats.fragments += packet[offset] == 17
            return None
        step = 8 if protocol == 44 else (packet[offset + 1] + 1) * 8
        protocol, offset = packet[offset], offset + step
    source = str(ipaddress.IPv6Address(packet[8:24]))
    return source, str(ipaddress.IPv6Address(packet[24:40])), protocol, packet[offset:]


def text_name(labels: list[bytes]) -> str:
    """The resolver's text form of a name (Name::to_string), without the trailing dot."""
    labels = [label.lower() for label in labels]  # ASCII only, as DNS case folding is
    if not any(_SPECIAL.search(label) for label in labels):
        return b".".join(labels).decode("ascii")
    out = []
    for label in labels:
        chars = []
        for byte in label:
            if byte in _ESCAPED:
                chars.append("\\" + chr(byte))
            elif byte < 0x21 or byte > 0x7E:
                chars.append(f"\\{byte:03d}")
            else:
                chars.append(chr(byte))
        out.append("".join(chars))
    return ".".join(out)


def _name(message: bytes, offset: int) -> tuple[list[bytes], int]:
    """The labels of the name at offset (following compression pointers), and the offset after it."""
    labels, end, jumps, total = [], None, 0, 0
    while True:
        if offset >= len(message):
            raise ValueError("name runs past the message")
        length = message[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(message) or jumps >= 32:
                raise ValueError("bad compression pointer")
            end = offset + 2 if end is None else end
            offset, jumps = ((length & 0x3F) << 8) | message[offset + 1], jumps + 1
            continue
        if length & 0xC0:
            raise ValueError("unknown label type")
        if length == 0:
            return labels, (offset + 1 if end is None else end)
        label = message[offset + 1:offset + 1 + length]
        total += length + 1
        if len(label) < length or total > 255:
            raise ValueError("label runs past the message, or name longer than 255 bytes")
        labels.append(label)
        offset += 1 + length


def dns_message(message: bytes) -> tuple[bool, int, int, str, str] | None:
    """(is response, ID, rcode, name, type) of a DNS message's first question; None if it has none."""
    if len(message) < 12:
        raise ValueError("shorter than a DNS header")
    ident, flags, questions = struct.unpack("!HHH", message[:6])
    if questions == 0 or (flags >> 11) & 0xF != 0:  # no question, or not a standard query
        return None
    labels, offset = _name(message, 12)
    if offset + 4 > len(message):
        raise ValueError("question runs past the message")
    qtype = struct.unpack("!H", message[offset:offset + 2])[0]
    return bool(flags & 0x8000), ident, flags & 0xF, text_name(labels), TYPES.get(qtype, f"TYPE{qtype}")


# ─── Events ─────────────────────────────────────────────────────────────────


def read_events(path: str | Path, stats: Stats | None = None) -> list[Query]:
    """Every query in a capture with its response's rcode and size, in time order."""
    stats = stats if stats is not None else Stats()
    asked: list[list] = []  # [time, client, name, type, rcode, size], filled in as responses match
    waiting: dict[tuple, list[tuple[float, int]]] = defaultdict(list)  # key -> [(time, index in asked)]
    answers: dict[tuple, list[tuple[float, int, int]]] = defaultdict(list)  # key -> [(time, rcode, size)]
    with open(path, "rb") as stream:
        for timestamp, link, frame in packets(stream):
            stats.packets += 1
            network = _network(link, frame)
            if network is None:
                if link not in _LINKS:
                    stats.other_links[link] = stats.other_links.get(link, 0) + 1
                continue
            transport = _transport(*network, stats)
            if transport is None or transport[2] not in (6, 17) or len(transport[3]) < 8:
                continue
            source, destination, protocol, segment = transport
            source_port, destination_port, length = struct.unpack("!HHH", segment[:6])
            if 53 not in (source_port, destination_port):
                continue
            if protocol == 6:
                stats.tcp_dns += 1
                continue
            stats.dns += 1
            try:
                parsed = dns_message(segment[8:])
            except ValueError:
                stats.malformed += 1
                continue
            if parsed is None:
                continue
            response, ident, rcode, qname, qtype = parsed
            if response and source_port == 53:
                stats.responses += 1
                # length - 8: the whole message, also when the capture holds only its first fragment
                answers[(destination, destination_port, source, ident, qname, qtype)].append(
                    (timestamp, rcode, length - 8))
            elif not response and destination_port == 53:
                stats.queries += 1
                waiting[(source, source_port, destination, ident, qname, qtype)].append((timestamp, len(asked)))
                asked.append([timestamp, source, qname, qtype, NO_RESPONSE, 0])
    for key, replies in answers.items():
        pending = sorted(waiting.get(key, ()))
        position = 0
        for timestamp, rcode, size in sorted(replies):
            # each response answers the earliest unanswered query sent before it
            if position < len(pending) and pending[position][0] <= timestamp + MATCH_SLACK:
                event = asked[pending[position][1]]
                event[4], event[5] = RCODES.get(rcode, f"RCODE{rcode}"), size
                position += 1
                stats.matched += 1
    asked.sort(key=lambda event: event[0])
    return [Query(*event) for event in asked]


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python -m ml.tunnel.pcap capture.pcap", file=sys.stderr)
        return 2
    stats = Stats()
    events = read_events(sys.argv[1], stats)
    writer = csv.writer(sys.stdout)
    writer.writerow(COLUMNS)
    for event in events:
        writer.writerow([f"{event.timestamp:.6f}", event.client, event.qname, event.qtype, event.rcode,
                         event.response_size])
    print(stats, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
