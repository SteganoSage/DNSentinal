"""Query events from captures: pcap and pcapng, link layers, names, response matching."""

import io
import struct
import tempfile
import unittest
from pathlib import Path

from analyzer.detectors.tunnel import labels_of
from ml.tunnel import pcap


def dns(ident: int, labels: list[bytes], qtype: int, response: bool = False, rcode: int = 0,
        extra: bytes = b"") -> bytes:
    flags = (0x8180 if response else 0x0100) | rcode
    question = b"".join(bytes([len(label)]) + label for label in labels) + b"\0" + struct.pack("!HH", qtype, 1)
    return struct.pack("!HHHHHH", ident, flags, 1, 1 if extra else 0, 0, 0) + question + extra


def udp4(source: str, destination: str, sport: int, dport: int, payload: bytes) -> bytes:
    segment = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(segment), 0, 0, 64, 17, 0,
                         bytes(map(int, source.split("."))), bytes(map(int, destination.split("."))))
    return header + segment


def ethernet(packet: bytes, ethertype: bytes = b"\x08\x00") -> bytes:
    return b"\x00" * 12 + ethertype + packet


def pcap_file(frames: list[tuple[float, bytes]], link: int = 1) -> bytes:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, link)
    for timestamp, frame in frames:
        seconds = int(timestamp)
        out += struct.pack("<IIII", seconds, round((timestamp - seconds) * 1e6), len(frame), len(frame)) + frame
    return out


def pcapng_file(frames: list[tuple[float, bytes]], link: int = 1) -> bytes:
    def block(kind: int, body: bytes) -> bytes:
        body += b"\0" * (-len(body) % 4)
        return struct.pack("<II", kind, len(body) + 12) + body + struct.pack("<I", len(body) + 12)

    out = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    options = struct.pack("<HHB3x", 9, 1, 9) + struct.pack("<HH", 0, 0)  # if_tsresol: nanoseconds
    out += block(1, struct.pack("<HHI", link, 0, 65535) + options)
    for timestamp, frame in frames:
        units = round(timestamp * 1e9)
        out += block(6, struct.pack("<IIIII", 0, units >> 32, units & 0xFFFFFFFF, len(frame), len(frame)) + frame)
    return out


CLIENT, SERVER = "192.168.1.10", "192.168.1.1"
QUERY = dns(0x1234, [b"AbC", b"x\xffy", b"a.b", b"Example", b"com"], 16)
RESPONSE = dns(0x1234, [b"abc", b"x\xffy", b"a.b", b"example", b"com"], 16, response=True, rcode=3,
               extra=b"\xc0\x0c" + struct.pack("!HHIH", 16, 1, 60, 4) + b"\x03hey")
FRAMES = [
    (100.25, ethernet(udp4(CLIENT, SERVER, 40000, 53, QUERY))),
    (100.30, ethernet(udp4(SERVER, CLIENT, 53, 40000, RESPONSE))),
    (101.00, ethernet(udp4(CLIENT, SERVER, 40001, 53, dns(7, [b"www", b"example", b"org"], 28)))),
    (101.50, ethernet(udp4(CLIENT, SERVER, 40002, 80, b"not dns"))),
    (102.00, ethernet(udp4(CLIENT, SERVER, 40003, 53, b"\x00\x01"))),  # too short for DNS
]


def read(content: bytes) -> tuple[list, pcap.Stats]:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "capture"
        path.write_bytes(content)
        stats = pcap.Stats()
        return pcap.read_events(path, stats), stats


class Events(unittest.TestCase):
    def check(self, events, stats):
        self.assertEqual(len(events), 2)
        first, second = events
        self.assertAlmostEqual(first.timestamp, 100.25, places=5)
        self.assertEqual(first.client, CLIENT)
        self.assertEqual(first.qname, "abc.x\\255y.a\\.b.example.com")  # Name::to_string, no trailing dot
        self.assertEqual((first.qtype, first.rcode, first.response_size), ("TXT", "NXDOMAIN", len(RESPONSE)))
        self.assertEqual((second.qname, second.qtype, second.rcode, second.response_size),
                         ("www.example.org", "AAAA", pcap.NO_RESPONSE, 0))
        self.assertEqual((stats.queries, stats.responses, stats.matched, stats.malformed), (2, 1, 1, 1))

    def test_pcap(self):
        self.check(*read(pcap_file(FRAMES)))

    def test_pcapng_with_nanosecond_timestamps(self):
        self.check(*read(pcapng_file(FRAMES)))

    def test_raw_ip_and_vlan(self):
        raw = [(t, frame[14:]) for t, frame in FRAMES]
        self.check(*read(pcap_file(raw, link=101)))
        tagged = [(t, frame[:12] + b"\x81\x00\x00\x05" + frame[12:]) for t, frame in FRAMES]
        self.check(*read(pcap_file(tagged)))

    def test_ipv6_over_linux_cooked(self):
        payload = dns(9, [b"v6", b"example", b"net"], 1)
        segment = struct.pack("!HHHH", 5353, 53, 8 + len(payload), 0) + payload
        packet = struct.pack("!IHBB16s16s", 6 << 28, len(segment), 17, 64, b"\x20\x01" + b"\0" * 13 + b"\x01",
                             b"\x20\x01" + b"\0" * 13 + b"\x02") + segment
        frame = b"\0" * 14 + b"\x86\xdd" + packet
        events, _ = read(pcap_file([(5.0, frame)], link=113))
        self.assertEqual([(e.client, e.qname, e.qtype) for e in events], [("2001::1", "v6.example.net", "A")])

    def test_response_matches_the_earliest_query_and_may_appear_first(self):
        query = dns(1, [b"a", b"example", b"com"], 1)
        response = dns(1, [b"a", b"example", b"com"], 1, response=True)
        frames = [(10.0, ethernet(udp4(SERVER, CLIENT, 53, 999, response))),  # merged capture: out of order
                  (10.5, ethernet(udp4(CLIENT, SERVER, 999, 53, query))),
                  (11.0, ethernet(udp4(CLIENT, SERVER, 999, 53, query)))]   # a retry, never answered
        events, stats = read(pcap_file(frames))
        self.assertEqual([e.rcode for e in events], ["NOERROR", pcap.NO_RESPONSE])
        self.assertEqual(stats.matched, 1)

    def test_tcp_and_later_fragments_are_counted_not_read(self):
        frame = ethernet(udp4(CLIENT, SERVER, 1, 53, QUERY))
        tcp = frame[:23] + b"\x06" + frame[24:]  # protocol field
        fragment = frame[:20] + b"\x00\x10" + frame[22:]  # fragment offset 16
        events, stats = read(pcap_file([(1.0, tcp), (2.0, fragment)]))
        self.assertEqual((events, stats.tcp_dns, stats.fragments), ([], 1, 1))

    def test_not_a_capture(self):
        with self.assertRaises(ValueError):
            list(pcap.packets(io.BytesIO(b"hello world")))


class Names(unittest.TestCase):
    def test_text_form_round_trips_through_the_detector(self):
        labels = [b"A.b", b"\x00\xff", b'q"(;)@$\\', b"Mixed-Case_1", b"com"]
        text = pcap.text_name(labels)
        self.assertEqual(text, 'a\\.b.\\000\\255.q\\"\\(\\;\\)\\@\\$\\\\.mixed-case_1.com')
        self.assertEqual(labels_of(text), [label.lower() for label in labels])

    def test_compression_loops_are_malformed(self):
        message = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c" + struct.pack("!HH", 1, 1)
        with self.assertRaises(ValueError):
            pcap.dns_message(message)


if __name__ == "__main__":
    unittest.main()
