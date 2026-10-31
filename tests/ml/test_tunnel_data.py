"""The tunnel dataset builder, without the network: the pinned files, the smoke data, the checks."""

import contextlib
import csv
import gzip
import io
import json
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from ml.tunnel import data


class PinnedSources(unittest.TestCase):
    def test_graphtunnel_files_are_whole_captures_and_dns2tcp_is_there_once(self):
        files = data.GRAPHTUNNEL["files"]
        self.assertEqual(len(data.GRAPHTUNNEL["commit"]), 40)
        self.assertEqual(Counter(path.split("/")[0] for path in files),
                         {"normal": 68, "tunnel": 13, "wildcard": 13, "unkownTunnel": 6, "crossEndPoint": 5})
        nested = [p for p in files if p.count("/") > 1 and not p.startswith("normal/normal/")]
        self.assertEqual(nested, [])
        self.assertEqual([p for p in files if "dns2tcp" in p],
                         ["unkownTunnel/dns2tcp-key.pcap", "unkownTunnel/dns2tcp-txt.pcap"])

    def test_capture_kinds_and_tools(self):
        cases = {
            "tunnel/iodine-NULL.pcap": ("known", "tunnel", "iodine"),
            "tunnel/DNS-shell.pcap": ("known", "tunnel", "dns-shell"),
            "tunnel/dnspot.pcap": ("known", "tunnel", "dnspot"),
            "unkownTunnel/cobalstrike.pcap": ("unknown", "tunnel", "cobaltstrike"),
            "unkownTunnel/tcp-over-dns-CNAME.pcap": ("unknown", "tunnel", "tcp-over-dns"),
            "crossEndPoint/AndIodine-MX.pcap": ("android", "tunnel", "andiodine"),
            "normal/normal/normal_00001_20230805152732.pcap": ("crawl", "benign", ""),
            "wildcard/wildcard_00003_20231011220812.pcap": ("wildcard", "benign", ""),
        }
        for path, expected in cases.items():
            capture = data.graphtunnel_capture(path)
            self.assertEqual((capture.set, capture.label, capture.tool), expected, path)
        tools = {data.graphtunnel_capture(p).tool for p in data.GRAPHTUNNEL["files"] if p.startswith("tunnel/")}
        self.assertEqual(tools, {"dnscat2", "dnspot", "iodine", "dns-shell", "tuns"})

    def test_browsing_choices(self):
        def sizes(browsing):
            return sum(size for capture, url, _, size in data.captures_for(browsing, None)
                       if capture.source == "stratosphere")

        self.assertEqual(sizes("none"), 0)
        self.assertLess(sizes("small"), 1.2e9)
        self.assertGreater(sizes("all"), 6e9)

    def test_git_blob_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "f"
            path.write_bytes(b"hello\n")
            self.assertEqual(data.git_blob_sha1(path), "ce013625030ba8dba906f756967f9e9ca394464a")  # git hash-object

    def test_fetch_reuses_a_complete_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, target = Path(tmp) / "source", Path(tmp) / "out" / "copy"
            source.write_bytes(b"x" * 1000)
            self.assertEqual(data.fetch(source.as_uri(), target, 1000).read_bytes(), b"x" * 1000)
            source.write_bytes(b"changed")
            self.assertEqual(data.fetch(source.as_uri(), target, 1000).read_bytes(), b"x" * 1000)

    def test_local_captures_by_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("benign/laptop/day1.pcapng", "tunnel/iodine/lab-null.pcap", "stray.pcap"):
                (root / name).parent.mkdir(parents=True, exist_ok=True)
                (root / name).write_bytes(b"")
            with contextlib.redirect_stdout(io.StringIO()):  # the stray capture is reported
                local = [c for c, *_ in data.captures_for("none", root) if c.source == "local"]
            self.assertEqual([(c.capture, c.label, c.tool) for c in local],
                             [("local/benign/laptop/day1", "benign", ""),
                              ("local/tunnel/iodine/lab-null", "tunnel", "iodine")])


class Smoke(unittest.TestCase):
    def test_same_files_as_the_real_build(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            with contextlib.redirect_stdout(io.StringIO()):
                info = data.build_smoke(out)
            with open(out / "captures.csv", newline="") as stream:
                captures = list(csv.DictReader(stream))
            self.assertEqual(list(captures[0]), data.CAPTURE_COLUMNS)
            self.assertEqual({c["set"] for c in captures},
                             {"known", "unknown", "android", "browsing", "crawl", "wildcard"})
            for c in captures:
                if c["label"] == "tunnel":
                    self.assertEqual(c["tunnel_domain"], f"{c['tool']}-tunnel.test")
            with gzip.open(out / "events.csv.gz", "rt", newline="") as stream:
                rows = list(csv.reader(stream))
            self.assertEqual(rows[0], ["capture", "timestamp", "client", "qname", "qtype", "rcode", "response_size"])
            self.assertEqual(len(rows) - 1, info["queries"])
            self.assertEqual(json.loads((out / "dataset_info.json").read_text())["captures"], len(captures))
            self.assertTrue((out / "allowlist_top100k.txt").read_text().strip())


if __name__ == "__main__":
    unittest.main()
