#!/usr/bin/env python3
"""E1's driver (EVALUATION.md E1): ask two resolvers the same questions at the same moment, and compare.

    python3 bench/drivers/e1_compare.py --names names.txt --test 10.53.1.2 --baseline 10.53.1.3 --out e1.csv

Runs on the lab's client (or anywhere both resolvers answer). `names.txt` holds "name type set" lines.
The agreement rule is the card's, fixed in advance:
- both give the same RCODE;
- and either the same final CNAME target, or overlapping address sets (or both have none: NODATA).

A mismatch is asked again after --recheck seconds: it is `transient` if the two then agree,
`persistent` if not. Queries are paced (--rate per resolver) under DNSentinel's per-client
rate limit, so the limiter never causes a mismatch.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "lab" / "tools"))
from dnsq import query  # noqa: E402


def agree(a: dict, b: dict) -> bool:
    if a["rcode"] != b["rcode"]:
        return False
    if a["cname"] and a["cname"] == b["cname"]:
        return True
    if not a["addresses"] and not b["addresses"]:
        return True  # NODATA or NXDOMAIN on both sides
    return bool(set(a["addresses"]) & set(b["addresses"]))


class Pacer:
    """At most `rate` starts a second, shared by the worker threads."""

    def __init__(self, rate: float) -> None:
        self.gap, self.next, self.lock = 1.0 / rate, time.monotonic(), threading.Lock()

    def wait(self) -> None:
        with self.lock:
            now = time.monotonic()
            self.next = max(self.next + self.gap, now)
            delay = self.next - now
        if delay > 0:
            time.sleep(delay)


def both(test: str, baseline: str, name: str, qtype: str, timeout: float) -> tuple[dict, dict]:
    with ThreadPoolExecutor(2) as pair:  # the same moment: neither resolver's cache is warmed by the other
        a = pair.submit(query, test, name, qtype, timeout=timeout)
        b = pair.submit(query, baseline, name, qtype, timeout=timeout)
        return a.result(), b.result()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--names", type=Path, required=True)
    parser.add_argument("--test", required=True, help="the resolver under test (DNSentinel)")
    parser.add_argument("--baseline", required=True, help="the resolver it is compared with (Unbound)")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--rate", type=float, default=80.0, help="query pairs a second (default 80)")
    parser.add_argument("--workers", type=int, default=32)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--recheck", type=float, default=2.0, help="seconds before a mismatch is asked again")
    args = parser.parse_args()

    jobs = []
    for line in args.names.read_text().splitlines():
        if line.strip() and not line.startswith("#"):
            name, qtype, *kind = line.split()
            jobs.append((name, qtype, kind[0] if kind else ""))
    pacer = Pacer(args.rate)

    def one(job):
        name, qtype, kind = job
        pacer.wait()
        a, b = both(args.test, args.baseline, name, qtype, args.timeout)
        match = agree(a, b)
        recheck = ""
        if not match:
            time.sleep(args.recheck)
            a2, b2 = both(args.test, args.baseline, name, qtype, args.timeout)
            recheck = "transient" if agree(a2, b2) else "persistent"
        return {"name": name, "type": qtype, "set": kind, "agree": int(match), "recheck": recheck,
                "test_rcode": a["rcode"], "base_rcode": b["rcode"], "test_cname": a["cname"], "base_cname": b["cname"],
                "test_addresses": " ".join(a["addresses"]), "base_addresses": " ".join(b["addresses"]),
                "test_ms": f"{a['latency_ms']:.3f}", "base_ms": f"{b['latency_ms']:.3f}",
                "test_transport": a["transport"], "base_transport": b["transport"]}

    started = time.time()
    with ThreadPoolExecutor(args.workers) as pool:
        rows = list(pool.map(one, jobs))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    agreed = sum(r["agree"] for r in rows)
    print(json.dumps({"queries": len(rows), "agree": agreed, "agreement": agreed / len(rows),
                      "seconds": round(time.time() - started, 1)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
