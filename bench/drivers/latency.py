#!/usr/bin/env python3
"""Per-query latency against one resolver (E2 cold and warm, E6's cost): every query timed, nothing averaged.

    python3 bench/drivers/latency.py --server 10.53.1.2 --names q.txt --rate 50 --out lat.csv [--transport dot]

`q.txt` holds "name type" lines. They are sent in order at --rate a second, with --workers in
flight, and one CSV row is written per query: name, type, rcode, latency_ms, transport.
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--server", required=True)
    parser.add_argument("--names", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--rate", type=float, default=50.0)
    parser.add_argument("--workers", type=int, default=16)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--transport", default="udp", choices=("udp", "tcp", "dot", "doh"))
    parser.add_argument("--ca", default="/dnsentinel/lab/state/certs/ca.crt")
    parser.add_argument("--hostname", default="dns.lab")
    args = parser.parse_args()
    jobs = [line.split()[:2] for line in args.names.read_text().splitlines() if line.strip() and not line.startswith("#")]
    gap, lock, start_at = 1.0 / args.rate, threading.Lock(), [time.monotonic()]

    def one(job):
        with lock:
            start_at[0] = max(start_at[0] + gap, time.monotonic())
            delay = start_at[0] - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        name, qtype = job
        r = query(args.server, name, qtype, timeout=args.timeout, transport=args.transport, ca=args.ca,
                  hostname=args.hostname)
        return {"t": f"{time.time():.3f}", "name": name, "type": qtype, "rcode": r["rcode"],
                "latency_ms": f"{r['latency_ms']:.3f}", "transport": r["transport"], "addresses": " ".join(r["addresses"])}

    started = time.time()
    with ThreadPoolExecutor(args.workers) as pool:
        rows = list(pool.map(one, jobs))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    failed = sum(r["rcode"] in ("TIMEOUT", "SERVFAIL") for r in rows)
    print(json.dumps({"queries": len(rows), "failed": failed, "seconds": round(time.time() - started, 1)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
