#!/usr/bin/env python3
"""A DNS tunnel at a set rate, for the pipeline experiment: fresh base32 names under one domain, TXT.

    python3 bench/drivers/tunnel_synthetic.py --server 10.53.1.2 --domain tunnel.lab --rate 0.2 --seconds 240 --out t.csv

It encodes --chunk bytes of random data per query, as tunnels do. One CSV row per query: t, name,
rcode, and `carried`: the bytes that query exfiltrated if it was answered (NOERROR), else 0.
"""

from __future__ import annotations

import argparse
import base64
import csv
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "lab" / "tools"))
from dnsq import query  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--server", required=True)
    parser.add_argument("--domain", default="tunnel.lab")
    parser.add_argument("--rate", type=float, default=2.0, help="queries a second")
    parser.add_argument("--seconds", type=float, default=240.0)
    parser.add_argument("--chunk", type=int, default=25, help="bytes of data per query")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    rng = random.Random(args.seed)
    start, rows, i = time.monotonic(), [], 0
    while time.monotonic() - start < args.seconds:
        payload = base64.b32encode(rng.randbytes(args.chunk)).decode().rstrip("=").lower()
        name = f"{payload}.s{i}.{args.domain}"
        r = query(args.server, name, "TXT", timeout=3.0)
        rows.append({"t": f"{time.monotonic() - start:.3f}", "name": name, "rcode": r["rcode"],
                     "carried": args.chunk if r["rcode"] == "NOERROR" else 0})
        i += 1
        time.sleep(max(0.0, start + i / args.rate - time.monotonic()))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print(f"{len(rows)} queries, {sum(int(r['carried']) for r in rows)} bytes carried")
    return 0


if __name__ == "__main__":
    sys.exit(main())
