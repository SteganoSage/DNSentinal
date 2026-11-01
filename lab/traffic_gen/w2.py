#!/usr/bin/env python3
"""Workload W2 (EVALUATION.md §3.5): a synthetic query trace over the lab's names.

    python3 lab/traffic_gen/w2.py --popular lab/hierarchy/out/popular.txt --queries 20000 --out w2.txt

Names are drawn with Zipf popularity over the lab's popular sites (rank r drawn with probability
proportional to 1 / r^s), each as one of its hosts (www, apex, cdn, api, mail). Arrivals are
Poisson at --rate a second. The card fits s to W1; with no W1 here, s is an assumption
(--zipf, default 0.9, as DNS measurements commonly find), and the report must say so.

Writes "name type" lines (dnsperf's query file format), and, with --times, a second file of
"offset_seconds name type" lines for a timed replay. A fixed --seed gives the same trace every
time (EVALUATION.md §9 rule 8).
"""

from __future__ import annotations

import argparse
import bisect
import random
from pathlib import Path

HOSTS = (("www", "A", 0.55), ("", "A", 0.15), ("www", "AAAA", 0.15), ("cdn", "A", 0.08), ("api", "A", 0.05),
         ("mail", "A", 0.02))


def trace(names: list[str], queries: int, zipf: float, rate: float, seed: int) -> list[tuple[float, str, str]]:
    rng = random.Random(seed)
    weights = [1.0 / (rank ** zipf) for rank in range(1, len(names) + 1)]
    cumulative, total = [], 0.0
    for w in weights:
        total += w
        cumulative.append(total)
    host_cumulative, acc = [], 0.0
    for _host, _type, share in HOSTS:
        acc += share
        host_cumulative.append(acc)
    out, t = [], 0.0
    for _ in range(queries):
        name = names[bisect.bisect_left(cumulative, rng.random() * total)]
        host, qtype, _ = HOSTS[min(bisect.bisect_left(host_cumulative, rng.random() * acc), len(HOSTS) - 1)]
        t += rng.expovariate(rate)
        out.append((t, f"{host}.{name}" if host else name, qtype))
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--popular", type=Path, required=True, help="'rank,domain' lines (lab/hierarchy/out/popular.txt)")
    parser.add_argument("--queries", type=int, default=20000)
    parser.add_argument("--zipf", type=float, default=0.9)
    parser.add_argument("--rate", type=float, default=100.0, help="Poisson arrivals a second (for --times)")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--times", type=Path, help="also write the timed trace here")
    args = parser.parse_args()
    names = [line.split(",", 1)[1].strip() for line in args.popular.read_text().splitlines() if "," in line]
    rows = trace(names, args.queries, args.zipf, args.rate, args.seed)
    args.out.write_text("".join(f"{name} {qtype}\n" for _t, name, qtype in rows))
    if args.times:
        args.times.write_text("".join(f"{t:.6f} {name} {qtype}\n" for t, name, qtype in rows))
    distinct = len({(n, q) for _t, n, q in rows})
    print(f"{args.out}: {len(rows)} queries, {distinct} distinct (zipf {args.zipf}, seed {args.seed})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
