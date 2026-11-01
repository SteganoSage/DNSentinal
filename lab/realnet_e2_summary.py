#!/usr/bin/env python3
"""Reduce the real-internet E2 latency CSVs to p50/p95/p99 per resolver and phase, and print a table."""
import csv, json, statistics, sys
from pathlib import Path

out = Path(sys.argv[1])
def pct(v, q):
    v = sorted(x for x in v if x is not None)
    return round(v[min(len(v) - 1, int(q * len(v)))], 3) if v else None

summary = {"resolvers": {}}
for resolver in ("dnsentinel", "unbound"):
    entry = {}
    for phase in ("cold", "warm"):
        f = out / f"{resolver}-{phase}.csv"
        if not f.exists(): continue
        lat = [float(r["latency_ms"]) for r in csv.DictReader(open(f)) if r["rcode"] not in ("TIMEOUT",)]
        fails = sum(1 for r in csv.DictReader(open(f)) if r["rcode"] in ("TIMEOUT", "SERVFAIL"))
        entry[phase] = {"queries": len(lat), "p50_ms": pct(lat, 0.5), "p95_ms": pct(lat, 0.95),
                        "p99_ms": pct(lat, 0.99), "mean_ms": round(statistics.mean(lat), 3) if lat else None,
                        "failed": fails}
    summary["resolvers"][resolver] = entry
(out / "summary.json").write_text(json.dumps(summary, indent=1))
print(f"{'resolver':11} {'phase':5} {'p50':>8} {'p95':>8} {'p99':>8} {'mean':>8}  failed")
for r, e in summary["resolvers"].items():
    for ph, v in e.items():
        print(f"{r:11} {ph:5} {v['p50_ms']:>8} {v['p95_ms']:>8} {v['p99_ms']:>8} {v['mean_ms']:>8}  {v['failed']}")
