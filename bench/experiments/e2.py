"""E2 — latency and throughput (EVALUATION.md E2), DNSentinel vs Unbound in the lab.

Three parts, per resolver:
- **cold:** restart the resolver (empty cache), then resolve the W2 names once each at a gentle rate,
  timing every query. Cold latency is dominated by walking the hierarchy from the root.
- **warm:** replay the same names again on the now-warm cache; these are cache hits.
- **load sweep:** dnsperf raises the offered rate in steps until loss passes 1%; record qps and loss.

The W2 trace (`lab/traffic_gen/w2.py`, a fixed seed) and the resolvers are the same for both, so the
comparison is fair. Latency CDFs → F1; throughput vs offered load → F2.
"""

from __future__ import annotations

import csv
import json
import statistics
from pathlib import Path

from run import LAB, RESULTS, sh

ADDRESS = {"unbound": "10.53.1.3", "dnsentinel": "10.53.1.2"}
DRIVERS = "/dnsentinel/bench/drivers"


def pct(values: list[float], q: float):
    values = sorted(v for v in values if v is not None)
    return round(values[min(len(values) - 1, int(q * len(values)))], 3) if values else None


def latency(lab, resolver: str, names_inside: str, out_inside: str, rate: int) -> None:
    lab.exec("client", "python3", f"{DRIVERS}/latency.py", "--server", ADDRESS[resolver], "--names", names_inside,
             "--rate", str(rate), "--out", out_inside, timeout=600)


def dnsperf(lab, resolver: str, names_inside: str, rate: int, seconds: int) -> dict:
    out = lab.exec("client", "dnsperf", "-s", ADDRESS[resolver], "-d", names_inside, "-Q", str(rate),
                   "-l", str(seconds), "-c", "4", "-T", "2", "-t", "3", check=False, timeout=seconds + 30)
    row = {"rate": rate}
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Queries sent:"):
            row["sent"] = int(line.split()[2])
        elif line.startswith("Queries completed:"):
            row["completed"] = int(line.split()[2])
        elif line.startswith("Queries lost:"):
            row["lost"] = int(line.split()[2])
        elif line.startswith("Queries per second:"):
            row["qps"] = float(line.split()[3])
        elif line.startswith("Average Latency (s):"):
            value = float(line.split()[3]) * 1000
            row["avg_ms"] = round(value, 3) if value < 1e6 else None  # dnsperf prints junk here when saturated
    row["loss"] = round(row.get("lost", 0) / max(1, row.get("sent", 1)), 4)
    return row


def run(lab, params: dict, out: Path) -> dict:
    count = int(params.get("queries", 5000))
    sh(["python3", str(LAB / "traffic_gen" / "w2.py"), "--popular", str(LAB / "hierarchy" / "out" / "popular.txt"),
        "--queries", str(count), "--seed", str(params.get("seed", 1)), "--out", str(out / "w2.txt")])
    inside_dir = Path("/bench-results") / out.relative_to(RESULTS)
    names_inside = str(inside_dir / "w2.txt")
    resolvers = params.get("resolvers", ["unbound", "dnsentinel"])
    sweep_rates = params.get("sweep", [1000, 2000, 5000, 10000, 20000, 30000, 40000, 50000])
    summary: dict = {"resolvers": {}}

    for rep in range(1, int(params.get("reps", 3)) + 1):
        for resolver in resolvers:
            lab.restart(resolver if resolver == "dnsentinel" else "unbound")
            lab.exec("client", "dig", f"@{ADDRESS[resolver]}", "www.example.lab", "+short", check=False)  # prime root
            latency(lab, resolver, names_inside, str(inside_dir / f"{resolver}-cold-r{rep}.csv"),
                    int(params.get("cold_rate", 100)))
            latency(lab, resolver, names_inside, str(inside_dir / f"{resolver}-warm-r{rep}.csv"),
                    int(params.get("warm_rate", 200)))

    for resolver in resolvers:
        entry: dict = {"cold": {}, "warm": {}, "sweep": []}
        for phase in ("cold", "warm"):
            lat = []
            for path in sorted(out.glob(f"{resolver}-{phase}-r*.csv")):
                lat += [float(r["latency_ms"]) for r in csv.DictReader(open(path)) if r["rcode"] not in ("TIMEOUT",)]
            entry[phase] = {"queries": len(lat), "p50_ms": pct(lat, 0.5), "p95_ms": pct(lat, 0.95),
                            "p99_ms": pct(lat, 0.99),
                            "mean_ms": round(statistics.mean(lat), 3) if lat else None}
        # throughput sweep, on a warm cache (so it is the resolver's own speed, not upstream RTT);
        # offered rate up in steps, stop one past the first >1% loss
        lab.restart(resolver if resolver == "dnsentinel" else "unbound")
        lab.exec("client", "dig", f"@{ADDRESS[resolver]}", "www.example.lab", "+short", check=False)
        dnsperf(lab, resolver, names_inside, 2000, 10)  # warm the cache with the whole trace
        for rate in sweep_rates:
            result = dnsperf(lab, resolver, names_inside, rate, int(params.get("sweep_seconds", 8)))
            entry["sweep"].append(result)
            if result["loss"] > 0.01:
                break
        good = [s for s in entry["sweep"] if s["loss"] <= 0.01]
        entry["max_qps_under_1pct_loss"] = max((s["qps"] for s in good), default=None)
        (out / f"{resolver}-sweep.json").write_text(json.dumps(entry["sweep"], indent=1))
        summary["resolvers"][resolver] = entry

    lab.recreate("dnsentinel", {})
    lab.recreate("unbound", {})
    d = summary["resolvers"].get("dnsentinel", {})
    summary["targets"] = {
        "warm_p50_under_1ms": (d.get("warm", {}).get("p50_ms") or 9) < 1.0,
        "cold_p50_within_1.5x_unbound": (
            d.get("cold", {}).get("p50_ms") and summary["resolvers"].get("unbound", {}).get("cold", {}).get("p50_ms")
            and d["cold"]["p50_ms"] <= 1.5 * summary["resolvers"]["unbound"]["cold"]["p50_ms"]),
    }
    return summary
