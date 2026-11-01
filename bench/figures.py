#!/usr/bin/env python3
"""Every table and figure of the report, from the raw results (EVALUATION.md §9 rule 10: nothing by hand).

    python3 bench/figures.py              # the latest run of each experiment
    python3 bench/figures.py P1           # one experiment
    python3 bench/figures.py P1 --run bench/results/P1/20261101T180000Z

Tables go to bench/tables/ (Markdown and CSV), figures to bench/plots/ (PNG).
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
RESULTS, TABLES, PLOTS = REPO / "bench" / "results", REPO / "bench" / "tables", REPO / "bench" / "plots"


def latest(experiment: str) -> Path | None:
    runs = sorted(p for p in (RESULTS / experiment).glob("*Z") if (p / "summary.json").exists()) \
        if (RESULTS / experiment).exists() else []
    return runs[-1] if runs else None


def write_table(name: str, header: list[str], rows: list[list], caption: str) -> None:
    TABLES.mkdir(parents=True, exist_ok=True)
    with open(TABLES / f"{name}.csv", "w", newline="") as stream:
        csv.writer(stream).writerows([header, *rows])
    lines = [f"**{caption}**", "", "| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    lines += ["| " + " | ".join("" if v is None else str(v) for v in row) + " |" for row in rows]
    (TABLES / f"{name}.md").write_text("\n".join(lines) + "\n")
    print(f"  {TABLES.relative_to(REPO)}/{name}.md")


def median(values):
    values = [v for v in values if v is not None]
    return round(statistics.median(values), 1) if values else None


def span(values):
    """median (min-max) over repetitions, as text."""
    values = [v for v in values if v is not None]
    if not values:
        return "—"
    m = statistics.median(values)
    fmt = (lambda v: f"{v:.0f}") if max(abs(v) for v in values) >= 100 else (lambda v: f"{v:.1f}")
    return fmt(m) if min(values) == max(values) else f"{fmt(m)} ({fmt(min(values))}–{fmt(max(values))})"


# ─── E1 ──────────────────────────────────────────────────────────────────────

def e1(run: Path) -> None:
    s = json.loads((run / "summary.json").read_text())
    rows = []
    for kind, label in (("w3", "W3: Tranco top 10,000 × {A, AAAA}"), ("hierarchy", "Crafted hierarchy cases"),
                        ("policy", "Policy (by design)")):
        part = s["sets"].get(kind)
        if part:
            rows.append([label, part["queries"], f"{part['agreement']:.2%}", json.dumps(part["mismatches"]) or "{}",
                         f"{part['servfail']['dnsentinel']:.2%}", f"{part['servfail']['unbound']:.2%}"])
    write_table("T1_correctness", ["Name set", "Queries", "Agreement", "Mismatches (re-checked)",
                                   "SERVFAIL DNSentinel", "SERVFAIL Unbound"], rows,
                f"Table T1. DNSentinel vs Unbound (lab; overall {s['agreement']:.2%}, target ≥ 99%)")


# ─── P1 ──────────────────────────────────────────────────────────────────────

def p1(run: Path) -> None:
    s = json.loads((run / "summary.json").read_text())
    configs = s["configs"]
    security, cost = [], []
    for name, entry in configs.items():
        runs = entry["runs"]
        get = lambda section, key: [r[section][key] for r in runs]
        security.append([
            name, entry["label"],
            f"{span(get('dga', 'c2_reached_families'))}/9",
            f"{span(get('dga', 'c2_reached'))}/{span(get('dga', 'c2_lookups'))}",
            f"{span(get('dga', 'tries_flagged'))}/{span(get('dga', 'tries'))}",
            span(get("iodine", "exfiltrated_kib")),
            span(get("iodine", "exfil_seconds")),
            span(get("iodine", "alert_s")),
            span(get("slow_tunnel", "carried_bytes")),
            span(get("slow_tunnel", "alert_s")),
        ])
        cost.append([
            name, entry["label"],
            span(get("benign", "p50_ms")), span(get("benign", "p95_ms")), span(get("benign", "p99_ms")),
            span(get("benign", "wrongly_blocked")), span(get("benign", "false_alerts")),
            span(get("cost", "cpu_mean")), span(get("cost", "mem_max_mib")),
            span(get("cost", "analyzer_cpu_mean")), span(get("cost", "max_qps_under_1pct_loss")),
        ])
    reps = len(next(iter(configs.values()))["runs"])
    write_table("P1_security", ["Config", "", "DGA command servers reached", "C2 lookups answered",
                                "Generated names flagged", "iodine: KiB exfiltrated", "iodine: s until stopped",
                                "iodine: s to alert", "Slow tunnel: bytes carried", "Slow tunnel: s to alert"],
                security, f"Table P1a. What gets through, per configuration (median (min–max) of {reps} runs, 240 s each)")
    write_table("P1_cost", ["Config", "", "Benign p50 ms", "p95 ms", "p99 ms", "Benign blocked", "False alerts",
                            "Resolver CPU %", "Resolver MiB", "Analyzer CPU %", "Max q/s (<1% loss)"],
                cost, f"Table P1b. What it costs, per configuration (median (min–max) of {reps} runs)")

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    PLOTS.mkdir(parents=True, exist_ok=True)
    names = list(configs)
    fig, axes = plt.subplots(1, 2, figsize=(11, 3.8))
    exfil = [median([r["iodine"]["exfiltrated_kib"] for r in configs[n]["runs"]]) or 0 for n in names]
    reached = [median([r["dga"]["c2_reached"] for r in configs[n]["runs"]]) or 0 for n in names]
    axes[0].bar(names, exfil, color="#4c72b0")
    axes[0].set_ylabel("KiB exfiltrated through iodine")
    axes[0].set_title("Real iodine tunnel, 240 s")
    axes[1].bar(names, reached, color="#c44e52")
    axes[1].set_ylabel("Command-server lookups answered")
    axes[1].set_title("DGA malware, 9 real families")
    for ax in axes:
        ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(PLOTS / "P1_what_gets_through.png", dpi=150)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(6.5, 4))
    for n in names:
        latencies = []
        for rep_dir in sorted(run.glob(f"{n}-r*")):
            path = rep_dir / "benign.csv"
            if path.exists():
                latencies += [float(r["latency_ms"]) for r in csv.DictReader(open(path)) if r["rcode"] != "TIMEOUT"]
        if latencies:
            latencies.sort()
            ax.plot(latencies, [i / len(latencies) for i in range(len(latencies))], label=f"{n} {configs[n]['label']}")
    ax.set_xscale("log")
    ax.set_xlabel("Benign query latency (ms, log)")
    ax.set_ylabel("Fraction of queries")
    ax.set_title("Benign latency per configuration (CDF)")
    ax.grid(alpha=0.3)
    ax.legend(fontsize=6.5, loc="lower right")
    fig.tight_layout()
    fig.savefig(PLOTS / "P1_benign_latency_cdf.png", dpi=150)
    plt.close(fig)
    print(f"  {PLOTS.relative_to(REPO)}/P1_what_gets_through.png, P1_benign_latency_cdf.png")


def e2(run: Path) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    s = json.loads((run / "summary.json").read_text())["resolvers"]
    colour = {"dnsentinel": "#4c72b0", "unbound": "#c44e52"}
    rows = []
    for name, entry in s.items():
        for phase in ("cold", "warm"):
            p = entry[phase]
            rows.append([name, phase, p["queries"], p["p50_ms"], p["p95_ms"], p["p99_ms"], p["mean_ms"]])
        rows.append([name, "max q/s <1% loss", "", entry.get("max_qps_under_1pct_loss"), "", "", ""])
    write_table("E2_latency_throughput", ["Resolver", "Phase", "Queries", "p50 ms / q/s", "p95 ms", "p99 ms",
                                          "mean ms"], rows, "Table E2. Latency (cold/warm) and max throughput")

    # F1: latency CDFs (cold and warm), DNSentinel vs Unbound
    fig, axes = plt.subplots(1, 2, figsize=(11, 4))
    for ax, phase in zip(axes, ("cold", "warm")):
        for name, entry in s.items():
            lat = []
            for path in sorted(run.glob(f"{name}-{phase}-r*.csv")):
                lat += [float(r["latency_ms"]) for r in csv.DictReader(open(path)) if r["rcode"] != "TIMEOUT"]
            if lat:
                lat.sort()
                ax.plot(lat, [i / len(lat) for i in range(len(lat))], label=name, color=colour.get(name))
        ax.set_xscale("log")
        ax.set_xlabel("latency (ms, log)")
        ax.set_ylabel("fraction of queries")
        ax.set_title(f"{phase} cache")
        ax.grid(alpha=0.3, which="both")
        ax.legend()
    fig.suptitle("F1: query latency CDF, DNSentinel vs Unbound (lab)")
    fig.tight_layout()
    fig.savefig(PLOTS / "F1_latency_cdf.png", dpi=150)
    plt.close(fig)

    # F2: throughput — offered rate vs achieved qps, with the 1% loss point
    fig, ax = plt.subplots(figsize=(6.5, 4.5))
    for name, entry in s.items():
        rates = [r["rate"] for r in entry["sweep"]]
        qps = [r["qps"] for r in entry["sweep"]]
        ax.plot(rates, qps, "o-", label=name, color=colour.get(name))
        if entry.get("max_qps_under_1pct_loss"):
            ax.axhline(entry["max_qps_under_1pct_loss"], color=colour.get(name), ls=":", lw=1)
    ax.plot([0, max(max(r["rate"] for r in e["sweep"]) for e in s.values())],
            [0, max(max(r["rate"] for r in e["sweep"]) for e in s.values())], "k--", lw=0.7, label="offered = achieved")
    ax.set_xlabel("offered rate (queries/s)")
    ax.set_ylabel("achieved queries/s")
    ax.set_title("F2: throughput vs offered load (warm cache)")
    ax.grid(alpha=0.3)
    ax.legend()
    fig.tight_layout()
    fig.savefig(PLOTS / "F2_throughput.png", dpi=150)
    plt.close(fig)
    print(f"  {PLOTS.relative_to(REPO)}/F1_latency_cdf.png, F2_throughput.png")


MAKERS = {"E1": e1, "E2": e2, "P1": p1}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("experiments", nargs="*", default=list(MAKERS))
    parser.add_argument("--run", type=Path, help="this run instead of the latest")
    args = parser.parse_args()
    for experiment in args.experiments:
        run = args.run or latest(experiment)
        if run is None:
            print(f"{experiment}: no run yet")
            continue
        print(f"{experiment}: {run.relative_to(REPO)}")
        MAKERS[experiment](run)
    return 0


if __name__ == "__main__":
    sys.exit(main())
