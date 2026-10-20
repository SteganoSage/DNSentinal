#!/usr/bin/env python3
"""Experiment E9, the end-to-end half: what the DGA classifier costs the
resolver as a whole (EVALUATION.md E9: < 1% change with a warm verdict
cache). dnsperf sends a stream of queries to the real daemon in three setups:

    off    ml.dga off
    cold   ml.dga on, cache_size 0: every query is scored, as if every name were new
    warm   ml.dga on, the verdict cache on: names were judged already (the usual case)

The answers come from the resolver's own cache (it is warmed first), so the
runs time the resolver's work, not the fake authoritative servers'. Like
tests/integration/offline_e2e.py, it runs in a private network namespace
against fake servers, with neither internet nor root.

    bench/scripts/e9_end_to_end.py build/release/dnsentinel [--seconds 10] [--repeats 3]

Needs dnsperf (sudo apt install dnsperf). Writes bench/results/e9/end_to_end.csv
and end_to_end.json; build the daemon with -DCMAKE_BUILD_TYPE=Release.

On a laptop (WSL especially) a run now and then lands on a slower core and
loses ~25% at random, whatever the setup; the setups are interleaved and
the summary leads with each setup's best run, the mean beside it.
"""

import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "tests", "integration"))
import offline_e2e as harness  # noqa: E402  (the fake servers and the daemon wrapper)

IN_NETNS = "DNSENTINEL_E9_IN_NETNS"
SKIP = 77
SETUPS = ("off", "cold", "warm")


def reexec_in_netns():
    unshare = ["unshare", "--user", "--map-root-user", "--net"]
    if not shutil.which("unshare") or not shutil.which("ip"):
        print("skipped: needs unshare(1) and ip(8)")
        return SKIP
    if subprocess.run(unshare + ["true"], capture_output=True).returncode != 0:
        print("skipped: can't create a user + network namespace here")
        return SKIP
    env = dict(os.environ, **{IN_NETNS: "1"})
    return subprocess.run(unshare + [sys.executable, os.path.abspath(__file__), *sys.argv[1:]], env=env).returncode


def test_names():
    """The parity fixture's names, moved under .info (served by the fake .info server)."""
    labels = []
    with open(os.path.join(REPO, "tests", "unit", "ml", "dga_parity.tsv")) as f:
        for line in f:
            if line.startswith("#"):
                continue
            name = line.split("\t", 1)[0].lower().rstrip(".")
            parts = name.split(".")
            if len(parts) >= 2 and all(p and all(c.isalnum() or c in "-_" for c in p) for p in parts):
                labels.append(parts[-2] if len(parts[-2]) > 1 else parts[0])
    return [f"www.{label}.info" for label in dict.fromkeys(labels) if not label.startswith("-") and not label.endswith("-")]


def ml_section(setup):
    if setup == "off":
        return None
    return (f"  dga:\n    enabled: true\n    mode: monitor\n    model: {REPO}/models/dga\n"
            f"    words: {REPO}/config/english_words.txt\n    cache_size: {0 if setup == 'cold' else 100000}\n")


def dnsperf(queries, seconds, extra=()):
    command = ["dnsperf", "-s", harness.DAEMON[0], "-p", str(harness.DAEMON[1]), "-d", queries, "-l", str(seconds),
               "-c", "4", "-q", "100", *extra]
    return subprocess.run(command, capture_output=True, text=True, timeout=seconds + 60).stdout


def parse(output):
    def number(label):
        match = re.search(label + r":\s+([0-9.]+)", output)
        return float(match.group(1)) if match else None
    return {"qps": number("Queries per second"), "avg_latency_us": (number("Average Latency \\(s\\)") or 0) * 1e6,
            "latency_stdev_us": (number("Latency StdDev \\(s\\)") or 0) * 1e6,
            "completed": number("Queries completed"), "lost": number("Queries lost")}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("binary")
    parser.add_argument("--seconds", type=int, default=10)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--out", default=os.path.join(REPO, "bench", "results", "e9"))
    parser.add_argument("--setups", default=",".join(SETUPS), help="which of off, cold, warm to run")
    args = parser.parse_args()
    if not shutil.which("dnsperf"):
        print("needs dnsperf: sudo apt install dnsperf", file=sys.stderr)
        return 2
    if os.environ.get(IN_NETNS) != "1":
        return reexec_in_netns()

    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    names = test_names()
    records = harness.ZONES[harness.INFO_IP]["records"]
    for i, name in enumerate(names):
        records[(name, harness.A)] = [f"198.51.100.{i % 250 + 1}"]
    servers = harness.FakeServers()
    os.makedirs(args.out, exist_ok=True)
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        queries = os.path.join(tmp, "queries.txt")
        with open(queries, "w") as f:
            f.write("".join(f"{name} A\n" for name in names))
        for repeat in range(args.repeats):
            for setup in args.setups.split(","):  # interleaved, so drift over time hits every setup alike
                config = harness.write_config(tmp, rate_limit="  per_client: { qps: 0 }\n", ml=ml_section(setup))
                daemon = harness.Daemon(os.path.abspath(args.binary), config)
                try:
                    if not daemon.wait_for("listening on udp") or not daemon.wait_for("primed the root"):
                        print(f"{setup}: the daemon didn't start\n" + "\n".join(daemon.log), file=sys.stderr)
                        return 1
                    dnsperf(queries, 30, ["-n", "1", "-c", "1", "-q", "20"])  # warm the resolver's cache
                    result = parse(dnsperf(queries, args.seconds))
                finally:
                    daemon.stop()
                summary_line = next((line for line in daemon.log if "dga since startup" in line), "")
                if summary_line:
                    print("        " + summary_line.split("dnsentinel: ", 1)[-1], flush=True)
                result.update(setup=setup, repeat=repeat + 1, names=len(names))
                rows.append(result)
                print(f"{setup:5} run {repeat + 1}: {result['qps']:9.0f} queries/s, average latency "
                      f"{result['avg_latency_us']:7.1f} µs, {result['lost']:.0f} lost", flush=True)

    with open(os.path.join(args.out, "end_to_end.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, ["setup", "repeat", "names", "qps", "avg_latency_us", "latency_stdev_us",
                                    "completed", "lost"])
        writer.writeheader()
        writer.writerows(rows)
    summary = {}
    setups = [s for s in SETUPS if any(r["setup"] == s for r in rows)]
    for setup in setups:
        mine = [r for r in rows if r["setup"] == setup]
        best = max(mine, key=lambda r: r["qps"])
        summary[setup] = {"qps_best": best["qps"], "avg_latency_us_best": best["avg_latency_us"],
                          "qps_mean": sum(r["qps"] for r in mine) / len(mine),
                          "avg_latency_us_mean": sum(r["avg_latency_us"] for r in mine) / len(mine),
                          "qps_runs": [r["qps"] for r in mine]}
    for setup in [s for s in ("cold", "warm") if s in summary and "off" in summary]:
        for kind in ("best", "mean"):
            summary[setup][f"qps_change_vs_off_pct_{kind}"] = 100 * (
                summary[setup][f"qps_{kind}"] / summary["off"][f"qps_{kind}"] - 1)
    summary["target"] = "warm: < 1% change from off"
    with open(os.path.join(args.out, "end_to_end.json"), "w") as f:
        json.dump(summary, f, indent=1)
    print()
    print(f"{'':5} {'best run':>24} {'mean of runs':>24}")
    for setup in setups:
        s = summary[setup]
        best = f"{s['qps_best']:7.0f} q/s" + (f" {s['qps_change_vs_off_pct_best']:+6.1f}%" if setup != "off" else " " * 8)
        mean = f"{s['qps_mean']:7.0f} q/s" + (f" {s['qps_change_vs_off_pct_mean']:+6.1f}%" if setup != "off" else " " * 8)
        print(f"{setup:5} {best:>24} {mean:>24}")
    print(f"wrote {args.out}/end_to_end.csv and end_to_end.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
