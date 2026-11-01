"""The full pipeline, end to end (docs/results.md Part 3): what each layer adds, and what it costs.

The same traffic runs under every configuration, all at once, from four lab hosts:
- benign browsing (client 10.53.1.10): W2 replayed at 50 queries/s;
- DGA malware (infected2 .21): 9 real families, 40 generated names each, then its command server,
  re-resolved every 3 s (bench/drivers/dga_malware.py);
- a real iodine tunnel (infected .20) pushing random data to a byte counter at its far end
  (bench/drivers/sink.py, on iodined);
- a slow tunnel (infected3 .22): 0.2 TXT queries/s of fresh encoded names (bench/drivers/tunnel_synthetic.py).

Configurations (CONFIGS): C0 is Unbound, the standard resolver. C1 to C6 are DNSentinel with its
layers added one by one. After the traffic, a dnsperf sweep measures throughput.
Each (configuration, repetition) has its own folder of raw data; summary.json reduces them.
"""

from __future__ import annotations

import copy
import csv
import json
import statistics
import threading
import time
from pathlib import Path

import yaml

from run import LAB, REPO, RESULTS, sh

CONFIGS = {
    "C0": {"resolver": "unbound", "dga": None, "slow": None, "label": "Unbound (standard resolver)"},
    "C1": {"resolver": "dnsentinel", "dga": None, "slow": None, "label": "DNSentinel, no ML"},
    "C2": {"resolver": "dnsentinel", "dga": "monitor", "slow": None, "label": "+ DGA classifier, monitor"},
    "C3": {"resolver": "dnsentinel", "dga": "enforce", "slow": None, "label": "+ DGA classifier, enforce"},
    "C4": {"resolver": "dnsentinel", "dga": "enforce", "slow": "rules", "label": "+ slow path, hand-written rules"},
    "C5": {"resolver": "dnsentinel", "dga": "enforce", "slow": "model", "label": "+ slow path, model + fusion (all)"},
    "C6": {"resolver": "dnsentinel", "dga": "monitor", "slow": "model", "label": "DGA monitor + model + fusion"},
}
ADDRESS = {"unbound": "10.53.1.3", "dnsentinel": "10.53.1.2"}
HOSTS = {"benign": "10.53.1.10", "iodine": "10.53.1.20", "dga": "10.53.1.21", "slow_tunnel": "10.53.1.22"}
DRIVERS = "/dnsentinel/bench/drivers"


def config_file(name: str, spec: dict) -> str:
    """DNSentinel's config for this configuration, written under lab/state; its path in the container."""
    base = yaml.safe_load((LAB / "config" / "dnsentinel.yaml").read_text())
    config = copy.deepcopy(base)
    if spec["dga"] is None:
        config["ml"]["dga"]["enabled"] = False
    else:
        config["ml"]["dga"]["enabled"] = True
        config["ml"]["dga"]["mode"] = spec["dga"]
    path = LAB / "state" / "configs" / f"{name}.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"# the pipeline experiment's {name}: {spec['label']}\n" + yaml.safe_dump(config, sort_keys=False))
    return "/dnsentinel/" + str(path.relative_to(REPO))


def unbound_file() -> str:
    """Unbound for C0: its config, with QNAME minimisation off. With it on, iodine stalls through Unbound
    (6 KiB in 30 s against 4.3 MiB without): an interop quirk, not a defence (docs/experiment-log.md)."""
    text = (LAB / "config" / "unbound.conf").read_text().replace("qname-minimisation: yes", "qname-minimisation: no")
    path = LAB / "state" / "configs" / "unbound-C0.conf"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return "/dnsentinel/" + str(path.relative_to(REPO))


CLEAN = 'pkill -x iodine; pkill -x nc; pkill -f "^python3 /dnsentinel/bench/drivers"; true'  # never matches this sh


def percentile(values: list[float], q: float) -> float | None:
    if not values:
        return None
    values = sorted(values)
    return values[min(len(values) - 1, int(q * len(values)))]


def wait_file(path: Path, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists() and path.stat().st_size > 0:
            return True
        time.sleep(1)
    return False


def dnsperf(lab, server: str, queries: str, rate: int, seconds: int) -> dict:
    out = lab.exec("client", "dnsperf", "-s", server, "-d", queries, "-Q", str(rate), "-l", str(seconds),
                   "-c", "4", "-T", "2", "-t", "2", check=False, timeout=seconds + 30)
    found = {}
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Queries sent:"):
            found["sent"] = int(line.split()[2])
        elif line.startswith("Queries lost:"):
            found["lost"] = int(line.split()[2])
        elif line.startswith("Queries per second:"):
            found["qps"] = float(line.split()[3])
        elif line.startswith("Average Latency (s):"):
            found["avg_latency_ms"] = float(line.split()[3]) * 1000
    found["rate"] = rate
    found["loss"] = found.get("lost", 0) / max(1, found.get("sent", 1))
    return found


def one_run(lab, name: str, spec: dict, rep: int, out: Path, params: dict) -> dict:
    run = out / f"{name}-r{rep}"
    run.mkdir(parents=True)
    inside = Path("/bench-results") / run.relative_to(RESULTS)
    server = ADDRESS[spec["resolver"]]
    seconds = float(params.get("seconds", 240))

    # the resolvers, fresh: cold caches, no rules left from the last run
    for host in ("infected", "infected2", "infected3", "client", "iodined"):
        lab.exec(host, "sh", "-c", CLEAN, check=False)
    alerts_inside = f"/results/runs/{out.name}-{name}-r{rep}.jsonl"
    if spec["resolver"] == "unbound":
        lab.recreate("unbound", {"UNBOUND_CONFIG": unbound_file()})
        lab.stop("analyzer")
    else:
        lab.recreate("dnsentinel", {"DNSENTINEL_CONFIG": config_file(name, spec)})
        if spec["slow"]:
            judge = "--model models/tunnel" if spec["slow"] == "model" else ""
            lab.recreate("analyzer", {"ANALYZER_JUDGE": judge, "ANALYZER_ALERTS": alerts_inside})
            lab.wait_for_log("analyzer", "connected to")
        else:
            lab.stop("analyzer")
    lab.restart("iodined", wait_primed=False)
    time.sleep(2)

    # the traffic, all at once
    started = time.time()
    lab.detach("iodined", "python3", f"{DRIVERS}/sink.py", "--listen", "172.30.0.1", "--out", str(inside / "sink.csv"))
    # lazy mode off (-L0): with it on, iodine stalls through Unbound; off, every configuration gets the same tunnel
    lab.detach("infected", "sh", "-c", f"exec iodine -f -r -L0 -P labsecret {server} tunnel.lab > {inside}/iodine.log 2>&1")
    lab.detach("client", "python3", f"{DRIVERS}/latency.py", "--server", server, "--names",
               str(Path("/bench-results") / out.relative_to(RESULTS) / "w2.txt"), "--rate", str(params.get("benign_rate", 50)),
               "--out", str(inside / "benign.csv"))
    lab.detach("infected2", "python3", f"{DRIVERS}/dga_malware.py", "--server", server,
               "--families", "/dnsentinel/lab/traffic_gen/dga_families.txt", "--out", str(inside / "dga.csv"))
    lab.detach("infected3", "python3", f"{DRIVERS}/tunnel_synthetic.py", "--server", server, "--domain", "exfil.lab",
               "--rate", str(params.get("slow_rate", 0.2)), "--seconds", str(seconds), "--out", str(inside / "slow_tunnel.csv"))

    tunnel_up = None
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        log = (run / "iodine.log").read_text(errors="replace") if (run / "iodine.log").exists() else ""
        if "Connection setup complete" in log:
            tunnel_up = time.time()
            lab.detach("infected", "sh", "-c", "head -c 200000000 /dev/urandom | nc -N 172.30.0.1 9000")
            break
        time.sleep(0.5)

    samples, stop = [], threading.Event()

    def sample():
        while not stop.is_set():
            for row in lab.stats():
                if row["container"] in ("dnsentinel", "analyzer", "unbound"):
                    samples.append({"t": time.time(), **row})
            stop.wait(5)

    sampler = threading.Thread(target=sample, daemon=True)
    sampler.start()
    while time.time() - started < seconds:
        time.sleep(1)
    for path in ("benign.csv", "dga.csv", "slow_tunnel.csv"):
        wait_file(run / path, 120)
    stop.set()
    sampler.join()
    lab.exec("infected", "sh", "-c", CLEAN, check=False)
    lab.exec("iodined", "sh", "-c", CLEAN, check=False)  # SIGTERM: the sink writes its last row
    time.sleep(1)
    with open(run / "stats.csv", "w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["t", "container", "cpu", "mem_mib"])
        writer.writeheader()
        writer.writerows(samples)

    # throughput: dnsperf over the benign trace, the rate raised until losses pass 1%
    sweep = []
    for rate in params.get("sweep", [2000, 5000, 10000, 20000, 40000]):
        result = dnsperf(lab, server, str(Path("/bench-results") / out.relative_to(RESULTS) / "w2.txt"), rate,
                         int(params.get("sweep_seconds", 5)))
        sweep.append(result)
        if result["loss"] > 0.01:
            break
    (run / "sweep.json").write_text(json.dumps(sweep, indent=1))
    alerts_host = LAB / "results" / "runs" / f"{out.name}-{name}-r{rep}.jsonl"
    alerts = [json.loads(line) for line in alerts_host.read_text().splitlines()] if alerts_host.exists() else []
    (run / "alerts.jsonl").write_text("".join(json.dumps(a) + "\n" for a in alerts))
    return reduce_run(run, spec, started, tunnel_up, alerts, sweep, samples)


def reduce_run(run: Path, spec: dict, started: float, tunnel_up: float | None, alerts: list[dict], sweep: list[dict],
               samples: list[dict]) -> dict:
    def rows(name):
        path = run / name
        return list(csv.DictReader(open(path))) if path.exists() and path.stat().st_size else []

    benign = rows("benign.csv")
    latency = [float(r["latency_ms"]) for r in benign if r["rcode"] not in ("TIMEOUT",)]
    wrongly_blocked = sum(1 for r in benign if r["rcode"] == "NXDOMAIN" or set(r["addresses"].split()) & {"0.0.0.0", "::"})
    dga = rows("dga.csv")
    families = sorted({r["family"] for r in dga})
    reached = {f: [r for r in dga if r["family"] == f and r["reached"] == "1"] for f in families}
    lookups = {f: [r for r in dga if r["family"] == f and r["role"] != "try"] for f in families}
    tries_flagged = sum(1 for r in dga if r["role"] == "try" and set(r["addresses"].split()) & {"0.0.0.0", "::"})
    slow = rows("slow_tunnel.csv")
    slow_blocked_at = next((float(r["t"]) for r in slow if r["rcode"] == "NXDOMAIN"), None)
    sink = rows("sink.csv")
    exfil = [(float(r["t"]), int(r["bytes"])) for r in sink]
    total = exfil[-1][1] if exfil else 0
    last_growth = None
    for (t0, b0), (t1, b1) in zip(exfil, exfil[1:]):
        if b1 > b0:
            last_growth = t1
    by_client: dict[str, list[dict]] = {}
    for a in alerts:
        by_client.setdefault(a.get("client") or a.get("client_id", ""), []).append(a)

    def first_alert(client: str, kind: str | None = None) -> float | None:
        times = [a["window_end"] for a in by_client.get(client, []) if "window_end" in a and (kind is None or a["alert"] == kind)]
        return min(times) - started if times else None

    def cost(container: str, key: str, agg) -> float | None:
        values = [s[key] for s in samples if s["container"] == container]
        return round(agg(values), 1) if values else None

    resolver = "unbound" if spec["resolver"] == "unbound" else "dnsentinel"
    good = [s for s in sweep if s.get("loss", 1) <= 0.01]
    return {
        "benign": {"queries": len(benign), "p50_ms": percentile(latency, 0.5), "p95_ms": percentile(latency, 0.95),
                   "p99_ms": percentile(latency, 0.99), "failed": sum(r["rcode"] in ("TIMEOUT", "SERVFAIL") for r in benign),
                   "wrongly_blocked": wrongly_blocked, "false_alerts": len(by_client.get(HOSTS["benign"], []))},
        "dga": {"families": len(families),
                "c2_reached_families": sum(1 for f in families if reached[f]),
                "c2_lookups": sum(len(v) for v in lookups.values()),
                "c2_reached": sum(len(v) for v in reached.values()),
                "tries": sum(1 for r in dga if r["role"] == "try"), "tries_flagged": tries_flagged,
                "per_family": {f: f"{len(reached[f])}/{len(lookups[f])}" for f in families},
                "c2_alerts": sum(1 for a in by_client.get(HOSTS["dga"], []) if a["alert"] == "dga_c2"),
                "burst_alerts": sum(1 for a in by_client.get(HOSTS["dga"], []) if a["alert"] == "nxdomain_burst")},
        "iodine": {"connected": tunnel_up is not None,
                   "connect_s": round(tunnel_up - started, 1) if tunnel_up else None,
                   "exfiltrated_kib": round(total / 1024, 1),
                   "exfil_seconds": round(last_growth - tunnel_up, 1) if last_growth and tunnel_up else None,
                   "alert_s": (round(first_alert(HOSTS["iodine"], "tunnel") - (tunnel_up - started), 1)
                               if tunnel_up and first_alert(HOSTS["iodine"], "tunnel") is not None else None)},
        "slow_tunnel": {"queries": len(slow), "answered": sum(1 for r in slow if r["rcode"] == "NOERROR"),
                        "carried_bytes": sum(int(r["carried"]) for r in slow),
                        "blocked_s": round(slow_blocked_at, 1) if slow_blocked_at is not None else None,
                        "alert_s": round(first_alert(HOSTS["slow_tunnel"], "tunnel"), 1)
                        if first_alert(HOSTS["slow_tunnel"], "tunnel") is not None else None},
        "cost": {"cpu_mean": cost(resolver, "cpu", statistics.mean), "cpu_max": cost(resolver, "cpu", max),
                 "mem_max_mib": cost(resolver, "mem_mib", max),
                 "analyzer_cpu_mean": cost("analyzer", "cpu", statistics.mean),
                 "analyzer_mem_max_mib": cost("analyzer", "mem_mib", max),
                 "max_qps_under_1pct_loss": max((s["qps"] for s in good), default=None)},
    }


def run(lab, params: dict, out: Path) -> dict:
    seconds = float(params.get("seconds", 240))
    rate = float(params.get("benign_rate", 50))
    sh(["python3", str(LAB / "traffic_gen" / "w2.py"), "--popular", str(LAB / "hierarchy" / "out" / "popular.txt"),
        "--queries", str(int(seconds * rate)), "--seed", str(params.get("seed", 1)), "--out", str(out / "w2.txt")])
    (LAB / "results" / "runs").mkdir(parents=True, exist_ok=True)
    configs = params.get("configs", list(CONFIGS))
    reps = int(params.get("reps", 3))
    results: dict[str, list[dict]] = {}
    for rep in range(1, reps + 1):  # interleaved: a slow moment of the machine hits every configuration alike
        for name in configs:
            print(f"pipeline: {name} ({CONFIGS[name]['label']}), repetition {rep}/{reps}", flush=True)
            result = one_run(lab, name, CONFIGS[name], rep, out, params)
            (out / f"{name}-r{rep}" / "result.json").write_text(json.dumps(result, indent=1))
            results.setdefault(name, []).append(result)
    # leave the lab as it was: the default config, the full slow path
    lab.recreate("dnsentinel", {})
    lab.recreate("analyzer", {})
    lab.recreate("unbound", {})
    return {"configs": {name: {"label": CONFIGS[name]["label"], "runs": runs} for name, runs in results.items()}}
