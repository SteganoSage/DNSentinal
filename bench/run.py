#!/usr/bin/env python3
"""The benchmark harness (EVALUATION.md §3.6): run one experiment, keep its raw results and how they were made.

    python3 bench/run.py bench/configs/E1.yaml              # one run, as the config says
    python3 bench/run.py bench/configs/E1.yaml --set reps=3  # override a parameter

Each run gets its own folder, bench/results/<experiment>/<UTC time>/, holding:
- the experiment's raw CSVs;
- summary.json, its numbers;
- metadata.json: git commit (and whether the tree was dirty), the SHA-256 of every config the
  lab used, the lab's image IDs, kernel, CPU, tool versions, the seed and the parameters.

Nothing is plotted here: bench/figures.py (`make -C bench figures`) draws every figure and
table from these folders. Experiments live in bench/experiments/<module>.py, as
run(lab, params, out) -> summary dict; the config names the module and its parameters.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib
import json
import os
import platform
import random
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
LAB = REPO / "lab"
RESULTS = REPO / "bench" / "results"
COMPOSE = ["docker", "compose", "-f", str(LAB / "docker-compose.yml")]
IMAGES = ("dnsentinel-lab/tools", "dnsentinel-lab/dnsentinel", "dnsentinel-lab/analyzer")


def sh(command: list[str], check: bool = True, timeout: float | None = None, env: dict | None = None) -> str:
    done = subprocess.run(command, capture_output=True, text=True, timeout=timeout,
                          env=None if env is None else os.environ | env)
    if check and done.returncode != 0:
        raise RuntimeError(f"{' '.join(command)} failed ({done.returncode}): {done.stderr.strip()[-2000:]}")
    return done.stdout


class Lab:
    """The lab's containers, for experiments: run commands, restart for a cold cache, shape links, read metrics."""

    def exec(self, service: str, *command: str, check: bool = True, timeout: float | None = None) -> str:
        return sh(COMPOSE + ["exec", "-T", service, *command], check=check, timeout=timeout)

    def restart(self, *services: str, wait_primed: bool = True) -> None:
        """Restart (a cold cache for a resolver), then wait until DNSentinel has primed the root again."""
        sh(COMPOSE + ["restart", *services])
        if "dnsentinel" in services and wait_primed:
            self.wait_for_log("dnsentinel", "primed the root", since=services)

    def wait_for_log(self, service: str, text: str, timeout: float = 30, since=None) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            logs = sh(COMPOSE + ["logs", "--since", "60s", service], check=False)
            if text in logs:
                return
            time.sleep(0.5)
        raise RuntimeError(f"{service} never logged {text!r}")

    def recreate(self, service: str, env: dict | None = None, wait_primed: bool = True) -> None:
        """Recreate a service with these compose variables (DNSENTINEL_CONFIG, ANALYZER_JUDGE, ...)."""
        sh(COMPOSE + ["up", "-d", "--force-recreate", "--no-deps", service], env=env or {})
        if service == "dnsentinel" and wait_primed:
            self.wait_for_log("dnsentinel", "primed the root")

    def stop(self, *services: str) -> None:
        sh(COMPOSE + ["stop", *services], check=False)

    def detach(self, service: str, *command: str) -> None:
        """Start a command in a service and return at once (it runs until it ends or is killed)."""
        sh(COMPOSE + ["exec", "-d", "-T", service, *command])

    def stats(self) -> list[dict]:
        """CPU (% of one core) and memory (MiB) of every running container, now."""
        out = sh(["docker", "stats", "--no-stream", "--format", "{{.Name}},{{.CPUPerc}},{{.MemUsage}}"], check=False)
        rows = []
        for line in out.splitlines():
            name, cpu, mem = line.split(",", 2)
            used = mem.split("/")[0].strip()
            factor = {"KiB": 1 / 1024, "MiB": 1, "GiB": 1024, "B": 1 / 1048576}
            unit = next((u for u in ("KiB", "MiB", "GiB", "B") if used.endswith(u)), "MiB")
            rows.append({"container": name.replace("dnsentinel-lab-", "").rsplit("-", 1)[0],
                         "cpu": float(cpu.rstrip("%") or 0), "mem_mib": float(used[: -len(unit)] or 0) * factor[unit]})
        return rows

    def netem(self, service: str, interface: str = "eth0", spec: str | None = None) -> None:
        """Shape a container's interface with tc netem ("delay 30ms loss 1%"); None clears it."""
        self.exec(service, "tc", "qdisc", "del", "dev", interface, "root", check=False)
        if spec:
            self.exec(service, "tc", "qdisc", "add", "dev", interface, "root", "netem", *spec.split())

    def metrics(self) -> dict[str, float]:
        text = self.exec("client", "curl", "-s", "http://10.53.1.2:9153/metrics")
        values = {}
        for line in text.splitlines():
            if line and not line.startswith("#"):
                key, _, value = line.rpartition(" ")
                values[key] = float(value)
        return values

    def running(self) -> bool:
        return "dnsentinel" in sh(COMPOSE + ["ps", "--services", "--status", "running"], check=False)


def metadata(config_path: Path, params: dict, seed: int) -> dict:
    def digest(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    commit = sh(["git", "-C", str(REPO), "rev-parse", "HEAD"], check=False).strip()
    dirty = bool(sh(["git", "-C", str(REPO), "status", "--porcelain", "--untracked-files=no"], check=False).strip())
    images = {}
    for image in IMAGES:
        images[image] = sh(["docker", "image", "inspect", "--format", "{{.Id}}", image], check=False).strip()
    configs = {str(p.relative_to(REPO)): digest(p) for p in sorted((LAB / "config").glob("*")) if p.is_file()}
    configs[str(config_path.relative_to(REPO)) if config_path.is_relative_to(REPO) else str(config_path)] = digest(config_path)
    for generated in ("root.hints", "popular.txt"):
        path = LAB / "hierarchy" / "out" / generated
        if path.exists():
            configs[str(path.relative_to(REPO))] = digest(path)
    cpu = ""
    try:
        cpu = next(line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines()
                   if line.startswith("model name"))
    except (OSError, StopIteration):
        pass
    return {"started": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "git_commit": commit,
            "git_dirty": dirty, "configs": configs, "images": images, "kernel": platform.release(),
            "machine": platform.machine(), "cpu": cpu, "python": platform.python_version(),
            "docker": sh(["docker", "version", "--format", "{{.Server.Version}}"], check=False).strip(),
            "seed": seed, "params": params}


def parse_value(text: str):
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("config", type=Path)
    parser.add_argument("--set", action="append", default=[], metavar="KEY=VALUE", help="override a parameter")
    parser.add_argument("--note", default="", help="why this run (kept in metadata.json)")
    args = parser.parse_args()

    import yaml  # PyYAML: python3-yaml on Ubuntu

    config = yaml.safe_load(args.config.read_text())
    params = dict(config.get("params") or {})
    for item in args.set:
        key, _, value = item.partition("=")
        params[key] = parse_value(value)
    seed = int(params.get("seed", 1))
    random.seed(seed)
    experiment = config["experiment"]
    out = RESULTS / experiment / dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out.mkdir(parents=True)
    meta = metadata(args.config.resolve(), params, seed) | {"experiment": experiment, "note": args.note,
                                                           "module": config["module"]}
    (out / "metadata.json").write_text(json.dumps(meta, indent=1) + "\n")

    lab = Lab()
    if config.get("needs_lab", True) and not lab.running():
        print("bench: the lab is not up: lab/lab.sh up", file=sys.stderr)
        return 1
    module = importlib.import_module(f"experiments.{config['module']}")
    started = time.time()
    summary = module.run(lab, params, out)
    meta["seconds"] = round(time.time() - started, 1)
    (out / "metadata.json").write_text(json.dumps(meta, indent=1) + "\n")
    (out / "summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    print(json.dumps(summary, indent=1))
    print(f"bench: {out.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    sys.exit(main())
