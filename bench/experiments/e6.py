"""E6 — privacy: what each observer sees (EVALUATION.md E6), in the lab.

Two observers, two defences, measured by capturing real packets (tcpdump) and reading the query
names out of them with the project's own parser (ml/tunnel/pcap.py):

1. **On the client's link (encrypted transport).** An eavesdropper between the client and DNSentinel
   captures the client's traffic. The client asks for three unique marker names, one over plain UDP,
   one over DoT, one over DoH. How many of the three marker names are readable in the capture?
   Plain DNS exposes the name; DoT/DoH should expose none.

2. **At the root and TLD servers (QNAME minimisation).** DNSentinel, cold, resolves one fresh deep
   name `<marker>.sub.example.lab`. We capture at the root (10.53.2.10) and the lab-TLD (10.53.2.11).
   With QNAME minimisation on, the root should be asked only about `lab`, the TLD only about
   `example.lab`; the leaf marker should reach neither. With it off, both see the full name.

Markers are random, so a name seen in a capture can only have come from this run.
"""

from __future__ import annotations

import json
import random
import string
import subprocess
import time
from pathlib import Path

import yaml

from run import LAB, REPO, sh

RESOLVER = "10.53.1.2"
DNSQ = "/dnsentinel/lab/tools/dnsq.py"
CA = "/dnsentinel/lab/state/certs/ca.crt"


def marker() -> str:
    return "zz" + "".join(random.choice(string.ascii_lowercase) for _ in range(10))


def qnames_in(pcap: Path) -> list[str]:
    """Every query name the parser can read out of the capture (empty for encrypted traffic)."""
    if not pcap.exists() or pcap.stat().st_size == 0:
        return []
    out = subprocess.run(["python3", "-m", "ml.tunnel.pcap", str(pcap)], cwd=REPO, capture_output=True, text=True)
    names = []
    for line in out.stdout.splitlines()[1:]:  # skip the CSV header
        parts = line.split(",")
        if len(parts) >= 3:
            names.append(parts[2].lower())
    return names


def capture(lab, service: str, host_pcap: Path, seconds: int, do) -> list[str]:
    """Run tcpdump in `service` for `seconds` while `do()` sends traffic; return the names captured."""
    inside = "/results/" + host_pcap.name
    lab.detach(service, "sh", "-c", f"timeout {seconds} tcpdump -i any -w {inside} -U 'udp or tcp' 2>/dev/null")
    time.sleep(1.5)  # let tcpdump start
    do()
    time.sleep(2)
    for _ in range(seconds):  # wait out the capture window so the file is flushed and closed
        if not lab.exec(service, "sh", "-c", "pgrep -x tcpdump || true").strip():
            break
        time.sleep(1)
    return qnames_in(host_pcap)


def run(lab, params: dict, out: Path) -> dict:
    results_dir = LAB / "results"
    summary: dict = {}

    # 1. the client's link: plain vs DoT vs DoH
    lab.recreate("dnsentinel", {})
    lab.exec("client", "python3", DNSQ, RESOLVER, "www.example.lab", "A", check=False)  # prime
    m_udp, m_dot, m_doh = f"{marker()}.udp.example.lab", f"{marker()}.dot.example.lab", f"{marker()}.doh.example.lab"
    pcap = results_dir / "e6-client.pcap"
    pcap.unlink(missing_ok=True)

    def client_queries():
        lab.exec("client", "python3", DNSQ, RESOLVER, m_udp, "A", check=False)
        lab.exec("client", "python3", DNSQ, "--dot", "--ca", CA, "--hostname", "dns.lab", RESOLVER, m_dot, "A",
                 check=False)
        lab.exec("client", "python3", DNSQ, "--doh", "--ca", CA, "--hostname", "dns.lab", RESOLVER, m_doh, "A",
                 check=False)

    seen = capture(lab, "client", pcap, int(params.get("window", 12)), client_queries)
    exposed = {"udp": any(m_udp.split(".")[0] in n for n in seen),
               "dot": any(m_dot.split(".")[0] in n for n in seen),
               "doh": any(m_doh.split(".")[0] in n for n in seen)}
    summary["client_link"] = {
        "markers_readable_in_capture": exposed,
        "queries_parsed_from_capture": len(seen),
        "note": "a name is 'readable' if its random marker label appears in the parsed capture",
    }

    # 2. the root and TLD servers: QNAME minimisation on vs off
    base = yaml.safe_load((LAB / "config" / "dnsentinel.yaml").read_text())
    summary["qname_minimisation"] = {}
    for setting in (True, False):
        config = yaml.safe_load(json.dumps(base))
        config["resolver"]["qname_minimisation"] = setting
        path = LAB / "state" / "configs" / f"e6-min-{setting}.yaml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump(config, sort_keys=False))
        lab.recreate("dnsentinel", {"DNSENTINEL_CONFIG": "/dnsentinel/" + str(path.relative_to(REPO))})
        m = marker()
        leaf = f"{m}.sub.example.lab"
        root_pcap, tld_pcap = results_dir / f"e6-root-{setting}.pcap", results_dir / f"e6-tld-{setting}.pcap"
        for p in (root_pcap, tld_pcap):
            p.unlink(missing_ok=True)
        # capture at root and TLD at once, then resolve the fresh deep name (cold: just recreated)
        inside_root, inside_tld = "/results/" + root_pcap.name, "/results/" + tld_pcap.name
        win = int(params.get("window", 12))
        lab.detach("root", "sh", "-c", f"timeout {win} tcpdump -i any -w {inside_root} -U 'udp or tcp' 2>/dev/null")
        lab.detach("tld", "sh", "-c", f"timeout {win} tcpdump -i any -w {inside_tld} -U 'udp or tcp' 2>/dev/null")
        time.sleep(1.5)
        lab.exec("client", "python3", DNSQ, RESOLVER, leaf, "A", check=False)
        time.sleep(2)
        for _ in range(win):
            if not lab.exec("root", "sh", "-c", "pgrep -x tcpdump || true").strip():
                break
            time.sleep(1)
        root_seen, tld_seen = qnames_in(root_pcap), qnames_in(tld_pcap)
        summary["qname_minimisation"][f"min_{'on' if setting else 'off'}"] = {
            "leaf_queried": leaf,
            "root_saw_full_leaf": any(m in n for n in root_seen),
            "tld_saw_full_leaf": any(m in n for n in tld_seen),
            "root_saw": sorted({n for n in root_seen if "example" in n or m in n or n == "lab"})[:8],
            "tld_saw": sorted({n for n in tld_seen if "example" in n or m in n})[:8],
        }

    lab.recreate("dnsentinel", {})
    c = summary["client_link"]["markers_readable_in_capture"]
    mn = summary["qname_minimisation"]
    summary["targets"] = {
        "plain_exposes_name": c["udp"],
        "dot_hides_name": not c["dot"],
        "doh_hides_name": not c["doh"],
        "min_on_hides_leaf_from_root": not mn["min_on"]["root_saw_full_leaf"],
        "min_off_exposes_leaf_to_root": mn["min_off"]["root_saw_full_leaf"],
    }
    return summary
