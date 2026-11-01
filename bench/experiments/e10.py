"""E10 — abuse resistance (EVALUATION.md E10), in the lab. Two defences, measured:

1. **Open-resolver refusal (R5).** A client outside `access.allow` (the `outside` network) queries
   DNSentinel. It must get REFUSED and cause no upstream query — an open resolver is the root of
   DNS amplification abuse.
2. **NXNS amplification cap (R5).** `nxns.lab` (lab/servers/quirks.py) answers every query with a
   referral to `--fanout` nameservers that have no glue and cannot be resolved (the NXNSAttack
   pattern). A naive resolver would chase all of them, at every level. DNSentinel's
   `resolver.max_upstream_queries` bounds the work. We resolve a fresh `nxns.lab` name and count the
   upstream queries it costs, against a normal name's cost and the configured cap.

Fresh random labels each time, so nothing is answered from cache.
"""

from __future__ import annotations

import json
import random
import string
from pathlib import Path


from run import LAB  # noqa: F401

RESOLVER, OUTSIDE_VIEW = "10.53.1.2", "10.53.3.2"
DNSQ = "/dnsentinel/lab/tools/dnsq.py"


def rand(n: int = 10) -> str:
    return "".join(random.choice(string.ascii_lowercase) for _ in range(n))


def ask(lab, host: str, server: str, name: str, qtype: str = "A") -> dict:
    return json.loads(lab.exec(host, "python3", DNSQ, server, name, qtype, timeout=30))


def run(lab, params: dict, out: Path) -> dict:
    lab.restart("dnsentinel")
    lab.exec("client", "python3", DNSQ, RESOLVER, "www.example.lab", "A", check=False)  # prime the root
    cap = int(params.get("cap", 30))  # resolver.max_upstream_queries default
    trials = int(params.get("trials", 10))

    def cost(host: str, server: str, name: str, qtype: str = "A") -> tuple[dict, int]:
        before = lab.metrics().get("dnsentinel_upstream_queries_total", 0)
        answer = ask(lab, host, server, name, qtype)
        after = lab.metrics().get("dnsentinel_upstream_queries_total", 0)
        return answer, int(after - before)

    # 1. open-resolver refusal
    refusals = [ask(lab, "outsider", OUTSIDE_VIEW, f"{rand()}.example.lab") for _ in range(trials)]
    before = lab.metrics().get("dnsentinel_upstream_queries_total", 0)
    for _ in range(trials):
        ask(lab, "outsider", OUTSIDE_VIEW, f"{rand()}.example.lab")
    outsider_upstream = int(lab.metrics().get("dnsentinel_upstream_queries_total", 0) - before)
    refused = sum(r["rcode"] == "REFUSED" for r in refusals)

    # 2. NXNS cap: normal name vs a malicious nxns.lab name
    normal, nxns = [], []
    for _ in range(trials):
        _, c = cost("client", RESOLVER, f"www.{rand()}.example.lab")  # a fresh subdomain, one delegation
        normal.append(c)
        answer, c = cost("client", RESOLVER, f"{rand()}.{rand()}.nxns.lab")
        nxns.append((answer["rcode"], c))
    nxns_cost = [c for _r, c in nxns]

    summary = {
        "open_resolver": {
            "trials": trials, "refused": refused,
            "upstream_queries_caused_by_outsider": outsider_upstream,
            "note": "outsider is on 10.53.3.0/24, outside access.allow",
        },
        "nxns_cap": {
            "fanout_advertised_per_referral": int(params.get("fanout", 20)),
            "configured_cap": cap,
            "normal_name_upstream_median": sorted(normal)[len(normal) // 2] if normal else None,
            "normal_name_upstream_max": max(normal) if normal else None,
            "nxns_name_upstream_median": sorted(nxns_cost)[len(nxns_cost) // 2] if nxns_cost else None,
            "nxns_name_upstream_max": max(nxns_cost) if nxns_cost else None,
            "nxns_rcodes": sorted({r for r, _c in nxns}),
        },
        "targets": {
            "all_outsiders_refused": refused == trials,
            "no_upstream_for_outsiders": outsider_upstream == 0,
            "nxns_bounded_by_cap": (max(nxns_cost) if nxns_cost else 0) <= cap,
        },
    }
    (out / "raw.json").write_text(json.dumps({"normal_upstream": normal, "nxns": nxns}, indent=1))
    lab.recreate("dnsentinel", {})
    return summary
