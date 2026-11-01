"""E1 — correctness against a production resolver (EVALUATION.md E1), in the lab.

DNSentinel and Unbound resolve the same names from the lab's root, both from a cold cache. The
names come in three sets:
- W3: Tranco's top names, as the lab hierarchy serves them;
- hierarchy: every crafted case of lab/hierarchy (CNAME chains, deep and glueless delegations,
  a lame server, no-0x20, out-of-bailiwick records, a large TXT, empty non-terminals, NXDOMAIN);
- policy: names DNSentinel's policy is meant to answer differently (block lists, cloaked
  trackers, rebinding). They are reported apart, not counted against agreement.
"""

from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path

from run import LAB, RESULTS

HIERARCHY = [
    ("www.example.lab", "A"), ("www.example.lab", "AAAA"), ("example.lab", "A"), ("example.lab", "MX"),
    ("big.example.lab", "TXT"), ("alias.example.lab", "A"), ("a.b.c.example.lab", "A"), ("b.c.example.lab", "A"),
    ("c.example.lab", "A"), ("nothing.example.lab", "A"), ("nothing.lab", "A"), ("www.bank.lab", "A"),
    ("ttl1.example.lab", "A"), ("ttl60.example.lab", "A"), ("ttl3600.example.lab", "A"), ("ttl86400.example.lab", "A"),
    *[(f"chain{n}.example.lab", "A") for n in range(1, 9)],
    ("www.e.d.c.b.a.deep.lab", "A"), ("www.noglue.lab", "A"), ("www.example.net", "A"), ("www.lame.lab", "A"),
    ("www.nocase.lab", "A"), ("www.slow.lab", "A"), ("www.attacker.lab", "A"), ("login.bank.lab", "A"),
    ("www.mdexmtiwmjia.info", "A"),
]
POLICY = [("ads.example.lab", "A"), ("metrics.example.lab", "A"), ("metrics.cloaked.lab", "A"),
          ("collect.tracker.lab", "A"), ("collect.tracker.lab", "AAAA"), ("router.example.lab", "A")]


def names(params: dict) -> list[tuple[str, str, str]]:
    popular = [line.split(",", 1)[1].strip() for line in (LAB / "hierarchy" / "out" / "popular.txt").read_text().splitlines()
               if line.strip()][: int(params.get("popular", 10000))]
    rows = [(name, qtype, "w3") for name in popular for qtype in params.get("types", ["A", "AAAA"])]
    rows += [(name, qtype, "hierarchy") for name, qtype in HIERARCHY]
    rows += [(name, qtype, "policy") for name, qtype in POLICY]
    return rows


def run(lab, params: dict, out: Path) -> dict:
    if params.get("cold", True):
        lab.restart("dnsentinel", "unbound")
    jobs = names(params)
    (out / "names.txt").write_text("".join(f"{n} {t} {s}\n" for n, t, s in jobs))
    inside = Path("/bench-results") / out.relative_to(RESULTS)
    report = lab.exec("client", "python3", "/dnsentinel/bench/drivers/e1_compare.py",
                      "--names", str(inside / "names.txt"), "--out", str(inside / "e1.csv"),
                      "--test", "10.53.1.2", "--baseline", "10.53.1.3", "--rate", str(params.get("rate", 80)),
                      timeout=3600)
    rows = list(csv.DictReader(open(out / "e1.csv")))
    summary: dict = {"driver": json.loads(report.strip().splitlines()[-1]), "sets": {}}
    for kind in ("w3", "hierarchy", "policy"):
        part = [r for r in rows if r["set"] == kind]
        if not part:
            continue
        agreed = sum(int(r["agree"]) for r in part)
        summary["sets"][kind] = {
            "queries": len(part), "agree": agreed, "agreement": round(agreed / len(part), 5),
            "mismatches": dict(Counter(r["recheck"] for r in part if r["agree"] == "0")),
            "servfail": {"dnsentinel": sum(r["test_rcode"] in ("SERVFAIL", "TIMEOUT") for r in part) / len(part),
                         "unbound": sum(r["base_rcode"] in ("SERVFAIL", "TIMEOUT") for r in part) / len(part)},
        }
    correctness = [r for r in rows if r["set"] != "policy"]
    agreed = sum(int(r["agree"]) for r in correctness)
    summary["agreement"] = round(agreed / len(correctness), 5)  # W3 and the hierarchy: the card's number
    summary["target"] = ">= 0.99 agreement, no unexplained persistent mismatch"
    summary["met"] = summary["agreement"] >= 0.99
    mismatches = [r for r in rows if r["agree"] == "0"]
    with open(out / "mismatches.csv", "w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]) + ["explanation"])
        writer.writeheader()
        for r in mismatches:  # explanation: filled in by hand after review (EVALUATION.md E1)
            writer.writerow({**r, "explanation": "policy (by design)" if r["set"] == "policy" else ""})
    summary["persistent_mismatches"] = [f"{r['name']} {r['type']}: {r['test_rcode']} {r['test_addresses']} vs "
                                        f"{r['base_rcode']} {r['base_addresses']}"
                                        for r in mismatches if r["recheck"] == "persistent" and r["set"] != "policy"][:50]
    return summary
