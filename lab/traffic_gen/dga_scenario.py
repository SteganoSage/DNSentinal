#!/usr/bin/env python3
"""The DGA malware of the pipeline experiment: real families' names, and one command server each.

    python3 lab/traffic_gen/dga_scenario.py --netlab ml/data/external_netlab.csv --out lab/traffic_gen/dga_families.txt

For each family, it picks --tries real names Netlab observed (the generated names malware tries,
which mostly don't exist), and one more as its live command server, which the lab's hierarchy
makes resolve. The command server is under a TLD the lab has, or under ddns.net for corebot.
The output ("family role name" lines) is committed, so the lab is the same without ml/data.
Seeded: the same file every time.
"""

from __future__ import annotations

import argparse
import csv
import random
from collections import defaultdict
from pathlib import Path

# easy to hard for a name-only classifier; simda builds names from syllables, suppobox from words,
# corebot's are under dynamic DNS (ddns.net), which the resolver still scores
FAMILIES = ("ramnit", "necurs", "murofet", "dircrypt", "qadars", "ramdo", "corebot", "simda", "suppobox")
LAB_TLDS = ("com", "net", "org", "info")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--netlab", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--tries", type=int, default=40)
    parser.add_argument("--seed", type=int, default=1)
    args = parser.parse_args()
    names: dict[str, list[str]] = defaultdict(list)
    for row in csv.DictReader(open(args.netlab)):
        if row["family"] in FAMILIES:
            names[row["family"]].append(row["domain"].lower())
    rng = random.Random(args.seed)
    lines = ["# family role name: real DGA names (Netlab); `c2` resolves in the lab (lab/hierarchy/build.py)"]
    for family in FAMILIES:
        pool = sorted(set(names[family]))
        rng.shuffle(pool)
        servable = [n for n in pool if n.endswith(".ddns.net") or
                    (n.count(".") == 1 and n.rsplit(".", 1)[1] in LAB_TLDS)]
        c2 = servable[0]
        tries = [n for n in pool if n != c2][: args.tries]
        lines += [f"{family} try {n}" for n in tries] + [f"{family} c2 {c2}"]
    args.out.write_text("\n".join(lines) + "\n")
    print(f"{args.out}: {len(FAMILIES)} families, {args.tries} tries and 1 command server each")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
