#!/usr/bin/env python3
"""Plot sim/ns3/link_profiles.cc's results: median DNS lookup latency per link
profile for plain UDP, DoT/DoH on a reused connection, and DoT/DoH on a new
one; whiskers reach the 95th percentile.

    python3 sim/ns3/plot_link_profiles.py results.csv figure.png
"""

import csv
import statistics
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.ticker import FuncFormatter  # noqa: E402

SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK_SECONDARY = "#52514e"
GRID = "#e4e3df"

# Categorical slots 1-3 of the reference palette, validated together (light mode).
# Aqua is below 3:1 on the surface, so its bars carry direct labels.
TRANSPORTS = [
    ("udp", "Plain DNS (UDP)", "#2a78d6"),
    ("tls-reused", "DoT/DoH, reused connection", "#eb6834"),
    ("tls-fresh", "DoT/DoH, new connection", "#1baf7a"),
]


def main():
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    rows = list(csv.DictReader(open(sys.argv[1])))
    profiles = list(dict.fromkeys(r["profile"] for r in rows))

    fig, ax = plt.subplots(figsize=(9, 4.8), facecolor=SURFACE)
    ax.set_facecolor(SURFACE)
    width = 0.27
    for i, (key, label, color) in enumerate(TRANSPORTS):
        medians, p95s = [], []
        for profile in profiles:
            ms = sorted(float(r["latency_ms"]) for r in rows
                        if r["profile"] == profile and r["transport"] == key and r["ok"] == "1")
            medians.append(statistics.median(ms))
            p95s.append(ms[min(len(ms) - 1, round(0.95 * (len(ms) - 1)))])
        xs = [x + (i - 1) * width for x in range(len(profiles))]
        ax.bar(xs, medians, width, label=label, color=color, edgecolor=SURFACE, linewidth=2, zorder=2)
        ax.errorbar(xs, medians, yerr=[[0] * len(medians), [p - m for m, p in zip(medians, p95s)]],
                    fmt="none", ecolor=INK_SECONDARY, elinewidth=1, capsize=3, zorder=3)
        if key == "tls-fresh":  # the median, placed above the whisker so they never collide
            for x, m, p in zip(xs, medians, p95s):
                ax.annotate(f"{m:,.0f} ms", (x, max(m, p)), textcoords="offset points", xytext=(0, 4), ha="center",
                            va="bottom", fontsize=8, color=INK_SECONDARY, zorder=4)

    ax.set_yscale("log")
    ax.yaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:,.0f}"))
    ax.set_xticks(range(len(profiles)), profiles, color=INK)
    ax.set_ylabel("Lookup latency (ms, log scale)", color=INK)
    ax.set_title("DNS lookup latency by access link (ns-3 simulation)\n"
                 "bars: median of 100 lookups · whiskers: 95th percentile", color=INK, fontsize=11)
    ax.tick_params(colors=INK_SECONDARY, which="both")
    ax.grid(axis="y", which="major", color=GRID, linewidth=0.8, zorder=0)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(GRID)
    legend = ax.legend(frameon=False, loc="upper left", fontsize=9)
    for text in legend.get_texts():
        text.set_color(INK)
    fig.tight_layout()
    fig.savefig(sys.argv[2], dpi=150, facecolor=SURFACE)
    print(f"wrote {sys.argv[2]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
