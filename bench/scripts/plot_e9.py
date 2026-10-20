#!/usr/bin/env python3
"""Figure F12 (EVALUATION.md E9): what the DGA classifier costs.

(a) per name, in the resolver's C++: the time to score a first-seen name and
    to answer one from the verdict cache (bench/dga_latency.cpp), as the
    share of names done within a time, against E9's 50 µs target;
(b) end to end: queries per second through the daemon with ML off, on with
    the verdict cache, and on scoring every query (bench/scripts/e9_end_to_end.py),
    each setup's best run.

    python3 bench/scripts/plot_e9.py [bench/results/e9] [bench/plots/F12_dga_overhead.png]
"""

import csv
import json
import os
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.ticker import FuncFormatter, PercentFormatter  # noqa: E402

SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK_SECONDARY = "#52514e"
GRID = "#e4e3df"
SCORED = "#2a78d6"  # categorical slot 1: a name scored (first seen, or every query in "cold")
CACHED = "#eb6834"  # slot 2: a name answered from the verdict cache
TARGET_US = 50


def axes_style(ax):
    ax.set_facecolor(SURFACE)
    ax.grid(color=GRID, linewidth=0.8, zorder=0)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(INK_SECONDARY)
    ax.tick_params(colors=INK_SECONDARY, labelsize=9)


def ecdf(values):
    values = sorted(values)
    return values, [(i + 1) / len(values) for i in range(len(values))]


def main():
    results = sys.argv[1] if len(sys.argv) > 1 else "bench/results/e9"
    out = sys.argv[2] if len(sys.argv) > 2 else "bench/plots/F12_dga_overhead.png"
    with open(os.path.join(results, "dga_latency.csv")) as f:
        rows = list(csv.DictReader(f))
    cold = [float(r["cold_us"]) for r in rows]
    warm = [float(r["warm_us"]) for r in rows]
    end_to_end = os.path.join(results, "end_to_end.json")
    summary = json.load(open(end_to_end)) if os.path.exists(end_to_end) else None

    fig, axes = plt.subplots(1, 2 if summary else 1, figsize=(10.5 if summary else 6, 4.2), facecolor=SURFACE,
                             gridspec_kw={"width_ratios": [1.25, 1]} if summary else None)
    ax = axes[0] if summary else axes

    # Each median labelled on the side away from the other curve.
    for values, color, label, side in ((cold, SCORED, "first-seen name (scored)", -1),
                                       (warm, CACHED, "seen before (verdict cache)", 1)):
        x, y = ecdf(values)
        ax.step(x, y, where="post", color=color, linewidth=2, label=label, zorder=3)
        median = x[len(x) // 2]
        ax.plot([median], [0.5], "o", color=color, markersize=6, markeredgecolor=SURFACE, markeredgewidth=2, zorder=4)
        ax.annotate(f"median {median:.1f} µs", (median, 0.5), xytext=(8 * side, 0), textcoords="offset points",
                    ha="left" if side > 0 else "right", va="center", fontsize=8.5, color=INK_SECONDARY)
    ax.axvline(TARGET_US, color=INK_SECONDARY, linewidth=1, linestyle=":", zorder=2)
    ax.annotate(f"E9 target: {TARGET_US} µs median", (TARGET_US, 0.04), xytext=(4, 0), textcoords="offset points",
                fontsize=8, color=INK_SECONDARY)
    ax.set_xscale("log")
    ax.xaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:g}"))
    ax.set_ylim(0, 1.02)
    ax.yaxis.set_major_formatter(PercentFormatter(1.0))
    ax.set_xlabel("Time per name in the resolver (µs, log scale)", color=INK, fontsize=10)
    ax.set_ylabel("Names done within that time", color=INK, fontsize=10)
    ax.set_title(f"(a) Scoring a name ({len(rows)} names)", color=INK, fontsize=11, loc="left")
    ax.legend(loc="center", bbox_to_anchor=(0.5, 0.78), frameon=False, fontsize=9)  # the gap between the curves
    axes_style(ax)

    if summary:
        bx = axes[1]
        setups = [("off", "ML off", INK_SECONDARY), ("warm", "ML on, verdict cache", CACHED),
                  ("cold", "ML on, every query scored", SCORED)]
        setups = [s for s in setups if s[0] in summary]
        values = [summary[key]["qps_best"] for key, _, _ in setups]
        y = list(range(len(setups)))[::-1]
        bx.barh(y, values, height=0.5, color=[c for _, _, c in setups], edgecolor=SURFACE, linewidth=2, zorder=3)
        for yi, (key, _, _), value in zip(y, setups, values):
            change = summary[key].get("qps_change_vs_off_pct_best")
            text = f"{value:,.0f}" + (f"  ({change:+.1f}%)".replace("-", "\u2212") if change is not None else "")
            bx.annotate(text, (value, yi), xytext=(4, 0), textcoords="offset points", va="center", fontsize=8.5,
                        color=INK_SECONDARY)
        bx.set_yticks(y, [label for _, label, _ in setups], fontsize=9, color=INK)
        bx.set_xlim(0, max(values) * 1.35)
        bx.xaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v / 1000:g}k"))
        bx.set_xlabel("Queries per second (best of the runs)", color=INK, fontsize=10)
        bx.set_title("(b) The whole resolver, under load", color=INK, fontsize=11, loc="left")
        axes_style(bx)
        bx.grid(axis="y", visible=False)

    fig.tight_layout()
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    fig.savefig(out, dpi=200, facecolor=SURFACE)
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
