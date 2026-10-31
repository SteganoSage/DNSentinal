"""E8's figures: ROC and precision-recall (cv), F10 (detection vs tunnel rate)
and F11 (detection delay). The pipeline draws them.

The figures show LightGBM, the random forest and the Isolation Forest in the
reference palette's first three slots, and the two baselines in ink; the
other boosting libraries (which tie with LightGBM, as for the DGA model) are
in the metrics only, to keep the lines readable.
"""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

from ..dga.metrics import Curve  # noqa: E402
from ..dga.plots import INK, INK_SECONDARY, SURFACE, _axes  # noqa: E402

STYLE = {  # title, colour, line, marker
    "lgbm": ("LightGBM", "#2a78d6", "-", "o"),
    "rf": ("Random forest", "#eb6834", "-", "s"),
    "iforest": ("Isolation Forest", "#1baf7a", "-", "^"),
    "qpm": ("Queries per minute", INK_SECONDARY, "--", "D"),
    "rules": ("Hand-written rules", INK, ":", "v"),
}


def _shown(names: list[str]) -> list[str]:
    return [n for n in STYLE if n in names]


def _z(name: str) -> int:
    """LightGBM on top where lines coincide, the baselines underneath."""
    return 10 - list(STYLE).index(name)


def curves(scores_path: Path, names: list[str], out: Path, target_fpr: float) -> None:
    """ROC (false-positive rate on a log scale: the operating region) and precision-recall, on windows."""
    scores = np.load(scores_path)
    y = scores["y"].astype(bool)
    fig, (roc, pr) = plt.subplots(1, 2, figsize=(10, 4.4), facecolor=SURFACE)
    floor = 1 / max(int((~y).sum()), 1)
    for name in _shown(names):
        title, color, line, _ = STYLE[name]
        fpr, recall, precision = Curve(y, scores[f"score_{name}"]).points()
        roc.plot(np.maximum(np.r_[0, fpr], floor), np.r_[0, recall], line, color=color, linewidth=1.8,
                 label=title, zorder=_z(name))
        pr.plot(np.r_[0, recall], np.r_[precision[0], precision], line, color=color, linewidth=1.8, label=title,
                zorder=_z(name))
    roc.axvline(target_fpr, color=INK_SECONDARY, linewidth=1, linestyle=":", zorder=2)
    roc.annotate(f"{target_fpr:.2%} FPR", (target_fpr, 0.02), xytext=(4, 0), textcoords="offset points",
                 fontsize=8, color=INK_SECONDARY)
    roc.set_xscale("log")
    roc.set_xlim(floor, 1)
    roc.set_ylim(0, 1.02)
    roc.set_xlabel("False-positive rate (benign windows flagged)", color=INK, fontsize=10)
    roc.set_ylabel("Recall (tunnel windows flagged)", color=INK, fontsize=10)
    roc.set_title("ROC", color=INK, fontsize=11, loc="left")
    pr.set_xlim(0, 1)
    pr.set_ylim(0, 1.02)
    pr.set_xlabel("Recall", color=INK, fontsize=10)
    pr.set_ylabel("Precision", color=INK, fontsize=10)
    pr.set_title("Precision-recall", color=INK, fontsize=11, loc="left")
    for ax in (roc, pr):
        _axes(ax)
    pr.legend(loc="lower left", frameon=False, fontsize=9)
    fig.tight_layout()
    fig.savefig(out, dpi=200, facecolor=SURFACE)
    plt.close(fig)


def recall_vs_rate(report: dict, names: list[str], out: Path, within: float) -> None:
    """F10: share of tunnels caught in time, and of their windows flagged, as the tunnel slows down."""
    fig, (caught, windows) = plt.subplots(1, 2, figsize=(10, 4.2), facecolor=SURFACE, sharex=True)
    for name in _shown(names):
        title, color, line, marker = STYLE[name]
        rates = report["models"][name]["rates"]
        x = [1 / r["slowdown"] for r in rates]
        caught.plot(x, [r["detected"] for r in rates], line, marker=marker, color=color, linewidth=2,
                    markersize=8, markeredgecolor=SURFACE, markeredgewidth=2, label=title, zorder=_z(name))
        windows.plot(x, [r["window_recall"] for r in rates], line, marker=marker, color=color, linewidth=2,
                     markersize=8, markeredgecolor=SURFACE, markeredgewidth=2, label=title, zorder=_z(name))
    slowdowns = sorted({r["slowdown"] for n in _shown(names) for r in report["models"][n]["rates"]})
    caught.axhline(0.95, color=INK_SECONDARY, linewidth=1, linestyle=":", zorder=2)
    caught.annotate("E8 target 95%", (1 / max(slowdowns, default=1), 0.95), xytext=(2, -12),
                    textcoords="offset points", fontsize=8, color=INK_SECONDARY)
    for ax in (caught, windows):
        ax.set_xscale("log")
        ax.set_xticks([1 / s for s in slowdowns], ["1" if s == 1 else f"1/{s:g}" for s in slowdowns])
        ax.minorticks_off()
        ax.set_ylim(0, 1.04)
        ax.set_xlabel("Tunnel rate (1 = the tool's default)", color=INK, fontsize=10)
        _axes(ax)
    caught.set_ylabel(f"Tunnels caught within {within / 60:g} min", color=INK, fontsize=10)
    windows.set_ylabel("Tunnel windows flagged", color=INK, fontsize=10)
    caught.set_title("Detection", color=INK, fontsize=11, loc="left")
    windows.set_title("Window recall", color=INK, fontsize=11, loc="left")
    windows.legend(loc="lower right", frameon=False, fontsize=9)
    fig.tight_layout()
    fig.savefig(out, dpi=200, facecolor=SURFACE)
    plt.close(fig)


def delay_cdf(report: dict, names: list[str], out: Path, slowdown: float = 1.0) -> None:
    """F11: seconds from a tunnel's first query to its first alert, at the tool's default rate."""
    fig, ax = plt.subplots(figsize=(6.4, 4.2), facecolor=SURFACE)
    longest = 60.0
    for name in _shown(names):
        title, color, line, _ = STYLE[name]
        found = [d for d in report["models"][name]["detections"] if d["slowdown"] == slowdown]
        if not found:
            continue
        delays = np.sort([d["delay"] for d in found if "delay" in d])
        if not len(delays):
            continue
        longest = max(longest, float(delays[-1]))
        share = np.arange(1, len(delays) + 1) / len(found)  # missed tunnels keep the curve below 1
        ax.step(np.r_[0, delays], np.r_[0, share], line, where="post", color=color, linewidth=2, label=title,
                zorder=_z(name))
    ax.axvline(60, color=INK_SECONDARY, linewidth=1, linestyle=":", zorder=2)
    ax.annotate("E8 target 60 s", (60, 1.0), xytext=(4, -4), textcoords="offset points", va="top", fontsize=8,
                color=INK_SECONDARY)
    ax.set_xlim(0, max(longest, 150) * 1.05)
    ax.set_ylim(0, 1.04)
    ax.set_xlabel("Seconds from the tunnel's first query to the first alert", color=INK, fontsize=10)
    ax.set_ylabel("Share of tunnels alerted", color=INK, fontsize=10)
    ax.set_title("Detection delay (default rate)", color=INK, fontsize=11, loc="left")
    _axes(ax)
    ax.legend(loc="lower right", frameon=False, fontsize=9)
    fig.tight_layout()
    fig.savefig(out, dpi=200, facecolor=SURFACE)
    plt.close(fig)
