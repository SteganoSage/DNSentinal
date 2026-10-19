"""E7's figures: F8 (ROC and precision-recall curves) and F9 (recall on each
unseen family). The pipeline draws them; this redraws every run under a folder:

    python -m ml.dga.plots ml/runs
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
from matplotlib.colors import LinearSegmentedColormap  # noqa: E402

from .metrics import Curve  # noqa: E402

SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK_SECONDARY = "#52514e"
GRID = "#e4e3df"

# Categorical slots 1-3 of the reference palette, then two more distinct hues
# for the other boosting libraries; the baselines are drawn in ink, dashed
# or as a single point.
STYLE = {
    "lgbm": ("LightGBM", "#2a78d6", "-"),
    "rf": ("Random forest", "#eb6834", "-"),
    "cnn": ("Character CNN", "#1baf7a", "-"),
    "xgboost": ("XGBoost", "#8b5cf6", "-"),
    "histgb": ("HistGradientBoosting", "#d6409f", "-"),
    "entropy": ("Entropy threshold", INK_SECONDARY, "--"),
    "blocklist": ("Blocklist only", INK, ""),
}


def _axes(ax) -> None:
    ax.set_facecolor(SURFACE)
    ax.grid(color=GRID, linewidth=0.8, zorder=0)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(INK_SECONDARY)
    ax.tick_params(colors=INK_SECONDARY, labelsize=9)


def curves(scores_path: Path, names: list[str], out: Path, target_fpr: float) -> None:
    """F8: ROC (false-positive rate on a log scale, where a resolver operates) and precision-recall."""
    scores = np.load(scores_path)
    y = scores["y"].astype(bool)
    fig, (roc, pr) = plt.subplots(1, 2, figsize=(10, 4.4), facecolor=SURFACE)
    floor = 1 / max(int((~y).sum()), 1)
    for name in names:
        title, color, line = STYLE.get(name, (name, INK, "-"))
        curve = Curve(y, scores[f"score_{name}"])
        fpr, recall, precision = curve.points()
        if name == "blocklist":  # a yes/no answer: one operating point, not a curve
            flagged = scores[f"score_{name}"] > 0.5
            point_fpr = max(float((flagged & ~y).sum()) / max((~y).sum(), 1), floor)
            point_recall = float((flagged & y).sum()) / max(y.sum(), 1)
            point_precision = float((flagged & y).sum()) / max(flagged.sum(), 1)
            roc.plot([point_fpr], [point_recall], "o", color=color, label=title, zorder=3)
            pr.plot([point_recall], [point_precision], "o", color=color, label=title, zorder=3)
            continue
        roc.plot(np.maximum(np.r_[0, fpr], floor), np.r_[0, recall], line, color=color, linewidth=1.8,
                 label=title, zorder=3)
        pr.plot(np.r_[0, recall], np.r_[precision[0], precision], line, color=color, linewidth=1.8, label=title,
                zorder=3)
    roc.axvline(target_fpr, color=INK_SECONDARY, linewidth=1, linestyle=":", zorder=2)
    roc.annotate(f"{target_fpr:.1%} FPR", (target_fpr, 0.02), xytext=(4, 0), textcoords="offset points",
                 fontsize=8, color=INK_SECONDARY)
    roc.set_xscale("log")
    roc.set_xlim(floor, 1)
    roc.set_ylim(0, 1.02)
    roc.set_xlabel("False-positive rate (benign names flagged)", color=INK, fontsize=10)
    roc.set_ylabel("Recall (DGA names flagged)", color=INK, fontsize=10)
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


def lofo_heatmap(report: dict, names: list[str], out: Path) -> None:
    """F9: recall on each family when it was left out of training, at the calibrated threshold."""
    families = sorted(report["families"], key=lambda f: -report["families"][f][names[0]]["recall"]["value"])
    values = np.array([[report["families"][f][n]["recall"]["value"] for n in names] for f in families])
    cmap = LinearSegmentedColormap.from_list("recall", [SURFACE, "#2a78d6"])
    fig, ax = plt.subplots(figsize=(1.6 + 1.3 * len(names), 0.9 + 0.32 * len(families)), facecolor=SURFACE)
    ax.imshow(values, cmap=cmap, vmin=0, vmax=1, aspect="auto")
    for i in range(len(families)):
        for j in range(len(names)):
            v = values[i, j]
            ax.text(j, i, f"{v:.2f}", ha="center", va="center", fontsize=8, color=SURFACE if v > 0.6 else INK)
    ax.set_xticks(range(len(names)), [f"{STYLE.get(n, (n,))[0]}\nmean {report['models'][n]['mean_recall']:.3f}"
                                      for n in names], fontsize=9, color=INK)
    ax.set_yticks(range(len(families)), families, fontsize=8, color=INK)
    ax.xaxis.tick_top()
    ax.tick_params(length=0)
    for spine in ax.spines.values():
        spine.set_visible(False)
    ax.set_xlabel("Recall on each family when it was left out of training", color=INK_SECONDARY, fontsize=8)
    fig.tight_layout()
    fig.savefig(out, dpi=200, facecolor=SURFACE)
    plt.close(fig)


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    for run in sorted(Path(sys.argv[1]).rglob("metrics.json")):  # <out>/<tag>/f-<groups>/<mode>/metrics.json
        mode, folder = run.parent.name, run.parent
        if (folder / "scores.npz").exists() and mode in ("cv", "dictionary", "future", "external"):
            names = [k[len("score_"):] for k in np.load(folder / "scores.npz").files if k.startswith("score_")]
            target = json.loads(run.read_text())["settings"]["target_fpr"]
            curves(folder / "scores.npz", names, folder / f"{'F8' if mode == 'cv' else 'curves'}_roc_pr.png", target)
        if mode == "lofo":
            report = json.loads(run.read_text())
            lofo_heatmap(report, list(report["models"]), folder / "F9_lofo_recall.png")
    return 0


if __name__ == "__main__":
    sys.exit(main())
