"""Every run so far, side by side: which features and model are best.

    python -m ml.dga.leaderboard ml/runs     # writes ml/runs/leaderboard.csv and .md

One row per (experiment tag, feature set, benign set, model), with the
numbers the choice rests on (README of ml/dga, "How we choose"):
leave-family-out mean recall at 0.1% FPR first, then real (external)
names, cross-validation, dictionary families and later dates, plus size
and latency. Rows are sorted by the first.
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

COLUMNS = [
    ("lofo", "mean_recall", "unseen-family recall"),
    ("lofo", "mean_recall_at_1pct_fpr", "unseen-family recall @1%"),
    ("lofo", "families_below_90", "families < 90%"),
    ("external", "recall", "real-name recall"),
    ("cv", "recall_at_target_fpr", "cv recall @0.1%"),
    ("cv", "pr_auc", "cv PR-AUC"),
    ("dictionary", "recall", "dictionary recall"),
    ("future", "recall", "later-date recall"),
]


def collect(root: Path) -> list[dict]:
    rows: dict[tuple, dict] = {}
    for path in sorted(root.rglob("run_info_*.json")):
        info = json.loads(path.read_text())
        mode = info["mode"]
        for model, numbers in info["headline"].items():
            if not isinstance(numbers, dict):
                continue
            key = (info.get("tag", ""), "".join(info.get("features", [])), info.get("benign", ""), model)
            row = rows.setdefault(key, {"tag": key[0], "features": key[1], "benign": key[2], "model": model})
            for column_mode, metric, title in COLUMNS:
                if column_mode == mode and metric in numbers:
                    row[title] = numbers[metric]
        if mode == "cv":
            metrics = json.loads((path.parent / "metrics.json").read_text())
            for model, measured in metrics.get("measured", {}).items():
                key = (info.get("tag", ""), "".join(info.get("features", [])), info.get("benign", ""), model)
                if key in rows:
                    rows[key]["size (kB)"] = round(measured.get("bytes", 0) / 1000)
                    rows[key]["latency (µs, Python)"] = round(measured.get("latency_median_us", 0))
    return sorted(rows.values(), key=lambda r: -(r.get("unseen-family recall") or 0))


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("ml/runs")
    rows = collect(root)
    if not rows:
        print(f"no runs under {root}", file=sys.stderr)
        return 1
    header = ["tag", "features", "benign", "model", *[t for _, _, t in COLUMNS], "size (kB)", "latency (µs, Python)"]
    with open(root / "leaderboard.csv", "w", newline="") as stream:
        writer = csv.DictWriter(stream, header)
        writer.writeheader()
        writer.writerows(rows)

    def cell(value):
        return "" if value is None else f"{value:.3f}" if isinstance(value, float) else str(value)

    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    lines += ["| " + " | ".join(cell(row.get(h)) for h in header) + " |" for row in rows]
    (root / "leaderboard.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
