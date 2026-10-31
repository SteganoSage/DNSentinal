"""Every tunnel run so far, side by side: which window, features and model are best.

    python -m ml.tunnel.leaderboard ml/runs/tunnel     # writes leaderboard.csv and .md there

One row per (experiment tag, window, feature set, model), with the numbers
the choice rests on (ml/tunnel/README.md, "How we choose"): recall on tools
never trained on first, then the left-out known tool, the slowest rate still
caught in time (R_min), false alerts a day on real browsing (and on wildcard
DNS, never trained on) and cross-validation.
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

COLUMNS = [
    ("unknown", "mean_tool_recall", "unseen-tool recall"),
    ("tool", "mean_tool_recall", "left-out-tool recall"),
    ("rates", "r_min", "R_min"),
    ("rates", "detected_at_1/10", "caught at 1/10"),
    ("rates", "detected_at_1/100", "caught at 1/100"),
    ("rates", "median_delay", "median delay (s)"),
    ("cv", "recall_at_target_fpr", "cv recall @target"),
    ("cv", "browsing_alerts_per_day", "browsing alerts/day"),
    ("cv", "browsing_alerts_per_day_allowlisted", "browsing alerts/day, allowlist"),
    ("cv", "wildcard_alerts_per_day_allowlisted", "wildcard alerts/day, allowlist"),
    ("unknown", "fpr", "window FPR"),
]


def collect(root: Path) -> list[dict]:
    rows: dict[tuple, dict] = {}
    for path in sorted(root.rglob("run_info_*.json")):
        info = json.loads(path.read_text())
        for model, numbers in info["headline"].items():
            if not isinstance(numbers, dict):
                continue
            key = (info.get("tag", ""), f"{info.get('window', 0):g}", "".join(info.get("features", [])), model)
            row = rows.setdefault(key, {"tag": key[0], "window": key[1], "features": key[2], "model": model})
            for mode, metric, title in COLUMNS:
                if mode == info["mode"] and metric in numbers:
                    row[title] = numbers[metric]
                    if metric == "r_min":  # a slowdown: the rate is its inverse
                        row[title] = "none" if numbers[metric] is None else f"1/{numbers[metric]:g}"
    return sorted(rows.values(), key=lambda r: -(r.get("unseen-tool recall") or 0))


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("ml/runs/tunnel")
    rows = collect(root)
    if not rows:
        print(f"no runs under {root}", file=sys.stderr)
        return 1
    header = ["tag", "window", "features", "model", *[t for _, _, t in COLUMNS]]
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
