"""The tunnel model the analyzer ships (models/tunnel), from a final run.

    python -m ml.tunnel.export ml/runs/tunnel/main/w60-fVNRD/final models/tunnel --data ml/data/tunnel

`--mode final` pickles a random forest. A pickle needs the scikit-learn it was
made with (and runs code when loaded), so this writes the forest's trees as
plain JSON instead (tunnel_rf.json), which ml/tunnel/scorer.py walks with no
library at all. It must be run with the scikit-learn model.json records, since
it reads the pickle. It then checks the JSON scores windows exactly as the
forest does, bit for bit: windows built to sit on and around every split
threshold, and with --data real windows of the dataset. It stops if one differs.
A LightGBM text model is portable already and is copied as it is.
"""

from __future__ import annotations

import argparse
import json
import pickle
import shutil
import sys
from pathlib import Path

import numpy as np

FORMAT = "dnsentinel-forest-1"


def forest_json(forest) -> dict:
    """A fitted RandomForestClassifier as plain arrays, one entry per node of each tree.

    feature  the feature a node splits on; -2 at a leaf (scikit-learn's own marker)
    threshold, left, right, missing_left  go left if the feature (as float32) <= threshold,
             or if it is missing (NaN) and missing_left
    value    at a leaf, the tree's probability of a tunnel
    """
    import sklearn

    if list(forest.classes_) != [False, True] or forest.n_outputs_ != 1:
        raise ValueError(f"expected a tunnel/benign forest, got classes {list(forest.classes_)}")
    # scikit-learn 1.4 started storing class fractions in tree_.value, and predicting them as they are
    major, minor = (int(part) for part in sklearn.__version__.split(".")[:2])
    normalise = (major, minor) < (1, 4)
    trees = []
    for estimator in forest.estimators_:
        tree = estimator.tree_
        value = tree.value[:, 0, :]
        if normalise:
            total = value.sum(axis=1)
            total[total == 0] = 1.0
            value = value / total[:, None]
        missing = getattr(tree, "missing_go_to_left", None)
        trees.append({
            "feature": tree.feature.tolist(),
            "threshold": tree.threshold.tolist(),
            "left": tree.children_left.tolist(),
            "right": tree.children_right.tolist(),
            "missing_left": missing.astype(int).tolist() if missing is not None else [0] * tree.node_count,
            "value": value[:, 1].tolist(),
        })
    return {"format": FORMAT, "features": int(forest.n_features_in_), "trees": trees}


def edge_windows(forest: dict, count: int, seed: int) -> np.ndarray:
    """Windows whose every feature sits on, or one float32 step either side of, a threshold
    the trees split that feature on: where a wrong comparison or a float32 rounding would show."""
    rng = np.random.default_rng(seed)
    cuts: list[list[float]] = [[] for _ in range(forest["features"])]
    for tree in forest["trees"]:
        for feature, threshold in zip(tree["feature"], tree["threshold"]):
            # a split that only separates missing values has an infinite threshold: no edge to test
            if feature >= 0 and np.isfinite(np.float32(threshold)):
                cuts[feature].append(threshold)
    X = np.zeros((count, forest["features"]))
    for f, values in enumerate(cuts):
        if not values:
            continue
        chosen = np.float32(rng.choice(values, count))
        step = rng.integers(-1, 2, count)  # one float32 below, on, one above
        moved = np.where(step < 0, np.nextafter(chosen, np.float32(-np.inf)),
                         np.where(step > 0, np.nextafter(chosen, np.float32(np.inf)), chosen))
        X[:, f] = np.where(np.isfinite(moved), moved, chosen)  # never past float32's largest value
    return X


def real_windows(data: Path, columns: list[int], captures_per_set: int, seed: int) -> np.ndarray:
    """Windows of a few captures of every set of the dataset, at full speed: the features as trained on."""
    from . import pipeline

    captures = pipeline.read_captures(data / "captures.csv")
    rng = np.random.default_rng(seed)
    chosen = []
    for kind in sorted({c["set"] for c in captures}):
        group = [c for c in captures if c["set"] == kind]
        chosen += [group[i] for i in sorted(rng.choice(len(group), min(captures_per_set, len(group)), replace=False))]
    events = pipeline.read_events(pipeline.events_file(data), {c["capture"] for c in chosen})
    parts = []
    for capture in chosen:
        tunnel = capture["tunnel_domain"] if capture["label"] == "tunnel" else ""
        found, _ = pipeline.capture_windows(events.get(capture["capture"], []), tunnel, [1.0], 60.0, 10.0)
        if 1.0 in found:
            parts.append(found[1.0][0][:, columns])
    return np.concatenate(parts) if parts else np.empty((0, len(columns)))


def export(source: Path, out: Path, data: Path | None = None, edges: int = 20000, captures_per_set: int = 3,
           seed: int = 1) -> dict:
    from analyzer.detectors.tunnel import TunnelFeatures

    from .scorer import Forest

    card = json.loads((source / "model.json").read_text())
    out.mkdir(parents=True, exist_ok=True)
    file = card["model"] if card["model"].endswith(".txt") else Path(card["model"]).with_suffix(".json").name
    if card["model"].endswith(".txt"):  # LightGBM: portable as it is
        shutil.copy(source / card["model"], out / file)
        _finish(source, out, card, file)
        return card

    with open(source / card["model"], "rb") as stream:
        wrapper = pickle.load(stream)
    forest = getattr(getattr(wrapper, "inner", None), "model", wrapper)
    forest.n_jobs = 1  # as the analyzer scored it: the trees added one after another, in order
    exported = forest_json(forest)
    if exported["features"] != len(card["features"]):
        raise ValueError(f"the forest takes {exported['features']} features, model.json lists {len(card['features'])}")

    names = TunnelFeatures.names()
    columns = [names.index(name) for name in card["features"]]
    sets = {"edge": edge_windows(exported, edges, seed)}
    if data is not None:
        sets["real"] = real_windows(data, columns, captures_per_set, seed)
    walker = Forest(exported)
    checked = {}
    for kind, X in sets.items():
        expected = forest.predict_proba(X)[:, 1]
        got = walker.score(X)
        differ = int(np.count_nonzero(got != expected))
        if differ:
            worst = float(np.max(np.abs(got - expected)))
            raise SystemExit(f"{kind} windows: {differ} of {len(X)} scored differently (up to {worst:.3g}); not exported")
        threshold = float(card["threshold"])
        checked[kind] = {"windows": len(X), "high": int(np.count_nonzero(expected > threshold))}

    (out / file).write_text(json.dumps(exported, separators=(",", ":")) + "\n")
    import sklearn

    card = card | {"model": file, "exported": {
        "from": card["model"], "format": FORMAT, "sklearn": sklearn.__version__,
        "trees": len(exported["trees"]), "nodes": sum(len(t["feature"]) for t in exported["trees"]),
        "checked": checked, "identical": True,
    }}
    _finish(source, out, card, file)
    return card


def _finish(source: Path, out: Path, card: dict, file: str) -> None:
    """model.json and how it was trained; a model left from an earlier export goes, so only one is shipped."""
    (out / "model.json").write_text(json.dumps(card, indent=1) + "\n")
    if (source / "run_info_final.json").exists():
        shutil.copy(source / "run_info_final.json", out / "run_info_final.json")
    for old in out.glob("tunnel_*"):
        if old.name != file:
            old.unlink()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("source", type=Path, help="a folder --mode final wrote (model.json and the model)")
    parser.add_argument("out", type=Path, help="where the shipped model goes, e.g. models/tunnel")
    parser.add_argument("--data", type=Path, help="the dataset (captures.csv, events.csv[.gz]): check on real windows too")
    parser.add_argument("--edge-windows", type=int, default=20000, help="threshold-edge windows to check (default 20000)")
    parser.add_argument("--captures-per-set", type=int, default=3, help="with --data: captures of each set (default 3)")
    args = parser.parse_args(argv)
    card = export(args.source, args.out, args.data, args.edge_windows, args.captures_per_set)
    done = card.get("exported", {})
    checks = ", ".join(f"{v['windows']:,} {k} windows ({v['high']:,} high)" for k, v in done.get("checked", {}).items())
    print(f"{args.out / card['model']}: " + (f"{done['trees']} trees, {done['nodes']:,} nodes; scores identical to "
                                             f"the forest on {checks}" if done else "copied"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
