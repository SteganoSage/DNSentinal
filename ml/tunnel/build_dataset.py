"""Create labeled feature windows with capture-session provenance."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from analyzer.detectors.tunnel import extract_features
from ml.tunnel.train import _session_windows


def write_windows(
    paths: list[Path],
    label: int,
    split: str,
    size: int,
    output: Path,
) -> int:
    written = 0
    with output.open("a", encoding="utf-8") as stream:
        for path in paths:
            for window in _session_windows([path], size):
                stream.write(json.dumps({
                    "label": label,
                    "split": split,
                    "session": str(path),
                    "features": extract_features(window).as_dict(),
                }, sort_keys=True) + "\n")
                written += 1
    return written


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--train-positive", nargs="+", type=Path, required=True)
    parser.add_argument("--train-benign", nargs="+", type=Path, required=True)
    parser.add_argument("--test-positive", nargs="+", type=Path, required=True)
    parser.add_argument("--test-benign", nargs="+", type=Path, required=True)
    parser.add_argument("--window-size", type=int, default=6)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("", encoding="utf-8")
    train_count = write_windows(
        args.train_positive, 1, "train", args.window_size, args.output
    ) + write_windows(args.train_benign, 0, "train", args.window_size, args.output)
    test_count = write_windows(
        args.test_positive, 1, "test", args.window_size, args.output
    ) + write_windows(args.test_benign, 0, "test", args.window_size, args.output)
    print(json.dumps({"train_windows": train_count, "test_windows": test_count}))


if __name__ == "__main__":
    main()
