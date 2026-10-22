"""Analyze DNS event JSONL with the sliding-window tunnel detector."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .detectors.tunnel import DnsEvent, NxdomainBurstDetector, SlidingWindowDetector


def analyze(
    path: Path,
    window_seconds: float,
    step_seconds: float,
    nxdomain_min_count: int = 10,
    nxdomain_min_ratio: float = 0.5,
) -> list[dict[str, object]]:
    detector = SlidingWindowDetector(window_seconds, step_seconds)
    nxdomain_detector = NxdomainBurstDetector(
        window_seconds,
        step_seconds,
        nxdomain_min_count,
        nxdomain_min_ratio,
    )
    results: list[dict[str, object]] = []
    with path.open(encoding="utf-8-sig") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                event = DnsEvent.from_mapping(json.loads(line))
            except (ValueError, json.JSONDecodeError) as error:
                raise ValueError(f"{path}:{line_number}: invalid DNS event: {error}") from error
            for burst in nxdomain_detector.add(event):
                results.append({
                    "signal": "nxdomain_burst",
                    "client_id": burst.client_id,
                    "window_end": burst.window_end,
                    "nxdomain_burst": burst.as_dict(),
                })
            for client, domain, end, features, verdict in detector.add(event):
                results.append({
                    "signal": "tunnel",
                    "client_id": client,
                    "registrable_domain": domain,
                    "window_end": end,
                    "features": features.as_dict(),
                    "verdict": verdict.as_dict(),
                })
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("events", type=Path, help="JSONL query/response events")
    parser.add_argument("--window-seconds", type=float, default=60.0)
    parser.add_argument("--step-seconds", type=float, default=10.0)
    parser.add_argument("--nxdomain-min-count", type=int, default=10)
    parser.add_argument("--nxdomain-min-ratio", type=float, default=0.5)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = analyze(
        args.events,
        args.window_seconds,
        args.step_seconds,
        args.nxdomain_min_count,
        args.nxdomain_min_ratio,
    )
    output = "\n".join(json.dumps(item, sort_keys=True) for item in result) + ("\n" if result else "")
    if args.output:
        args.output.write_text(output, encoding="utf-8")
    else:
        print(output, end="")


if __name__ == "__main__":
    main()
