"""Analyze DNS event JSONL with the sliding-window tunnel detector."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .detectors.tunnel import (
    STEP_SECONDS,
    WINDOW_SECONDS,
    DnsEvent,
    NxdomainBurstDetector,
    SlidingWindowDetector,
    TunnelWindow,
)

ALERT_AFTER = 2  # consecutive high windows of a client and domain for an alert, as the pipeline's default


class AlertRule:
    """Alert when `after` consecutive judged windows of a client and domain are `high` (less than `gap` s apart).

    Tunnels last minutes; a CDN's burst of lookups is mostly one window. The
    pipeline measures the same rule (ml/tunnel/pipeline.py alerting).
    """

    def __init__(self, after: int, gap: float = 600.0) -> None:
        self.after, self.gap = after, gap
        self._streaks: dict[tuple[str, str], tuple[int, float]] = {}

    def __call__(self, window: TunnelWindow) -> bool:
        key = (window.client_id, window.domain)
        streak, last = self._streaks.get(key, (0, float("-inf")))
        if window.end - last > self.gap:
            streak = 0
        streak = streak + 1 if window.verdict and window.verdict.label == "high" else 0
        self._streaks[key] = (streak, window.end)
        return streak >= self.after


def _tunnel_record(window: TunnelWindow, alert: bool) -> dict[str, object]:
    return {
        "signal": "tunnel",
        "client_id": window.client_id,
        "registrable_domain": window.domain,
        "window_end": window.end,
        "features": window.features.as_dict(),
        "verdict": window.verdict.as_dict() if window.verdict else None,
        "alert": alert,
    }


def analyze(
    path: Path,
    window_seconds: float | None = None,
    step_seconds: float | None = None,
    nxdomain_min_count: int = 10,
    nxdomain_min_ratio: float = 0.5,
    model: Path | None = None,
    alert_after: int | None = None,
) -> list[dict[str, object]]:
    """Every judged window (and NXDOMAIN burst) for the events in `path`, in time order."""
    if model is not None:  # the trained model; its windows are the ones it was trained on
        from ml.tunnel.scorer import TunnelModel

        trained = TunnelModel(model)
        detector = SlidingWindowDetector(window_seconds or trained.window_seconds,
                                         step_seconds or trained.step_seconds, scorer=trained.verdict)
        alert = AlertRule(alert_after or trained.alert_after)
    else:  # the hand-written rules
        detector = SlidingWindowDetector(window_seconds or WINDOW_SECONDS, step_seconds or STEP_SECONDS)
        alert = AlertRule(alert_after or ALERT_AFTER)
    nxdomain_detector = NxdomainBurstDetector(
        detector.window_seconds,
        detector.step_seconds,
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
            results.extend(_tunnel_record(window, alert(window)) for window in detector.add(event))
    results.extend(_tunnel_record(window, alert(window)) for window in detector.flush())
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("events", type=Path, help="JSONL query/response events")
    parser.add_argument("--model", type=Path, help="a trained model folder (ml/tunnel/pipeline.py --mode final); "
                                                   "default: the hand-written rules")
    parser.add_argument("--window-seconds", type=float, help=f"default: the model's, or {WINDOW_SECONDS:g}")
    parser.add_argument("--step-seconds", type=float, help=f"default: the model's, or {STEP_SECONDS:g}")
    parser.add_argument("--alert-after", type=int,
                        help=f"consecutive high windows for an alert (default: the model's, or {ALERT_AFTER})")
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
        args.model,
        args.alert_after,
    )
    output = "\n".join(json.dumps(item, sort_keys=True) for item in result) + ("\n" if result else "")
    if args.output:
        args.output.write_text(output, encoding="utf-8")
    else:
        print(output, end="")


if __name__ == "__main__":
    main()
