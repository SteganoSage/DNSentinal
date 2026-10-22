"""Combine the DGA, tunnel, and NXDOMAIN slow-path signals."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FusionVerdict:
    """Explainable combined risk score for one client/window."""

    score: float
    label: str
    dga_score: float
    tunnel_score: float
    nxdomain_score: float
    reasons: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "score": self.score,
            "label": self.label,
            "signals": {
                "dga": self.dga_score,
                "tunnel": self.tunnel_score,
                "nxdomain": self.nxdomain_score,
            },
            "reasons": list(self.reasons),
        }


def nxdomain_signal_score(
    nxdomain_count: int,
    nxdomain_ratio: float,
    window_seconds: float,
    min_count: int,
) -> float:
    """Turn NXDOMAIN volume and ratio into a bounded risk signal."""
    if nxdomain_count < 0 or not 0.0 <= nxdomain_ratio <= 1.0:
        raise ValueError("NXDOMAIN count must be non-negative and ratio must be between 0 and 1")
    if window_seconds <= 0 or min_count <= 0:
        raise ValueError("window_seconds and min_count must be positive")
    rate_factor = min(1.0, (nxdomain_count / window_seconds) / (min_count / window_seconds))
    return min(1.0, nxdomain_ratio * rate_factor)


def combine_scores(
    dga_score: float,
    tunnel_score: float,
    nxdomain_score: float,
    *,
    dga_weight: float = 0.4,
    tunnel_weight: float = 0.4,
    nxdomain_weight: float = 0.2,
    medium_threshold: float = 0.6,
    high_threshold: float = 0.9,
) -> FusionVerdict:
    """Combine three normalized scores and retain the signal explanations."""
    values = (dga_score, tunnel_score, nxdomain_score)
    if any(not 0.0 <= value <= 1.0 for value in values):
        raise ValueError("all signal scores must be between 0 and 1")
    weights = (dga_weight, tunnel_weight, nxdomain_weight)
    if any(weight < 0 for weight in weights) or sum(weights) <= 0:
        raise ValueError("signal weights must be non-negative and not all zero")
    total = sum(weights)
    score = sum(value * weight for value, weight in zip(values, weights)) / total
    reasons = tuple(
        reason for active, reason in (
            (dga_score >= medium_threshold, "DGA-like domain activity"),
            (tunnel_score >= medium_threshold, "tunnel-like query behavior"),
            (nxdomain_score >= medium_threshold, "NXDOMAIN burst"),
        ) if active
    )
    label = "high" if score >= high_threshold else "medium" if score >= medium_threshold else "low"
    return FusionVerdict(score, label, dga_score, tunnel_score, nxdomain_score, reasons)
