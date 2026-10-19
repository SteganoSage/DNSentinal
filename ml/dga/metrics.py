"""E7's metrics, with bootstrap 95% confidence intervals and McNemar's test.

Curve metrics (ROC-AUC, PR-AUC, recall at a fixed false-positive rate) are
computed from one sort of the scores. A bootstrap resample is then just
a set of weights, so 1000 resamples of a million scores take seconds.
Metrics at the decision threshold are counts, and resampling a count is
a binomial draw, so their intervals are exact and instant.

Every bootstrap here is stratified: DGA and benign rows are resampled
separately, so each resample has the test set's class balance.
"""

from __future__ import annotations

import math

import numpy as np


class Curve:
    """A test set sorted by score, for ROC and precision-recall metrics."""

    def __init__(self, y: np.ndarray, score: np.ndarray) -> None:
        self.order = np.argsort(-score, kind="stable")
        self.y = np.asarray(y, dtype=bool)[self.order]
        ranked = np.asarray(score, dtype=float)[self.order]
        self.ends = np.flatnonzero(np.r_[ranked[1:] != ranked[:-1], True])  # last row of each tied score
        self.thresholds = ranked[self.ends]

    def points(self, weights: np.ndarray | None = None) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        """(false-positive rate, recall, precision) at each distinct threshold, highest first."""
        w = np.ones(len(self.y)) if weights is None else np.asarray(weights, dtype=float)[self.order]
        tp = np.cumsum(np.where(self.y, w, 0.0))[self.ends]
        fp = np.cumsum(np.where(self.y, 0.0, w))[self.ends]
        precision = np.divide(tp, tp + fp, out=np.ones_like(tp), where=tp + fp > 0)
        return fp / max(fp[-1], 1e-300), tp / max(tp[-1], 1e-300), precision

    def summary(self, target_fpr: float, weights: np.ndarray | None = None) -> tuple[float, float, float, float]:
        """(ROC-AUC, PR-AUC, recall at target_fpr, recall at 1% FPR).

        PR-AUC is average precision, as scikit-learn computes it. Recall at 1%
        is there because most DGA papers report it.
        """
        fpr, recall, precision = self.points(weights)
        fpr0, recall0 = np.r_[0.0, fpr], np.r_[0.0, recall]
        roc_auc = float(np.sum(np.diff(fpr0) * (recall0[1:] + recall0[:-1])) / 2)
        pr_auc = float(np.sum(np.diff(recall0) * precision))
        def recall_at(limit: float) -> float:
            within = fpr <= limit
            return float(recall[within].max()) if within.any() else 0.0

        return roc_auc, pr_auc, recall_at(target_fpr), recall_at(0.01)


def bootstrap_weights(y: np.ndarray, rng: np.random.Generator, n_boot: int):
    """Weights for n_boot stratified resamples: how often each row was drawn."""
    y = np.asarray(y, dtype=bool)
    groups = [np.flatnonzero(y), np.flatnonzero(~y)]
    for _ in range(n_boot):
        weights = np.zeros(len(y))
        for rows in groups:
            if len(rows):
                weights[rows] = np.bincount(rng.integers(0, len(rows), len(rows)), minlength=len(rows))
        yield weights


def _interval(samples) -> list[float]:
    samples = np.asarray(samples, dtype=float)
    samples = samples[~np.isnan(samples)]
    if not len(samples):
        return [math.nan, math.nan]
    return [float(np.percentile(samples, 2.5)), float(np.percentile(samples, 97.5))]


def _value(value: float, samples) -> dict:
    return {"value": float(value), "ci95": _interval(samples)}


def _f1(precision, recall):
    precision, recall = np.asarray(precision, dtype=float), np.asarray(recall, dtype=float)
    total = precision + recall
    return np.divide(2 * precision * recall, total, out=np.zeros_like(total), where=total > 0)


def evaluate(
    y: np.ndarray,
    score: np.ndarray,
    decision: np.ndarray,
    family: np.ndarray,
    target_fpr: float,
    rng: np.random.Generator,
    n_boot: int = 1000,
    n_boot_curve: int = 200,
    kinds: dict[str, str] | None = None,
) -> dict:
    """Every E7 metric for one model on one test set.

    Per-family precision is the family's true positives against all the
    test set's false positives (one family versus all benign names), so it
    depends on how many benign names the test set has.
    """
    y = np.asarray(y, dtype=bool)
    decision = np.asarray(decision, dtype=bool)
    positives, negatives = int(y.sum()), int((~y).sum())
    tp, fp = int((decision & y).sum()), int((decision & ~y).sum())
    recall = tp / positives if positives else math.nan
    fpr = fp / negatives if negatives else math.nan
    precision = tp / (tp + fp) if tp + fp else math.nan

    # Decision metrics: binomial resampling of the counts.
    tp_b = rng.binomial(positives, recall, n_boot) if positives else np.full(n_boot, np.nan)
    fp_b = rng.binomial(negatives, fpr, n_boot) if negatives else np.zeros(n_boot)
    recall_b = tp_b / positives if positives else tp_b
    with np.errstate(invalid="ignore", divide="ignore"):
        precision_b = tp_b / (tp_b + fp_b)
    result = {
        "rows": len(y), "dga": positives, "benign": negatives, "true_positives": tp, "false_positives": fp,
        "recall": _value(recall, recall_b),
        "fpr": _value(fpr, fp_b / negatives if negatives else fp_b),
        "precision": _value(precision, precision_b),
        "f1": _value(_f1(precision, recall), _f1(precision_b, recall_b)),
    }

    # Curve metrics: weighted bootstrap over one sort.
    if positives and negatives:
        curve = Curve(y, score)
        point = curve.summary(target_fpr)
        samples = np.array([curve.summary(target_fpr, w) for w in bootstrap_weights(y, rng, n_boot_curve)])
        samples = samples if len(samples) else np.full((0, 4), np.nan)
        for column, key in enumerate(("roc_auc", "pr_auc", "recall_at_target_fpr", "recall_at_1pct_fpr")):
            result[key] = _value(point[column], samples[:, column])

    families = {}
    for name in sorted(set(np.asarray(family)[y])):
        rows = (np.asarray(family) == name) & y
        n, hits = int(rows.sum()), int((decision & rows).sum())
        family_recall = hits / n
        hits_b = rng.binomial(n, family_recall, n_boot)
        family_precision = hits / (hits + fp) if hits + fp else math.nan
        with np.errstate(invalid="ignore", divide="ignore"):
            family_precision_b = hits_b / (hits_b + fp_b)
        families[name] = {
            "kind": (kinds or {}).get(name, "dga"), "rows": n, "detected": hits,
            "recall": _value(family_recall, hits_b / n),
            "precision": _value(family_precision, family_precision_b),
            "f1": _value(_f1(family_precision, family_recall), _f1(family_precision_b, hits_b / n)),
        }
    result["families"] = families
    for kind in ("dga", "dictionary"):
        recalls = [f["recall"]["value"] for f in families.values() if f["kind"] == kind]
        if recalls:
            result[f"mean_family_recall_{kind}"] = float(np.mean(recalls))
    return result


def mcnemar(correct_a: np.ndarray, correct_b: np.ndarray) -> dict:
    """McNemar's test: do two models make different mistakes on the same rows?

    Exact (binomial) when fewer than 25 rows disagree, otherwise the
    chi-squared test with continuity correction.
    """
    a, b = np.asarray(correct_a, dtype=bool), np.asarray(correct_b, dtype=bool)
    only_a, only_b = int((a & ~b).sum()), int((~a & b).sum())
    n = only_a + only_b
    if n == 0:
        return {"only_a_right": 0, "only_b_right": 0, "test": "none", "statistic": None, "p_value": 1.0}
    if n < 25:
        tail = sum(math.comb(n, k) for k in range(min(only_a, only_b) + 1)) / 2**n
        return {"only_a_right": only_a, "only_b_right": only_b, "test": "exact", "statistic": None,
                "p_value": min(1.0, 2 * tail)}
    statistic = (abs(only_a - only_b) - 1) ** 2 / n
    return {"only_a_right": only_a, "only_b_right": only_b, "test": "chi2", "statistic": statistic,
            "p_value": math.erfc(math.sqrt(statistic / 2))}  # chi-squared with one degree of freedom


def threshold_at_fpr(benign_scores: np.ndarray, target_fpr: float) -> float:
    """The lowest threshold that flags at most target_fpr of these benign names (flagged: score > threshold)."""
    scores = np.sort(np.asarray(benign_scores, dtype=float))
    if not len(scores):
        raise ValueError("no benign scores to calibrate on")
    allowed = int(math.floor(target_fpr * len(scores)))  # names that may score above the threshold
    return float(scores[len(scores) - 1 - allowed])
