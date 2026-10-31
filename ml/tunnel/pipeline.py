"""Training and evaluating the tunnel detector: EVALUATION.md E8.

    python -m ml.tunnel.pipeline --mode all --data ml/data/tunnel     # every mode, then the final model
    python -m ml.tunnel.pipeline --mode rates --models lgbm,iforest,qpm --windows 30 60 120

The windows are the detector's own (analyzer/detectors/tunnel.py): per
(client, registrable domain), the last --window seconds, judged every
--step seconds. A slower tunnel is emulated by stretching a capture's
clock: at slowdown 10 the same queries come ten times further apart, a
tenth of the rate (E8's "1/10"). Training uses --train-slowdowns, so the
models see slow tunnels too; testing uses --test-slowdowns.

| Mode | Train | Test |
|---|---|---|
| cv | 5 folds over captures, known tools and benign | the held-out captures |
| tool | every known tool but one | the one left out |
| unknown | the known tools | tools never trained on (unknown, android) |
| rates | 5 folds over known-tool captures | each held-out capture at every slowdown: F10, F11, T5 |
| final | everything | (writes the model the analyzer runs) |

Captures, not windows, are split: windows of one capture overlap and must
not land on both sides. Outside cv, the same 20% of each benign set's
captures is the test set; in every split 10% of the benign training captures
is held back and each model's threshold set so at most --fpr of their windows
are flagged. Wildcard DNS (subdomain enumeration: thousands of unique names
under one domain, the very shape of a tunnel) is GraphTunnel's robustness
test and is only tested: its false alerts are reported on their own, not in
the window metrics (--train-wildcard trains on it instead).

Each run writes <out>/<tag>/w<window>-f<groups>/<mode>/: metrics.json (with
bootstrap 95% intervals), run_info_<mode>.json, scores.npz and the figures.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import multiprocessing
import os
import pickle
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

from analyzer.detectors.tunnel import FEATURE_GROUPS, STEP_SECONDS, TunnelFeatures, DnsEvent, labels_of, windows

from ..dga import metrics
from ..dga.pipeline import environment, write_json
from ..dga.progress import log
from . import models

REPO = Path(__file__).resolve().parents[2]
MODES = ["cv", "tool", "unknown", "rates", "final"]
KNOWN_SETS = ("known", "local")   # tunnel sets trained on outside `unknown`
UNSEEN_SETS = ("unknown", "android")
TEST_ONLY_SETS = ("wildcard",)  # benign sets never trained on, reported apart (unless --train-wildcard)
DEFAULT_MODELS = "lgbm,xgboost,histgb,rf,iforest,qpm,rules"
ALL_FEATURES = TunnelFeatures.names()


# ─── Windows ────────────────────────────────────────────────────────────────


@dataclass
class Track:
    """One tunnel capture's queries over time, for detection delay and bytes sent before it."""

    start: float
    times: np.ndarray     # each query's time (unstretched)
    upstream: np.ndarray  # cumulative bytes in the names' subdomains: what the client sent up


@dataclass
class Table:
    """Every window, one row each."""

    X: np.ndarray         # every feature, ALL_FEATURES order
    y: np.ndarray         # tunnel?
    capture: np.ndarray   # index into captures
    slowdown: np.ndarray
    end: np.ndarray       # the window's end, on the stretched clock
    key: np.ndarray       # index into keys: (capture, client, domain)
    keys: list
    tracks: dict          # capture index -> Track

    def __len__(self) -> int:
        return len(self.y)


def capture_windows(rows: list[tuple], tunnel_domain: str, slowdowns: list[float], window: float, step: float):
    """The windows of one capture at each slowdown: {slowdown: (features, ends, keys)}, and its Track."""
    events = [DnsEvent(float(t), client, qname, qtype, rcode, int(size))
              for t, client, qname, qtype, rcode, size in rows]
    events.sort(key=lambda e: e.timestamp)
    track = None
    if tunnel_domain:  # only the tunnel; the lab machine's other lookups are left out
        base = labels_of(tunnel_domain)
        events = [e for e in events if labels_of(e.qname)[-len(base):] == base]
        if not events:
            return {}, None
        start = events[0].timestamp
        sizes = [sum(len(label) for label in labels_of(e.qname)[:-len(base)]) for e in events]
        track = Track(start, np.array([e.timestamp for e in events]), np.cumsum(sizes))
    else:
        slowdowns = [1.0]
    out = {}
    for slowdown in slowdowns:
        if slowdown == 1:
            stretched = events
        else:
            start = events[0].timestamp
            stretched = [DnsEvent(start + (e.timestamp - start) * slowdown, e.client_id, e.qname, e.qtype, e.rcode,
                                  e.response_size) for e in events]
        found = windows(stretched, window, step)
        features = np.array([w.features.vector() for w in found], dtype=np.float64).reshape(-1, len(ALL_FEATURES))
        out[slowdown] = (features, np.array([w.end for w in found]), [(w.client_id, w.domain) for w in found])
    return out, track


def read_captures(path: Path) -> list[dict]:
    with open(path, newline="") as stream:
        rows = list(csv.DictReader(stream))
    for row in rows:
        row["hours"] = float(row["hours"] or 0)
        row["queries"] = int(row["queries"] or 0)
    return rows


def choose_captures(captures: list[dict], fraction: float, seed: int) -> list[dict]:
    """--fraction: a share of each benign set's captures (all tunnels), for a quick trial."""
    if fraction >= 1:
        return captures
    rng = np.random.default_rng(seed)
    kept = []
    for kind in sorted({c["set"] for c in captures}):
        group = [c for c in captures if c["set"] == kind]
        if group[0]["label"] == "benign":
            group = [group[i] for i in sorted(rng.choice(len(group), max(2, round(len(group) * fraction)),
                                                         replace=False))] if len(group) > 2 else group
        kept += group
    return sorted(kept, key=lambda c: c["capture"])


def events_file(data: Path) -> Path:
    """events.csv.gz, or events.csv if it was unpacked (as uploading a dataset may do)."""
    return data / "events.csv.gz" if (data / "events.csv.gz").exists() else data / "events.csv"


def dataset_info(data: Path) -> dict:
    """dataset_info.json, if it came with the data: only events and captures.csv are needed."""
    path = data / "dataset_info.json"
    return json.loads(path.read_text()) if path.exists() else {}


def read_events(path: Path, wanted: set[str]) -> dict[str, list[tuple]]:
    grouped: dict[str, list[tuple]] = defaultdict(list)
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", newline="") as stream:
        reader = csv.reader(stream)
        next(reader)
        for capture, *event in reader:
            if capture in wanted:
                grouped[capture].append(tuple(event))
    return grouped


def build_table(captures: list[dict], events: dict[str, list[tuple]], slowdowns: list[float], window: float,
                step: float, threads: int) -> Table:
    order = sorted(range(len(captures)), key=lambda i: -len(events.get(captures[i]["capture"], ())))
    parts: dict[int, tuple] = {}
    # not fork: LightGBM's and scikit-learn's threads may already be running in this process
    context = multiprocessing.get_context("forkserver" if "forkserver" in multiprocessing.get_all_start_methods()
                                          else "spawn")
    with ProcessPoolExecutor(max_workers=max(1, threads), mp_context=context) as pool:
        futures = {i: pool.submit(capture_windows, events.get(captures[i]["capture"], []),
                                  captures[i]["tunnel_domain"] if captures[i]["label"] == "tunnel" else "",
                                  slowdowns, window, step) for i in order}
        for i, future in futures.items():
            parts[i] = future.result()
    X, y, capture, slowdown, end, key, keys, tracks = [], [], [], [], [], [], [], {}
    index: dict[tuple, int] = {}
    for i in range(len(captures)):
        found, track = parts[i]
        if track is not None:
            tracks[i] = track
        for s, (features, ends, found_keys) in sorted(found.items()):
            X.append(features)
            n = len(ends)
            y.append(np.full(n, captures[i]["label"] == "tunnel"))
            capture.append(np.full(n, i))
            slowdown.append(np.full(n, s))
            end.append(ends)
            key.append(np.array([index.setdefault((i, *k), len(index)) for k in found_keys], dtype=np.int64))
    keys = [None] * len(index)
    for k, v in index.items():
        keys[v] = k
    cat = (lambda parts, dtype: np.concatenate(parts).astype(dtype) if parts else np.empty(0, dtype))
    return Table(np.concatenate(X) if X else np.empty((0, len(ALL_FEATURES))), cat(y, bool), cat(capture, np.int64),
                 cat(slowdown, float), cat(end, float), cat(key, np.int64), keys, tracks)


def load(args, window: float) -> tuple[list[dict], Table]:
    """The captures and their windows; the windows are cached (--cache), keyed by everything they depend on."""
    captures = choose_captures(read_captures(args.data / "captures.csv"), args.fraction, args.seed)
    slowdowns = sorted(set(args.train_slowdowns) | set(args.test_slowdowns))
    events = events_file(args.data)
    stamp = json.dumps([dataset_info(args.data).get("events_sha256") or f"{events.name}:{events.stat().st_size}",
                        [c["capture"] for c in captures], slowdowns, window, args.step,
                        ALL_FEATURES, _code_digest(), 2])  # 2: the cache's format
    digest = hashlib.sha256(stamp.encode()).hexdigest()[:12]
    cache = (args.cache or args.out / "cache") / f"windows-w{window:g}-s{args.step:g}-{digest}.pkl"
    if cache.exists():
        log(f"windows from {cache}")
        with open(cache, "rb") as stream:
            state = pickle.load(stream)
        state["tracks"] = {c: Track(*track) for c, track in state["tracks"].items()}
        return captures, Table(**state)
    log(f"reading {events}")
    events = read_events(events, {c["capture"] for c in captures})
    log(f"cutting windows ({window:g} s every {args.step:g} s) of {len(captures)} captures, "
        f"{sum(map(len, events.values())):,} queries, at slowdowns {slowdowns}")
    table = build_table(captures, events, slowdowns, window, args.step, args.threads)
    cache.parent.mkdir(parents=True, exist_ok=True)
    # plain arrays and tuples, not the classes: `python -m` would record them as __main__'s
    state = dict(vars(table), tracks={c: (t.start, t.times, t.upstream) for c, t in table.tracks.items()})
    with open(cache.with_suffix(".part"), "wb") as stream:
        pickle.dump(state, stream, protocol=pickle.HIGHEST_PROTOCOL)
    cache.with_suffix(".part").rename(cache)
    return captures, table


def _code_digest() -> str:
    """The detector's code: a changed feature invalidates cached windows."""
    source = (REPO / "analyzer" / "detectors" / "tunnel.py").read_bytes()
    return hashlib.sha256(source).hexdigest()[:12]


# ─── Splits ─────────────────────────────────────────────────────────────────


@dataclass
class Split:
    name: str
    train: np.ndarray        # window rows
    calibration: np.ndarray  # benign window rows that set the thresholds
    test: np.ndarray


def _deal(items: list[int], parts: int, rng, group=lambda i: "") -> list[list[int]]:
    """Captures dealt into folds round-robin, group by group (smallest first), shuffled within each.

    Grouped by tool, every tool's captures spread over the folds, and tools
    with one capture each land in different folds: two that only resemble each
    other (dnspot and DNS-shell, the only A-record tunnels) must not be held out
    together, or `cv` turns into a leave-two-tools-out test by chance.
    """
    groups: dict[str, list[int]] = defaultdict(list)
    for i in items:
        groups[group(i)].append(i)
    ordered = []
    for name in sorted(groups, key=lambda g: (len(groups[g]), g)):
        members = list(groups[name])
        rng.shuffle(members)
        ordered += members
    return [ordered[i::parts] for i in range(parts)]


def hold_back(benign: list[int], captures: list[dict], share: float, rng) -> tuple[list[int], list[int]]:
    """(kept, held back): `share` of each benign set's captures, so every set's windows set the threshold.

    Not of all of them at random: the crawl's many easy windows would set it
    alone, and the real browsing's harder ones would then be flagged far more
    often than the target rate.
    """
    kept, held = [], []
    for kind in sorted({captures[i]["set"] for i in benign}):
        group = [i for i in benign if captures[i]["set"] == kind]
        rng.shuffle(group)
        n = max(1, round(len(group) * share)) if len(group) > 2 else 0
        held += group[:n]
        kept += group[n:]
    return sorted(kept), sorted(held)


def benign_partition(captures: list[dict], args) -> tuple[list[int], list[int], list[int]]:
    """(train, calibration, test) benign captures: per set, test 20%, then 10% of the rest held back."""
    rng = np.random.default_rng(args.seed)
    rest, test = [], []
    for kind in sorted({c["set"] for c in captures if c["label"] == "benign"}):
        group = [i for i, c in enumerate(captures) if c["set"] == kind]
        if kind in args.test_only:
            test += group
            continue
        rng.shuffle(group)
        n_test = max(1, round(len(group) * args.benign_test)) if len(group) > 1 else 0
        test += group[:n_test]
        rest += group[n_test:]
    train, calibration = hold_back(rest, captures, args.calibration, rng)
    return train, calibration, sorted(test)


class Rows:
    """Window rows by capture and slowdown."""

    def __init__(self, table: Table) -> None:
        self.table = table
        self.by_capture: dict[int, np.ndarray] = {}
        order = np.argsort(table.capture, kind="stable")
        bounds = np.flatnonzero(np.r_[True, table.capture[order][1:] != table.capture[order][:-1], True])
        for a, b in zip(bounds[:-1], bounds[1:]):
            self.by_capture[int(table.capture[order[a]])] = order[a:b]

    def of(self, captures: list[int], slowdowns: list[float]) -> np.ndarray:
        parts = [rows[np.isin(self.table.slowdown[rows], slowdowns)] for c in captures
                 if len(rows := self.by_capture.get(c, np.empty(0, np.int64)))]
        return np.sort(np.concatenate(parts)) if parts else np.empty(0, np.int64)


def splits_for(mode: str, captures: list[dict], rows: Rows, args) -> list[Split]:
    rng = np.random.default_rng(args.seed)
    tunnels = [i for i, c in enumerate(captures) if c["label"] == "tunnel"]
    known = [i for i in tunnels if captures[i]["set"] in KNOWN_SETS]
    unseen = [i for i in tunnels if captures[i]["set"] in UNSEEN_SETS]
    benign_train, benign_calibration, benign_test = benign_partition(captures, args)
    train_s, test_s = args.train_slowdowns, [1.0]

    def split(name, train_tunnels, test_tunnels, train_benign=benign_train, calibration=benign_calibration,
              test_benign=benign_test, test_slowdowns=test_s):
        return Split(name,
                     np.sort(np.r_[rows.of(train_tunnels, train_s), rows.of(train_benign, [1.0])]).astype(np.int64),
                     rows.of(calibration, [1.0]),
                     np.sort(np.r_[rows.of(test_tunnels, test_slowdowns),
                                   rows.of(test_benign, [1.0])]).astype(np.int64))

    if mode == "cv":
        benign = [i for i, c in enumerate(captures) if c["label"] == "benign" and c["set"] not in args.test_only]
        apart = [i for i, c in enumerate(captures) if c["set"] in args.test_only]
        tunnel_folds = _deal(known, args.folds, rng, lambda i: captures[i]["tool"])
        benign_folds = [sorted(f) for f in _deal(benign, args.folds, rng, lambda i: captures[i]["set"])]
        apart_folds = _deal(apart, args.folds, rng)  # tested once each, by whichever fold
        out = []
        for k in range(args.folds):
            train_b, held = hold_back([i for i in benign if i not in set(benign_folds[k])], captures,
                                      args.calibration, rng)
            out.append(split(f"fold {k + 1}", [i for i in known if i not in set(tunnel_folds[k])], tunnel_folds[k],
                             train_b, held, sorted(benign_folds[k] + apart_folds[k])))
        return out
    if mode == "tool":
        tools = sorted({captures[i]["tool"] for i in known})
        return [split(tool, [i for i in known if captures[i]["tool"] != tool],
                      [i for i in known if captures[i]["tool"] == tool]) for tool in tools]
    if mode == "unknown":
        return [split("unknown tools", known, unseen)]
    if mode == "rates":
        folds = _deal(known, args.folds, rng, lambda i: captures[i]["tool"])
        return [split(f"fold {k + 1}", [i for i in known if i not in set(f)], f, test_slowdowns=args.test_slowdowns)
                for k, f in enumerate(folds) if f]
    if mode == "final":
        everything = sorted(i for i in benign_train + benign_test if captures[i]["set"] not in args.test_only)
        return [Split("final", np.sort(np.r_[rows.of(tunnels, train_s), rows.of(everything, [1.0])]).astype(np.int64),
                      rows.of(benign_calibration, [1.0]), np.empty(0, np.int64))]
    raise ValueError(mode)


# ─── Training ───────────────────────────────────────────────────────────────


@dataclass
class SplitResult:
    split: Split
    scores: dict = field(default_factory=dict)
    thresholds: dict = field(default_factory=dict)
    fit_seconds: dict = field(default_factory=dict)
    fitted: dict = field(default_factory=dict)


def run_split(table: Table, split: Split, names: list[str], columns: list[int], args) -> SplitResult:
    result = SplitResult(split)
    full = table.X
    train, calibration, test = split.train, split.calibration, split.test
    for name in names:
        model = models.make(name, args.seed, args.threads, args.params.get(name))
        started = time.monotonic()
        model.fit(full[train][:, columns], table.y[train], full[train])
        result.fit_seconds[name] = round(time.monotonic() - started, 2)
        if model.fixed_threshold is not None:
            result.thresholds[name] = model.fixed_threshold
        else:
            result.thresholds[name] = metrics.threshold_at_fpr(
                model.score(full[calibration][:, columns], full[calibration]), args.fpr)
        result.scores[name] = model.score(full[test][:, columns], full[test]) if len(test) else np.empty(0)
        result.fitted[name] = model
    return result


# ─── Reports ────────────────────────────────────────────────────────────────


def _family(table: Table, captures: list[dict], rows: np.ndarray) -> np.ndarray:
    """A window's 'family' for per-family metrics: the tool of a tunnel, the set of a benign capture."""
    return np.array([captures[c]["tool"] or captures[c]["set"] for c in table.capture[rows]], dtype=object)


def false_alerts(table: Table, captures: list[dict], rows: np.ndarray, flagged: np.ndarray, gap: float,
                 allowlist: set[str]) -> dict:
    """Per benign set: alerts (flagged windows of one key less than `gap` s apart count once) per day of traffic."""
    out = {}
    benign = rows[~table.y[rows]]
    benign_flagged = flagged[~table.y[rows]]
    for kind in sorted({captures[c]["set"] for c in table.capture[benign]}):
        in_set = np.array([captures[c]["set"] == kind for c in table.capture[benign]], dtype=bool)
        hours = sum(captures[c]["hours"] for c in set(table.capture[benign[in_set]].tolist()))
        entry = {"captures": len(set(table.capture[benign[in_set]].tolist())), "hours": round(hours, 2),
                 "windows": int(in_set.sum()), "flagged": int(benign_flagged[in_set].sum())}
        for label, skip in (("", set()), ("_allowlisted", allowlist)):
            if label and not allowlist:
                continue
            hits = benign[in_set & benign_flagged]
            hits = [r for r in hits if table.keys[table.key[r]][2] not in skip]
            last: dict[int, float] = {}
            domains: Counter = Counter()
            for r in sorted(hits, key=lambda r: (table.key[r], table.end[r])):
                k = int(table.key[r])
                if k not in last or table.end[r] - last[k] > gap:
                    domains[table.keys[k][2]] += 1
                last[k] = float(table.end[r])
            alerts = sum(domains.values())
            entry[f"alerts{label}"] = alerts
            entry[f"alerts_per_day{label}"] = alerts / hours * 24 if hours else None
            if not label:  # what an allowlist would have to cover
                entry["top_domains"] = dict(domains.most_common(10))
        out[kind] = entry
    return out


def detections(table: Table, captures: list[dict], rows: np.ndarray, flagged: np.ndarray, within: float) -> list[dict]:
    """Per tunnel capture and slowdown: when the first alert came, and how much the client had sent up by then."""
    out = []
    tunnel = rows[table.y[rows]]
    tunnel_flagged = flagged[table.y[rows]]
    groups: dict[tuple[int, float], list[int]] = defaultdict(list)
    for position, r in enumerate(tunnel):
        groups[(int(table.capture[r]), float(table.slowdown[r]))].append(position)
    for (c, slowdown), positions in sorted(groups.items()):
        track = table.tracks[c]
        times = track.start + (track.times - track.start) * slowdown
        hits = [table.end[tunnel[p]] for p in positions if tunnel_flagged[p]]
        first = min(hits) if hits else None
        span = max(times[-1] - track.start, 1e-9)
        entry = {"capture": captures[c]["capture"], "tool": captures[c]["tool"], "rtype": captures[c]["rtype"],
                 "slowdown": slowdown, "windows": len(positions), "flagged": len(hits),
                 "recall": len(hits) / len(positions), "seconds": float(span),
                 "upstream_bytes": int(track.upstream[-1]),
                 "upstream_bytes_per_hour": float(track.upstream[-1] / span * 3600)}
        if first is not None:
            sent = int(np.searchsorted(times, first, side="right"))
            entry.update(delay=float(first - track.start), bytes_before=int(track.upstream[sent - 1]) if sent else 0)
        entry["detected"] = first is not None and first - track.start <= within
        out.append(entry)
    return out


def rate_summary(found: list[dict], within: float) -> list[dict]:
    """Per slowdown: share of captures detected within `within` s, window recall, delays, capacity (T5)."""
    out = []
    for slowdown in sorted({d["slowdown"] for d in found}):
        group = [d for d in found if d["slowdown"] == slowdown]
        delays = [d["delay"] for d in group if "delay" in d]
        out.append({
            "slowdown": slowdown, "captures": len(group),
            "detected": float(np.mean([d["detected"] for d in group])),
            "window_recall": float(sum(d["flagged"] for d in group) / max(sum(d["windows"] for d in group), 1)),
            "median_delay": float(np.median(delays)) if delays else None,
            "p90_delay": float(np.percentile(delays, 90)) if delays else None,
            "median_bytes_before": float(np.median([d.get("bytes_before", d["upstream_bytes"]) for d in group])),
            "median_upstream_bytes_per_hour": float(np.median([d["upstream_bytes_per_hour"] for d in group])),
        })
    return out


def r_min(summary: list[dict], target: float = 0.95) -> float | None:
    """The largest slowdown (slowest tunnel) still detected in time for at least `target` of the captures."""
    caught = [s["slowdown"] for s in summary if s["detected"] >= target]
    return max(caught) if caught else None


def ordinary(table: Table, captures: list[dict], rows: np.ndarray, args) -> np.ndarray:
    """Rows of the window metrics: all but the test-only benign sets (reported only as false alerts)."""
    return np.array([captures[c]["set"] not in args.test_only for c in table.capture[rows]], dtype=bool)


def evaluate(table: Table, captures: list[dict], rows: np.ndarray, score: np.ndarray, threshold: float, args, rng,
             allowlist: set[str]) -> dict:
    flagged = score > threshold
    main = ordinary(table, captures, rows, args)
    report = metrics.evaluate(table.y[rows[main]], score[main], flagged[main], _family(table, captures, rows[main]),
                              args.fpr, rng, args.bootstrap, args.bootstrap_curve, {})
    report["threshold"] = threshold
    report["false_alerts"] = false_alerts(table, captures, rows, flagged, args.alert_gap, allowlist)
    report["detections"] = detections(table, captures, rows, flagged, args.within)
    return report


def headline_of(report: dict) -> dict:
    keys = ("recall", "fpr", "roc_auc", "pr_auc", "recall_at_target_fpr")
    out = {k: (report[k]["value"] if isinstance(report.get(k), dict) else report.get(k)) for k in keys if k in report}
    for kind, entry in report.get("false_alerts", {}).items():
        out[f"{kind}_alerts_per_day"] = entry.get("alerts_per_day")
        if "alerts_per_day_allowlisted" in entry:
            out[f"{kind}_alerts_per_day_allowlisted"] = entry["alerts_per_day_allowlisted"]
    found = report.get("detections", [])
    if found:
        out["captures_detected"] = float(np.mean([d["detected"] for d in found]))
        delays = [d["delay"] for d in found if "delay" in d]
        out["median_delay"] = float(np.median(delays)) if delays else None
    return out


def report_pooled(table, captures, results, names, args, rng, allowlist) -> dict:
    """One evaluation over every split's test rows together (cv: each window is tested once)."""
    rows = np.concatenate([r.split.test for r in results])
    main = ordinary(table, captures, rows, args)
    report, correct = {"models": {}, "scores": {}}, {}
    for name in names:
        # each split's own threshold: compare to it, then pool the decisions
        margin = np.concatenate([r.scores[name] - r.thresholds[name] for r in results])
        report["models"][name] = evaluate(table, captures, rows, margin, 0.0, args, rng, allowlist)
        report["models"][name]["thresholds"] = [r.thresholds[name] for r in results]
        correct[name] = ((margin > 0) == table.y[rows])[main]
        report["scores"][name] = margin[main]
    report["rows"] = rows[main]
    report["mcnemar"] = {f"{names[0]} vs {other}": metrics.mcnemar(correct[names[0]], correct[other])
                         for other in names[1:]}
    return report


def report_per_split(table, captures, results, names, args, rng, allowlist) -> dict:
    """tool, unknown, rates: the tunnels are tested once each, the benign test set in every split."""
    report = {"models": {}, "splits": {}}
    for name in names:
        tunnel_rows, tunnel_margin, per_split, found = [], [], {}, []
        fpr, alerts = [], defaultdict(list)
        for r in results:
            rows, score, threshold = r.split.test, r.scores[name], r.thresholds[name]
            evaluated = evaluate(table, captures, rows, score, threshold, args, rng, allowlist)
            per_split[r.split.name] = {k: v for k, v in evaluated.items() if k != "detections"}
            found += evaluated["detections"]
            positive = table.y[rows]
            tunnel_rows.append(rows[positive])
            tunnel_margin.append(score[positive] - threshold)
            fpr.append(evaluated["fpr"]["value"])
            for kind, entry in evaluated["false_alerts"].items():
                for key in ("alerts_per_day", "alerts_per_day_allowlisted"):
                    if entry.get(key) is not None:
                        alerts[f"{kind}_{key}"].append(entry[key])
        rows = np.concatenate(tunnel_rows)
        flagged = np.concatenate(tunnel_margin) > 0
        tools = _family(table, captures, rows)
        recall_by_tool = {str(t): float(flagged[tools == t].mean()) for t in sorted(set(tools))}
        summary = rate_summary(found, args.within)
        report["models"][name] = {
            "tool_recall": recall_by_tool,
            "mean_tool_recall": float(np.mean(list(recall_by_tool.values()))) if recall_by_tool else None,
            "recall": float(flagged.mean()) if len(flagged) else None,
            "fpr": float(np.mean(fpr)),
            **{k: float(np.mean(v)) for k, v in sorted(alerts.items())},  # over the splits
            "rates": summary,
            "r_min": r_min(summary),
            "detections": found,
        }
        report["splits"][name] = per_split
    return report


def headline(mode: str, report: dict) -> dict:
    if mode == "final":
        return {"threshold": report["threshold"]}
    if mode == "cv":
        return {n: headline_of(m) for n, m in report["models"].items()}
    keys = ("mean_tool_recall", "recall", "fpr", "r_min")
    out = {}
    for n, m in report["models"].items():
        out[n] = {k: v for k, v in m.items() if k in keys or "_alerts_per_day" in k}
        for s in m.get("rates", []):
            out[n][f"detected_at_1/{s['slowdown']:g}"] = s["detected"]
            out[n][f"window_recall_at_1/{s['slowdown']:g}"] = s["window_recall"]
            if s["slowdown"] == 1:
                out[n]["median_delay"] = s["median_delay"]
    return out


def table_t5(report: dict, names: list[str], path: Path, within: float) -> None:
    """T5: per slowdown, how often each detector caught the tunnel in time, and what slipping under it allows."""
    lines = [f"Detected: share of held-out captures with an alert within {within:g} s of the tunnel's start. "
             "Capacity: the median capture's upstream bytes (data in the names) per hour at that rate.", "",
             "| Rate | Capacity (kB/h) | "
             + " | ".join(f"{models.TITLES.get(n, n)}: detected, delay (s)" for n in names) + " |",
             "|---|---|" + "---|" * len(names)]
    first = report["models"][names[0]]["rates"]
    for i, s in enumerate(first):
        cells = []
        for n in names:
            entry = report["models"][n]["rates"][i]
            delay = "-" if entry["median_delay"] is None else f"{entry['median_delay']:.0f}"
            cells.append(f"{entry['detected']:.2f}, {delay}")
        lines.append(f"| 1/{s['slowdown']:g} | {s['median_upstream_bytes_per_hour'] / 1000:,.1f} | "
                     + " | ".join(cells) + " |")
    lines += ["", "R_min (slowest rate detected in time for >= 95% of captures): "
              + ", ".join(f"{models.TITLES.get(n, n)} {_rate(report['models'][n]['r_min'])}" for n in names)]
    path.write_text("\n".join(lines) + "\n")


def _rate(slowdown) -> str:
    return "none" if slowdown is None else f"1/{slowdown:g}"


# ─── The final model ────────────────────────────────────────────────────────


def save_final(result: SplitResult, captures: list[dict], table: Table, groups: list[str], window: float,
               out: Path, args) -> dict:
    """The deployed model: LightGBM's trees and model.json (features, threshold, windows)."""
    name = args.final_model
    model = result.fitted[name]
    if name != "lgbm":
        raise SystemExit("the analyzer reads LightGBM models: use --final-model lgbm")
    model.inner.model.booster_.save_model(str(out / "tunnel_lgbm.txt"))
    rows = result.split.train
    trained = sorted({captures[c]["capture"] for c in table.capture[rows]})
    card = {
        "model": "tunnel_lgbm.txt",
        "features": [n for g in groups for n in FEATURE_GROUPS[g]],
        "groups": groups,
        "threshold": result.thresholds[name],
        "target_fpr": args.fpr,
        "window_seconds": window,
        "step_seconds": args.step,
        "train_slowdowns": args.train_slowdowns,
        "trained_on": {"tunnel_windows": int(table.y[rows].sum()), "benign_windows": int((~table.y[rows]).sum()),
                       "captures": len(trained),
                       "tools": sorted({captures[c]["tool"] for c in table.capture[rows] if captures[c]["tool"]})},
        "dataset_sha256": dataset_info(args.data).get("events_sha256"),
        "lightgbm_params": model.params,
    }
    (out / "model.json").write_text(json.dumps(card, indent=1) + "\n")
    return card


# ─── Running a mode ─────────────────────────────────────────────────────────


def run_mode(mode: str, captures: list[dict], table: Table, rows: Rows, groups: list[str], window: float,
             allowlist: set[str], args) -> dict:
    started = time.monotonic()
    out = args.out / args.tag / f"w{window:g}-f{''.join(groups)}" / mode
    out.mkdir(parents=True, exist_ok=True)
    columns = [ALL_FEATURES.index(n) for g in groups for n in FEATURE_GROUPS[g]]
    names = [args.final_model] if mode == "final" else args.models
    usable = []
    for split in splits_for(mode, captures, rows, args):
        problem = _problem(split, table, mode)
        if problem and mode == "final":
            raise SystemExit(f"final: {problem}")
        if problem:
            log(f"{mode} / {split.name}: skipped, {problem}")
        else:
            usable.append(split)
    splits = usable
    if not splits:
        return {}
    rng = np.random.default_rng(args.seed)
    results = []
    for split in splits:
        log(f"{mode} / {split.name}: train {len(split.train):,} windows ({int(table.y[split.train].sum()):,} tunnel), "
            f"calibration {len(split.calibration):,}, test {len(split.test):,}")
        results.append(run_split(table, split, names, columns, args))
    if mode == "final":
        report = save_final(results[0], captures, table, groups, window, out, args)
    elif mode == "cv":
        report = report_pooled(table, captures, results, names, args, rng, allowlist)
        from .plots import curves

        y = table.y[report["rows"]]
        np.savez_compressed(out / "scores.npz", y=y, **{f"score_{n}": s for n, s in report.pop("scores").items()})
        curves(out / "scores.npz", names, out / "roc_pr.png", args.fpr)
        report.pop("rows")
    else:
        report = report_per_split(table, captures, results, names, args, rng, allowlist)
        if mode == "rates":
            from .plots import delay_cdf, recall_vs_rate

            recall_vs_rate(report, names, out / "F10_recall_vs_rate.png", args.within)
            delay_cdf(report, names, out / "F11_detection_delay.png")
            table_t5(report, names, out / "T5_exfiltration.md", args.within)
    if mode != "final":
        report["thresholds"] = {n: [r.thresholds[n] for r in results] for n in names}
        report["fit_seconds"] = {n: sum(r.fit_seconds[n] for r in results) for n in names}
        report["sizes"] = {n: results[-1].fitted[n].size() for n in names}
        write_json(out / "metrics.json", report)
    info = {
        "mode": mode, "tag": args.tag, "features": groups, "window": window, "step": args.step,
        "models": names, "fpr": args.fpr, "train_slowdowns": args.train_slowdowns,
        "test_slowdowns": args.test_slowdowns, "within": args.within, "fraction": args.fraction,
        "splits": [{"name": s.name, "train": len(s.train), "calibration": len(s.calibration), "test": len(s.test),
                    "test_tunnel": int(table.y[s.test].sum())} for s in splits],
        "params": args.params, "seconds": round(time.monotonic() - started, 1),
        "dataset": dataset_info(args.data),
        "environment": environment(),
        "headline": headline(mode, report),
    }
    write_json(out / f"run_info_{mode}.json", info)
    log(f"{mode} done in {info['seconds']:.0f} s: {json.dumps(info['headline'], default=str)[:1500]}")
    return report


def _problem(split: Split, table: Table, mode: str) -> str:
    """Why a split can't be run (only on tiny datasets), or ""."""
    if not table.y[split.train].any() or table.y[split.train].all():
        return "its training captures are all of one class"
    if not len(split.calibration):
        return "no benign captures left to hold back for the threshold"
    if mode != "final" and (not table.y[split.test].any() or table.y[split.test].all()):
        return "no tunnel or no benign captures to test"
    return ""


def parse_groups(text: str) -> list[str]:
    groups = [g.strip().upper() for g in text.split(",") if g.strip()]
    unknown = [g for g in groups if g not in FEATURE_GROUPS]
    if unknown or not groups:
        raise SystemExit(f"unknown feature groups {unknown}: choose from {', '.join(FEATURE_GROUPS)}")
    return groups


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mode", choices=MODES + ["all"], required=True)
    parser.add_argument("--data", type=Path, default=REPO / "ml" / "data" / "tunnel")
    parser.add_argument("--out", type=Path, default=REPO / "ml" / "runs" / "tunnel")
    parser.add_argument("--tag", default="main", help="experiment name: results go to <out>/<tag>/")
    parser.add_argument("--cache", type=Path, help="where cut windows are kept for the next run (default: OUT/cache)")
    parser.add_argument("--features", nargs="+", default=["V,N,R"],
                        help="feature groups (V volume/timing, N names, R record types/responses); several sets "
                             "give one run each")
    parser.add_argument("--models", default=DEFAULT_MODELS, help=f"comma-separated, from {','.join(models.NAMES)}")
    parser.add_argument("--final-model", default="lgbm")
    parser.add_argument("--windows", type=float, nargs="+", default=[60.0], help="window lengths (s); one run each")
    parser.add_argument("--step", type=float, default=STEP_SECONDS)
    parser.add_argument("--train-slowdowns", type=float, nargs="+", default=[1, 2, 10],
                        help="stretched copies of the training tunnels (10: a tenth of the rate)")
    parser.add_argument("--test-slowdowns", type=float, nargs="+", default=[1, 2, 10, 100])
    parser.add_argument("--within", type=float, default=600.0,
                        help="a tunnel counts as detected if an alert comes within this many seconds of its start")
    parser.add_argument("--alert-gap", type=float, default=600.0,
                        help="flagged windows of one client and domain less than this apart are one alert")
    parser.add_argument("--fraction", type=float, default=1.0, help="share of each benign set's captures")
    parser.add_argument("--train-wildcard", action="store_true",
                        help="train on wildcard DNS as benign, instead of only testing for false alerts on it")
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--fpr", type=float, default=1e-4, help="target false-positive rate (benign windows)")
    parser.add_argument("--calibration", type=float, default=0.1, help="share of benign training captures held back")
    parser.add_argument("--benign-test", type=float, default=0.2, help="share of each benign set's captures tested")
    parser.add_argument("--allowlist", type=Path,
                        help="popular domains never judged (default: DATA/allowlist_top100k.txt)")
    parser.add_argument("--bootstrap", type=int, default=1000)
    parser.add_argument("--bootstrap-curve", type=int, default=100)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--threads", type=int, default=os.cpu_count() or 1)
    parser.add_argument("--params", type=Path, help="JSON settings per model, e.g. {\"lgbm\": {\"num_leaves\": 63}}")
    args = parser.parse_args(argv)
    args.params = json.loads(args.params.read_text()) if args.params else {}
    args.models = [m.strip() for m in args.models.split(",") if m.strip()]
    args.test_only = set() if args.train_wildcard else set(TEST_ONLY_SETS)
    missing = [m for m in args.models + [args.final_model] if not models.available(m)]
    if missing:
        raise SystemExit(f"not installed: {missing} (pip install -r ml/requirements.txt)")
    missing = [str(path) for path in (events_file(args.data), args.data / "captures.csv") if not path.exists()]
    if missing:
        raise SystemExit(f"no {' or '.join(missing)} (events.csv.gz or events.csv, and captures.csv): "
                         f"run python -m ml.tunnel.data --out {args.data}")
    allowlist_path = args.allowlist or args.data / "allowlist_top100k.txt"
    allowlist = set(allowlist_path.read_text().split()) if allowlist_path.exists() else set()
    feature_sets = [parse_groups(text) for text in args.features]
    modes = MODES if args.mode == "all" else [args.mode]
    for window in args.windows:
        captures, table = load(args, window)
        rows = Rows(table)
        log(f"{len(table):,} windows: {int(table.y.sum()):,} tunnel ({len(table.tracks)} captures), "
            f"{int((~table.y).sum()):,} benign")
        for groups in feature_sets:
            for mode in modes:
                run_mode(mode, captures, table, rows, groups, window, allowlist, args)


if __name__ == "__main__":
    sys.exit(main())
