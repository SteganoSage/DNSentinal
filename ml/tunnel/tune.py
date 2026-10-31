"""Tuning the tunnel models' settings on training data only (--mode tune).

    python -m ml.tunnel.pipeline --mode tune --models rf,lgbm,xgboost --trials 40 --timeout-hours 9
    python -m ml.tunnel.pipeline --mode all --params <out>/<tag>/w60-f<groups>/tune/best_params.json

A trial asks `tool` mode's question of the training data. It trains once per
known tool, each time without that tool and without one of as many parts of
the benign training captures (dealt per set). That part sets the threshold,
as the pipeline does (at most --fpr of each benign set's windows flagged),
and the left-out tool's windows are scored at full speed and at a tenth of
it. The objective is that recall, averaged over the two rates and over the
tools (each tool counts the same, however many captures it has). The
threshold being fixed by benign windows the model never trained on, a trial
can't buy recall with false alerts.

Never seen while tuning: the benign test captures (the fixed 20% the other
modes test on), wildcard DNS and the unknown tools. `unknown` mode, run
afterwards with the settings found, is the untouched check; `tool` mode asks
the question tuned on, so its numbers after tuning are optimistic.

Searched besides each library's settings: benign_balance, a training weight
evening out the benign sets (pipeline.balance_weights). The first trial is
the current defaults, so the gain is measured on the same question. Several
feature sets are tuned one after the other, sharing --timeout-hours.

Writes <out>/<tag>/w<window>-f<groups>/tune/: trials_<model>.csv (rewritten
after every trial), best_params.json (for --params) and run_info_tune.json.
"""

from __future__ import annotations

import copy
import csv
import datetime as dt
import json
import statistics
import time

import numpy as np

from analyzer.detectors.tunnel import FEATURE_GROUPS

from ..dga.progress import log
from .pipeline import (
    ALL_FEATURES,
    KNOWN_SETS,
    Rows,
    Split,
    Table,
    _deal,
    benign_partition,
    environment,
    run_split,
    write_json,
)

RATES = (1.0, 10.0)  # the left-out tool is scored at full speed and at a tenth of it
BALANCE = [0.0, 0.25, 0.5, 0.75, 1.0]


def _rf(trial) -> dict:
    return {
        "n_estimators": trial.suggest_int("n_estimators", 100, 400, step=50),
        "max_depth": trial.suggest_int("max_depth", 8, 30),
        "min_samples_leaf": trial.suggest_int("min_samples_leaf", 2, 100, log=True),
        "max_features": trial.suggest_categorical("max_features", ["sqrt", "log2", 0.3, 0.5, 0.8]),
        "max_samples": trial.suggest_float("max_samples", 0.2, 1.0),
        "class_weight": trial.suggest_categorical("class_weight", [None, "balanced"]),
    }


def _lgbm(trial) -> dict:
    return {
        "n_estimators": trial.suggest_int("n_estimators", 100, 1000, step=50),
        "learning_rate": trial.suggest_float("learning_rate", 0.01, 0.2, log=True),
        "num_leaves": trial.suggest_int("num_leaves", 8, 255, log=True),
        "min_child_samples": trial.suggest_int("min_child_samples", 5, 500, log=True),
        "subsample": trial.suggest_float("subsample", 0.5, 1.0),
        "colsample_bytree": trial.suggest_float("colsample_bytree", 0.3, 1.0),
        "reg_lambda": trial.suggest_float("reg_lambda", 1e-3, 30.0, log=True),
    }


def _xgboost(trial) -> dict:
    return {
        "n_estimators": trial.suggest_int("n_estimators", 100, 1000, step=50),
        "learning_rate": trial.suggest_float("learning_rate", 0.01, 0.2, log=True),
        "max_leaves": trial.suggest_int("max_leaves", 8, 255, log=True),
        "min_child_weight": trial.suggest_float("min_child_weight", 0.1, 50.0, log=True),
        "subsample": trial.suggest_float("subsample", 0.5, 1.0),
        "colsample_bytree": trial.suggest_float("colsample_bytree", 0.3, 1.0),
        "reg_lambda": trial.suggest_float("reg_lambda", 1e-3, 30.0, log=True),
    }


SPACES = {"rf": _rf, "lgbm": _lgbm, "xgboost": _xgboost}
DEFAULTS = {  # the first trial: ml/dga/models.py's settings, in the search's terms
    "rf": {"n_estimators": 100, "max_depth": 20, "min_samples_leaf": 5, "max_features": "sqrt", "max_samples": 1.0,
           "class_weight": None, "benign_balance": 0.0},
    "lgbm": {"n_estimators": 300, "learning_rate": 0.05, "num_leaves": 31, "min_child_samples": 50,
             "subsample": 0.8, "colsample_bytree": 1.0, "reg_lambda": 1.0, "benign_balance": 0.0},
    "xgboost": {"n_estimators": 300, "learning_rate": 0.05, "max_leaves": 31, "min_child_weight": 1.0,
                "subsample": 0.8, "colsample_bytree": 1.0, "reg_lambda": 1.0, "benign_balance": 0.0},
}


def tool_splits(captures: list[dict], table: Table, rows: Rows, args) -> list[tuple[Split, str]]:
    """One split per known tool: trained without it and without one part of the benign training captures."""
    known = [i for i, c in enumerate(captures) if c["label"] == "tunnel" and c["set"] in KNOWN_SETS]
    tools = sorted({captures[i]["tool"] for i in known})
    train_b, calibration_b, _ = benign_partition(captures, args)  # the benign test captures stay unseen
    benign = sorted(train_b + calibration_b)
    parts = _deal(benign, len(tools), np.random.default_rng(args.seed), lambda i: captures[i]["set"])
    rates = [s for s in RATES if s in set(args.train_slowdowns) | set(args.test_slowdowns) | {1.0}]
    splits = []
    for k, tool in enumerate(tools):
        others = [i for i in known if captures[i]["tool"] != tool]
        held = [i for i in known if captures[i]["tool"] == tool]
        fit_b = [i for j, part in enumerate(parts) if j != k for i in part]
        train = np.sort(np.r_[rows.of(others, args.train_slowdowns), rows.of(fit_b, [1.0])]).astype(np.int64)
        splits.append((Split(f"without {tool}", train, rows.of(sorted(parts[k]), [1.0]), rows.of(held, rates)), tool))
    return splits


def _write_trials(study, path) -> None:
    names = sorted({p for t in study.trials for p in t.params})
    extra = ["recall_full_rate", "recall_tenth_rate", "worst_tool", "per_tool"]
    with open(path, "w", newline="") as stream:
        writer = csv.writer(stream)
        # value: complete trials only; a pruned trial's last report covers only the tools it got through
        writer.writerow(["trial", "state", "value", "partial_value", "seconds", *names, *extra])
        for t in study.trials:
            seconds = (t.datetime_complete - t.datetime_start).total_seconds() if t.datetime_complete else ""
            complete = t.state.name == "COMPLETE"
            partial = t.intermediate_values[max(t.intermediate_values)] if t.intermediate_values else None
            writer.writerow([t.number, t.state.name, round(t.value, 5) if complete else "",
                             "" if complete or partial is None else round(partial, 5),
                             round(seconds, 1) if seconds != "" else "", *[t.params.get(n, "") for n in names],
                             *[t.user_attrs.get(k, "") for k in extra]])


def tune(captures: list[dict], table: Table, rows: Rows, groups: list[str], window: float, args,
         sets: int = 1) -> dict:
    """Tune each of --models (those with a search space) on these feature groups."""
    import optuna

    names = [n for n in args.models if n in SPACES] or list(SPACES)
    skipped = [n for n in args.models if n not in SPACES]
    if skipped:
        log(f"tune: no settings to tune for {', '.join(skipped)}; tuning {', '.join(names)}")
    optuna.logging.set_verbosity(optuna.logging.WARNING)
    out = args.out / args.tag / f"w{window:g}-f{''.join(groups)}" / "tune"
    out.mkdir(parents=True, exist_ok=True)
    columns = [ALL_FEATURES.index(n) for g in groups for n in FEATURE_GROUPS[g]]
    splits = tool_splits(captures, table, rows, args)
    for split, _ in splits:
        log(f"tune [{''.join(groups)}] {split.name}: train {len(split.train):,} windows "
            f"({int(table.y[split.train].sum()):,} tunnel), threshold on {len(split.calibration):,}, "
            f"scored on {len(split.test):,}")
    timeout = args.timeout_hours * 3600 / (sets * len(names)) if args.timeout_hours else None

    best = {}
    for name in names:
        started, clock = dt.datetime.now(dt.timezone.utc), time.monotonic()

        def objective(trial, name=name):
            params = SPACES[name](trial)
            params["benign_balance"] = trial.suggest_categorical("benign_balance", BALANCE)
            trial_args = copy.copy(args)
            trial_args.params = {name: params}
            per_tool, full, tenth = {}, [], []
            for step, (split, tool) in enumerate(splits):
                result = run_split(table, split, [name], columns, trial_args)
                flagged = result.scores[name] > result.thresholds[name]
                recall = [float(flagged[table.slowdown[split.test] == s].mean()) for s in RATES
                          if (table.slowdown[split.test] == s).any()]
                full.append(recall[0])
                tenth.append(recall[-1])
                per_tool[tool] = round(statistics.mean(recall), 4)
                trial.report(statistics.mean(per_tool.values()), step)
                if trial.should_prune():
                    raise optuna.TrialPruned()
            trial.set_user_attr("recall_full_rate", round(statistics.mean(full), 5))
            trial.set_user_attr("recall_tenth_rate", round(statistics.mean(tenth), 5))
            trial.set_user_attr("worst_tool", min(per_tool, key=per_tool.get))
            trial.set_user_attr("per_tool", json.dumps(per_tool))
            return statistics.mean(per_tool.values())

        def progress(study, trial, name=name):
            _write_trials(study, out / f"trials_{name}.csv")
            if trial.state.name == "COMPLETE":
                value = f"{trial.value:.4f} {trial.user_attrs['per_tool']}"
            else:  # Optuna keeps a pruned trial's last report as its value
                value = f"pruned after {len(trial.intermediate_values)} of {len(splits)} tools"
            done = [t.value for t in study.trials if t.state.name == "COMPLETE"]
            log(f"tune {name} [{''.join(groups)}] trial {trial.number}: {value}  {json.dumps(trial.params)}"
                + (f"  (best {max(done):.4f})" if done else ""))

        study = optuna.create_study(direction="maximize", sampler=optuna.samplers.TPESampler(seed=args.seed),
                                    pruner=optuna.pruners.MedianPruner(n_startup_trials=5, n_warmup_steps=1))
        study.enqueue_trial(DEFAULTS[name])
        study.optimize(objective, n_trials=args.trials, callbacks=[progress], timeout=timeout)
        complete = [t for t in study.trials if t.state.name == "COMPLETE"]
        if not complete:
            log(f"tune {name}: no trial completed")
            continue
        top, first = study.best_trial, study.trials[0]
        best[name] = {"params": dict(study.best_params), "objective": top.value,
                      "per_tool": json.loads(top.user_attrs["per_tool"]),
                      "recall_full_rate": top.user_attrs["recall_full_rate"],
                      "recall_tenth_rate": top.user_attrs["recall_tenth_rate"],
                      "defaults": {"objective": first.value,
                                   "per_tool": json.loads(first.user_attrs.get("per_tool", "{}"))},
                      "trials": len(complete), "pruned": sum(t.state.name == "PRUNED" for t in study.trials),
                      "seconds": round(time.monotonic() - clock, 1), "started": started.isoformat(timespec="seconds")}
        log(f"tune {name} [{''.join(groups)}]: best {top.value:.4f} {top.user_attrs['per_tool']}; "
            f"defaults {first.value} with {json.dumps(study.best_params)}")

    # --params format: settings per model (benign_balance among them), and what tuning found
    write_json(out / "best_params.json", {**{n: b["params"] for n, b in best.items()},
                                          "tuned": {n: {k: v for k, v in b.items() if k != "params"}
                                                    for n, b in best.items()}})
    info = {"mode": "tune", "tag": args.tag, "features": groups, "window": window,
            "splits": [s.name for s, _ in splits], "results": best, "fpr": args.fpr, "calibrate": args.calibrate,
            "args": {k: str(v) for k, v in vars(args).items()}, "environment": environment(), "headline": {}}
    write_json(out / "run_info_tune.json", info)
    return best
