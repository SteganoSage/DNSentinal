"""Phase 3: tuning a boosted-tree model's settings without touching any test set.

    python -m ml.dga.pipeline --mode tune --models lgbm --trials 40 [--timeout-hours 8]
    python -m ml.dga.pipeline --mode lofo --params <out>/<tag>/f-<groups>/tune/best_params.json

The question is the leave-family-out one, asked of training data only. The
DGA families are dealt into 5 groups and the benign training names into 5
parts; a trial trains 5 times, each time without one group and one part,
and scores what lofo scores: each left-out family's recall at the threshold
that flags 0.1% of the benign calibration names. The objective is the mean
over all families (each is left out once). The benign test names (the 20%
every other mode tests on) and Netlab's real names are never seen, so the
runs made afterwards with the settings found stay honest.

Searched besides the library's own settings: family_balance, a training
weight that evens out the families (pipeline.family_weights). Settings
whose model would be too big for the resolver's C++ fast path (more than
MAX_LEAVES leaves in all) are skipped. The first trial is the current
defaults, so the gain from tuning is measured on the same question.

Writes <out>/<tag>/f-<groups>/tune/: trials.csv (rewritten after every
trial), best_params.json (for --params) and run_info_tune.json.
"""

from __future__ import annotations

import copy
import csv
import datetime as dt
import json
import statistics
import time

import numpy as np

from .features import FEATURE_GROUPS
from .pipeline import COLUMN, Split, benign_holdout, environment, run_split, write_json
from .progress import log

GROUPS = 5
MAX_LEAVES = 60_000  # trees x leaves: about 10 µs and a few MB once compiled to C++
BALANCE = [0.0, 0.25, 0.5, 0.75, 1.0]


def _lgbm(trial) -> dict:
    return {
        "n_estimators": trial.suggest_int("n_estimators", 100, 1000, step=50),
        "learning_rate": trial.suggest_float("learning_rate", 0.01, 0.2, log=True),
        "num_leaves": trial.suggest_int("num_leaves", 15, 255, log=True),
        "min_child_samples": trial.suggest_int("min_child_samples", 5, 500, log=True),
        "subsample": trial.suggest_float("subsample", 0.5, 1.0),
        "colsample_bytree": trial.suggest_float("colsample_bytree", 0.4, 1.0),
        "reg_lambda": trial.suggest_float("reg_lambda", 1e-3, 30.0, log=True),
    }


def _xgboost(trial) -> dict:
    return {
        "n_estimators": trial.suggest_int("n_estimators", 100, 1000, step=50),
        "learning_rate": trial.suggest_float("learning_rate", 0.01, 0.2, log=True),
        "max_leaves": trial.suggest_int("max_leaves", 15, 255, log=True),
        "min_child_weight": trial.suggest_float("min_child_weight", 0.1, 50.0, log=True),
        "subsample": trial.suggest_float("subsample", 0.5, 1.0),
        "colsample_bytree": trial.suggest_float("colsample_bytree", 0.4, 1.0),
        "reg_lambda": trial.suggest_float("reg_lambda", 1e-3, 30.0, log=True),
    }


SPACES = {"lgbm": _lgbm, "xgboost": _xgboost}
DEFAULTS = {  # the first trial: models.py's settings, in the search's terms
    "lgbm": {"n_estimators": 300, "learning_rate": 0.05, "num_leaves": 31, "min_child_samples": 50,
             "subsample": 0.8, "colsample_bytree": 1.0, "reg_lambda": 1.0, "family_balance": 0.0},
    "xgboost": {"n_estimators": 300, "learning_rate": 0.05, "max_leaves": 31, "min_child_weight": 1.0,
                "subsample": 0.8, "colsample_bytree": 1.0, "reg_lambda": 1.0, "family_balance": 0.0},
}


def group_splits(data, args) -> list[Split]:
    """5 splits of the training data: each leaves out a fifth of the families and of the benign names."""
    b_train, _ = benign_holdout(data, args.benign_test, args.seed)  # the benign test names stay unseen
    dga = (data.kind == "dga") & ~data.external
    families = sorted(set(data.family[dga].astype(str)))
    rng = np.random.default_rng(args.seed)
    order = rng.permutation(len(families))
    groups = [[families[i] for i in order[k::GROUPS]] for k in range(GROUPS)]
    parts = np.array_split(rng.permutation(b_train), GROUPS)
    splits = []
    for k in range(GROUPS):
        held = dga & np.isin(data.family.astype(str), groups[k])
        benign = np.sort(np.concatenate([parts[j] for j in range(GROUPS) if j != k]))
        splits.append(Split(f"group {k + 1}: {', '.join(groups[k])}",
                            np.concatenate([benign, np.flatnonzero(dga & ~held)]),
                            np.concatenate([np.sort(parts[k]), np.flatnonzero(held)])))
    return splits


def _write_trials(study, path) -> None:
    names = sorted({p for t in study.trials for p in t.params})
    with open(path, "w", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["trial", "state", "value", "seconds", *names, "mean_fpr", "families_below_90"])
        for t in study.trials:
            seconds = (t.datetime_complete - t.datetime_start).total_seconds() if t.datetime_complete else ""
            writer.writerow([t.number, t.state.name, "" if t.value is None else round(t.value, 5),
                             round(seconds, 1) if seconds != "" else "", *[t.params.get(n, "") for n in names],
                             t.user_attrs.get("mean_fpr", ""), t.user_attrs.get("families_below_90", "")])


def tune(data, features, groups: list[str], args) -> dict:
    import optuna

    names = (args.models or "lgbm").split(",")
    unknown = [n for n in names if n not in SPACES]
    if unknown:
        raise SystemExit(f"tune mode tunes {', '.join(SPACES)} (got {', '.join(unknown)})")
    optuna.logging.set_verbosity(optuna.logging.WARNING)
    out = args.out / args.tag / f"f-{''.join(groups)}" / "tune"
    out.mkdir(parents=True, exist_ok=True)
    columns = [COLUMN[n] for g in groups for n in FEATURE_GROUPS[g]]
    splits = group_splits(data, args)
    for split in splits:
        log(f"tune: {split.name[:100]} (train {len(split.train):,}, test {len(split.test):,})")

    best = {}
    for name in names:
        started, clock = dt.datetime.now(dt.timezone.utc), time.monotonic()

        def objective(trial, name=name):
            params = SPACES[name](trial)
            balance = trial.suggest_categorical("family_balance", BALANCE)
            leaves = params["n_estimators"] * params.get("num_leaves", params.get("max_leaves", 31))
            if leaves > MAX_LEAVES:
                raise optuna.TrialPruned(f"{leaves:,} leaves: too big for the C++ fast path")
            trial_args = copy.copy(args)
            trial_args.params = {name: params, "family_balance": balance}
            recalls, fprs = [], []
            for step, split in enumerate(splits):
                result = run_split(data, split, [name], features, columns, trial_args)
                flagged = result.scores[name] > result.thresholds[name]
                y = data.y[split.test] == 1
                family = data.family[split.test].astype(str)
                recalls += [float(flagged[y & (family == f)].mean()) for f in sorted(set(family[y]))]
                fprs.append(float(flagged[~y].mean()))
                trial.report(statistics.mean(recalls), step)
                if trial.should_prune():
                    raise optuna.TrialPruned()
            trial.set_user_attr("mean_fpr", round(statistics.mean(fprs), 6))
            trial.set_user_attr("families_below_90", sum(r < 0.9 for r in recalls))
            return statistics.mean(recalls)

        def progress(study, trial, name=name):
            _write_trials(study, out / f"trials_{name}.csv")
            value = "pruned" if trial.value is None else f"{trial.value:.4f}"
            done = [t.value for t in study.trials if t.value is not None]
            log(f"tune {name} trial {trial.number}: {value}  {json.dumps(trial.params)}"
                + (f"  (best {max(done):.4f})" if done else ""))

        study = optuna.create_study(direction="maximize", sampler=optuna.samplers.TPESampler(seed=args.seed),
                                    pruner=optuna.pruners.MedianPruner(n_startup_trials=5, n_warmup_steps=1))
        study.enqueue_trial(DEFAULTS[name])
        study.optimize(objective, n_trials=args.trials, callbacks=[progress],
                       timeout=args.timeout_hours * 3600 if args.timeout_hours else None)
        settings = dict(study.best_params)
        balance = settings.pop("family_balance")
        baseline = study.trials[0].value
        best[name] = {"params": settings, "family_balance": balance, "objective": study.best_value,
                      "defaults_objective": baseline,
                      "trials": sum(t.state.name == "COMPLETE" for t in study.trials),
                      "pruned": sum(t.state.name == "PRUNED" for t in study.trials),
                      "seconds": round(time.monotonic() - clock, 1), "started": started.isoformat(timespec="seconds")}
        log(f"tune {name}: best {study.best_value:.4f} (defaults {baseline}) with {json.dumps(study.best_params)}")

    # --params format: settings per model, and the family balance (of the first model tuned).
    first = names[0]
    write_json(out / "best_params.json", {**{n: best[n]["params"] for n in names},
                                          "family_balance": best[first]["family_balance"],
                                          "tuned": {n: {k: v for k, v in best[n].items() if k != "params"}
                                                    for n in names}})
    info = {"mode": "tune", "tag": args.tag, "features": groups, "benign": args.benign,
            "splits": [s.name for s in splits], "results": best, "max_leaves": MAX_LEAVES,
            "args": {k: str(v) for k, v in vars(args).items()}, "environment": environment(), "headline": {}}
    write_json(out / "run_info_tune.json", info)
    return best
