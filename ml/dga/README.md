# DGA classifier

The resolver's fast-path detector (README §7.8.2) and its evaluation, EVALUATION.md E7.
It scores the **registrable label** of a name (the part left of the public suffix:
`example` in `x7kq2.example.co.uk`, `cvyh1po636` in `cvyh1po636.ddns.net`). The resolver
will run the exported model (`final/`); everything here is offline.

| File | |
|---|---|
| `psl.py` | Public Suffix List (`config/public_suffix_list.dat`, pinned), the same file the resolver reads |
| `features.py` | The features (six groups), the n-gram models, TLD prior and word list; the reference for the C++ port |
| `grams.py` | The same n-gram models fitted and scored on a whole dataset at once (the pipeline's fast path) |
| `data.py` | Builds the dataset from pinned sources (`ml/DATA.md`) |
| `pipeline.py` | Trains and evaluates every E7 split; writes metrics, figures and the final model |
| `models.py`, `charcnn.py` | The candidate models and E7's baselines |
| `metrics.py`, `plots.py`, `leaderboard.py` | Bootstrap CIs, McNemar's test, F8/F9, every run side by side |
| `tune.py` | Phase 3: tunes LightGBM/XGBoost settings on training data only (`--mode tune`) |
| `../notebooks/dga_pipeline.ipynb` | Runs all of it on Kaggle or Colab |

## Run it

On Kaggle or Colab: open `ml/notebooks/dga_pipeline.ipynb`; its first cell lists the setup.

Locally (`ml/requirements.txt`; about 10 GB of RAM for the full data):

```bash
python3 -m venv ~/dga-venv && ~/dga-venv/bin/pip install -r ml/requirements.txt
~/dga-venv/bin/python -m ml.dga.data --out ml/data          # about 10 min: downloads + generation
~/dga-venv/bin/python -m ml.dga.pipeline --mode cv          # or lofo, dictionary, future, external, final, all
~/dga-venv/bin/python -m ml.dga.pipeline --mode lofo --models lgbm --features A A,B A,B,C   # an ablation
~/dga-venv/bin/python -m ml.dga.leaderboard ml/runs         # every run so far, side by side
```

`--fraction 0.05` runs on 5% of every family, for a quick look. `python -m ml.dga.data --out
/tmp/smoke --smoke` makes a tiny made-up dataset with the same files, for trying the pipeline
without the network.

## What each mode answers

| Mode | Train | Test | Output |
|---|---|---|---|
| `cv` | stratified 5-fold over benign + DGA | the held-out fold | F8, T4, McNemar |
| `lofo` | every DGA family but one | the one left out | F9: recall per unseen family |
| `dictionary` | all non-dictionary families | gozi, matsnu, nymaim2, suppobox | reported separately (E7) |
| `future` | DGA names dated before `--cutoff` | names dated after it | drift over time |
| `external` | all our data | Netlab 360's real names of families we generate | does it hold on real names |
| `final` | everything | — | `dga_lgbm.txt`, `features.json`, `model.json` |

Benign names are Tranco ranks beyond 100k (the top 100k are allowlisted and never scored),
and by default only the **stable** ones: also in the Tranco lists of 6 and 12 months earlier.
Throwaway and malicious names don't last a year, and in the tail they were most of the false
alarms. `--benign all` uses the whole tail instead, to report alongside. Outside `cv`, the same
20% of benign names is the test set in every mode.

Every split is run the same way: 10% of the benign training names are held back; the fitted
features are fitted on the rest (training names are scored leave-one-out, so they don't look
more familiar than new ones); each model's threshold is set so that at most 0.1% (`--fpr`) of
the held-back names are flagged; then the test names are judged.

Each run writes `ml/runs/<tag>/f-<groups>/<mode>/`: `metrics.json` (every metric, overall and per
family, with bootstrap 95% CIs), `run_info_<mode>.json` (settings, library versions, git
commit, timings, headline numbers), `scores.npz` (every test score, for re-plotting with
`python -m ml.dga.plots ml/runs`) and the figures.

## Features

| Group | Features | Fitted per split? |
|---|---|---|
| A, character statistics | `label_length`, `entropy`, `digit_ratio`, `vowel_ratio`, `consonant_ratio`, `longest_consonant_run`, `hex_ratio`, `distinct_ratio` | no |
| B, benign language | `ngram_log_likelihood` (3-gram of benign labels), `tld_log_share` (how common the TLD is among benign names) | yes, on benign training names |
| C, structure | `is_idn` (xn--), `letter_digit_switches`, `hyphens`, `longest_digit_run` | no |
| D, words | `word_coverage` (share of the label covered by English words), `longest_word` | no (`config/english_words.txt`) |
| E, more n-grams | `bigram_log_likelihood` (benign 2-gram), `dga_likelihood_ratio` (benign minus DGA 3-gram) | yes, on training names |
| F, popularity | `label_in_allowlist` (the label is an allowlisted site's under another suffix: google.de) | no (the allowlist) |
| G, rhythm | `cv_alternation` (how evenly consonants and vowels alternate), `rhythm_log_likelihood` (4-gram of the label's consonant/vowel shape) | the second, on benign training names |

`--features A,B,C` picks groups; several sets (`--features A A,B A,B,C`) give one run each.
The ablation (2026-10-18) kept A-E: F added nothing. G was added after phase 3 for the families
everything misses: syllable-built DGAs (pushdo `nafojeivo`, vawtrak, simda) alternate consonants
and vowels more evenly than real names do, and hex ones (orchard `40e5720e`) less.

## Models, and how we choose

Candidates: **random forest**, three gradient-boosting libraries (**LightGBM**, **XGBoost**,
scikit-learn's **HistGradientBoosting**, from comparable settings) and a **character CNN**
(`--add-models cnn`, on a GPU). E7's baselines run alongside: an entropy threshold and the
blocklist alone.

Decided before the results:
1. **Primary:** mean recall at 0.1% FPR on unseen families (`lofo`).
2. It must hold on real names (`external`).
3. A difference counts only if the bootstrap CIs and McNemar's test (p < 0.05) agree; otherwise
   the smaller, faster model wins.
4. It must fit E9 (≤ 50 µs per new name in C++). A CNN too slow for that would run only on the
   names the boosted trees are unsure of (a cascade).

Phase 2 (2026-10-19, full data, features A-E): the three boosting libraries tied on unseen
families (0.570-0.573 mean recall at 0.1% FPR; 0.81 at 1%); LightGBM was best on cross-validation
and real names, and the smallest and fastest, so it is the model to tune and ship. Random forest
was behind (0.553) and 80 times bigger.

## Tuning (phase 3)

```bash
python -m ml.dga.pipeline --mode tune --models lgbm --trials 40 --timeout-hours 9
python -m ml.dga.pipeline --mode all --params ml/runs/main/f-ABCDE/tune/best_params.json
```

The families are dealt into 5 groups and each trial trains 5 times, each time without one group:
the leave-family-out question on training data only. The benign test names and the real
(external) names are never used, so the runs made afterwards with the settings found stay
honest. Besides the library's settings it searches `family_balance`, a training weight that
evens out the families; settings that would make the model too big for the C++ fast path are
skipped. The first trial is the current defaults, so the gain is measured on the same question.

First round (2026-10-19, 40 trials, objective: unseen families only): 0.560 -> 0.601 on the
tuning folds, and 0.570 -> 0.595 in the full leave-family-out run, but the settings it chose (a
slow learning rate, strong regularisation, full family balancing) fit known families loosely:
real names fell 0.624 -> 0.562, cross-validation 0.864 -> 0.783, later dates 0.909 -> 0.850.
Switching balancing off recovered only a third of that. So the objective now asks both
questions: each fold also holds back a fifth of the names of the families it trains on, and a
trial scores `--unseen-weight` (0.5) x unseen-family recall + the rest x known-family recall.
`params/lgbm_tuned.json` holds the first round's trial 10 until the second round replaces them: it tied
the best trial on the tuning objective without family balancing, and in full runs beat it everywhere
(unseen families 0.605, real names 0.611, cross-validation 0.830, later dates 0.881).

Second round (2026-10-20, two-part objective, 80 trials per feature set; unseen / known recall on
the tuning folds): A-E went from 0.553 / 0.863 (defaults) to 0.578 / 0.874, better on both;
A-E+G from 0.532 / 0.841 to 0.606 / 0.858. Every top trial chose no family balancing. Untuned, the
rhythm features hurt; tuned (strong L2), they give the best unseen-family recall but cost some on
known families, and the objectives differ by only 0.006, so full runs decide between
`params/lgbm_round2_ABCDE.json` and `params/lgbm_round2_ABCDEG.json` (use each with its `--features`).

## Tests

```bash
python3 -m unittest discover -s tests/ml -t .   # also run by ctest as ml_python
```

Tests that need scikit-learn or LightGBM skip where they aren't installed.
