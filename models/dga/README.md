# The DGA classifier the resolver ships

Trained by `python -m ml.dga.pipeline --mode final` (Kaggle, 2026-10-20, commit `5c35c11`,
dataset SHA-256 `61aeb6a…`), with features A-E + G and the settings in
`ml/dga/params/lgbm_tuned.json`. Score a name with `python -m ml.dga.scorer <name>`.

| File | |
|---|---|
| `dga_lgbm.txt` | LightGBM model: 450 trees, 108 leaves at most, 96,750 nodes |
| `features.json` | the fitted feature tables: benign 3-gram, TLD shares, benign 2-gram, DGA 3-gram, rhythm 4-gram |
| `model.json` | feature order, threshold (0.9558: flags 0.1% of benign calibration names), training counts, word-list SHA-256 |
| `run_info_final.json` | how it was run: arguments, library versions, machine |

The word features also need `config/english_words.txt` (checked against `model.json`), and
every name is split with `config/public_suffix_list.dat`.

How well it does (the same settings, evaluated without the test names in training; 0.1% FPR):
unseen families 0.613 mean recall, real (Netlab) names 0.630, cross-validation 0.847, later
dates 0.900; dictionary DGAs are not caught. Details: `ml/dga/README.md`, "Final model".
