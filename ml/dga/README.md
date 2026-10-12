# DGA classifier

This directory contains the first DNSentinel ML component: an explainable
Random Forest baseline over lexical features. It is offline-only for now; it
does not change resolver behaviour.

## Dataset format

Use a CSV with this header:

```csv
domain,label,family
example.com,0,benign
generated-dga.example,1,banjori
```

The loader also accepts the headerless format used by the bundled
`dga_domains_full.csv` dataset:

```csv
dga,gozi,mortiscontrastatim.com
legit,alexa,plasticbags.sa.com
```

Here the columns are `label,family,domain`; labels may be `dga`/`legit`.

`label=0` is benign and `label=1` is DGA. Keep the DGA family name so later
evaluation can hold out an entire family rather than relying only on a random
split.

## Train

From the repository root:

```bash
python -m ml.dga.train ml/data/dga.csv --output models/dga_rf.joblib
```

Training requires `scikit-learn` and `joblib`. Generated model files are
ignored by git. Do not train on random strings alone: include CDN-like benign
domains and multiple real DGA families.

## Current limitation

The fallback public-suffix handling includes only common multi-label suffixes.
Before production training, add a pinned Public Suffix List and pass it to the
feature extractor, or integrate a PSL library. C++ export and resolver
integration are the next milestones after dataset/evaluation work.
