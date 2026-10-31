# DNS tunnel detector

The slow-path detector of README §7.8.3 and its evaluation, EVALUATION.md E8. It judges each
**(client, registrable domain)** on the last 60 s of its queries, every 10 s: one query can't
reveal a tunnel, a minute of behaviour can. The detector is `analyzer/detectors/tunnel.py`;
everything here builds its data, trains it and measures it.

| File | |
|---|---|
| `pcap.py` | Query events from pcap/pcapng captures, in the resolver's own form (name text, rcode, response size) |
| `data.py` | Builds the dataset from pinned sources (`ml/DATA.md`), or your own captures |
| `graphtunnel_files.json`, `korving_files.json` | The tunnel captures used: commits, sizes, git blob hashes (and each Korving session's settings) |
| `pipeline.py` | Cuts the detector's windows, trains and evaluates every E8 split, writes the final model |
| `models.py` | The candidates and E8's baselines |
| `tune.py` | Searches RF, LightGBM and XGBoost settings on training data only (`--mode tune`) |
| `plots.py`, `leaderboard.py` | F10, F11, ROC/PR; every run side by side |
| `scorer.py` | The final model as the analyzer runs it |
| `../notebooks/tunnel_pipeline.ipynb` | Runs all of it on Kaggle or Colab |

## Run it

On Kaggle or Colab: open `ml/notebooks/tunnel_pipeline.ipynb`; its first cell lists the setup.

Locally (`ml/requirements.txt`):

```bash
python3 -m venv ~/venvs/dnsentinel-ml && ~/venvs/dnsentinel-ml/bin/pip install -r ml/requirements.txt
~/venvs/dnsentinel-ml/bin/python -m ml.tunnel.data --out ml/data/tunnel     # downloads ~7.5 GB, keeps ~1.5 GB
~/venvs/dnsentinel-ml/bin/python -m ml.tunnel.pipeline --mode all           # or cv, tool, unknown, rates, final, tune
~/venvs/dnsentinel-ml/bin/python -m ml.tunnel.leaderboard ml/runs/tunnel
```

`--browsing small` downloads only the smaller browsing captures (~2.5 GB in all); `--fraction
0.1` trains on a tenth of each benign set, for a quick look; `python -m ml.tunnel.data --out
/tmp/x --smoke` makes a tiny made-up dataset with the same files, without the network.

## What each mode answers

| Mode | Train | Test | Output |
|---|---|---|---|
| `cv` | 5 folds over captures: known tools and every benign set | the held-out captures | ROC/PR, false alerts a day per benign set |
| `tool` | every known tool but one | the one left out | recall per tool |
| `unknown` | the known tools | tools never trained on: cobaltstrike, dns2tcp (GraphTunnel's and Korving's), ozymandns, tcp-over-dns, and iodine's Android client | recall per tool (GraphTunnel's robustness test) |
| `rates` | 5 folds over known-tool captures | each held-out capture at every rate | F10, F11, T5, R_min |
| `final` | everything | — | `tunnel_rf.pkl` (`--final-model`), `model.json` |
| `tune` | every known tool but one, on training captures only | the one left out | `best_params.json` (see Tuning) |

Captures, not windows, are split: windows of one capture overlap and must not be on both sides
(`tests/ml/test_tunnel_pipeline.py` checks it). Outside `cv`, the same 20% of each benign set's
captures is the test set. In every split 10% of each benign set's training captures is held back,
and each model's threshold is set so that at most 0.01% (`--fpr`) of **each set's** windows are
flagged (the strictest set decides; `--calibrate pooled` uses them all together). In the first
full run the threshold was set on them all together, about 90% crawl windows that score almost
exactly 0: it came out low (0.008 for LightGBM) and real browsing, scoring a little higher,
crossed it about 30 times a day. The hand-written rules keep their own "high" threshold.

**Training weights.** The crawl's ~900k single-query windows would otherwise outweigh real
browsing's ~100k nine to one. `benign_balance` (in `--params`, per model; tuned) evens out the
benign sets: 0 leaves them as they are, 1 gives each set the same total weight.

`cv` and `rates` deal captures into folds tool by tool, so each tool's captures spread over the
folds and the tools with a single capture land in different ones. Dealt at random, dnspot and
DNS-shell (the only tunnels in A records) once fell in the same fold: that fold's model had seen
no A-record tunnel and missed both, which is `tool` mode's question, not `cv`'s.

**Wildcard DNS is only tested.** Enumerating a wildcard domain's subdomains makes thousands of
unique names under one domain a minute: the very shape of a tunnel, which training on it as
benign would teach the models to let through. So, as GraphTunnel meant it, it is a robustness
test: its false alerts are reported on their own and left out of the window metrics
(`--train-wildcard` trains on it instead, to compare).

**Slower tunnels** (E8's rates ½, 1/10, 1/100) are emulated by stretching a capture's clock: at
slowdown 10 the same queries come ten times further apart. Training uses slowdowns 1, 2 and 10
(`--train-slowdowns`), so the models see slow tunnels; `rates` tests 1, 2, 10, 100, 1000 and
10000 (the slower ones only on the known tools, which are what `rates` tests). A tunnel
counts as **detected** if an alert comes within 10 minutes of its first query (`--within`);
**R_min** is the slowest rate at which at least 95% are. **Delay** is seconds from the first
query to the first alert; **bytes before** is what the client had sent up in names by then.
**Capacity** (T5) is upstream bytes per hour at a rate: what an attacker slow enough to slip
under R_min can still send.

**Alerts.** A window is *flagged* when it scores over the threshold; an **alert** needs two
consecutive flagged windows of the same client and domain (`--alert-after 2`). Tunnels last
minutes; the browsing windows flagged in the first full run were mostly one-window bursts to a
CDN. It costs one step (10 s) of delay at full speed, and more at the slowest rates, where the
second window comes with the second query. Every number below is also reported for one flagged
window alone (`_single_window`), to compare.

**False alerts a day**: alerts of one client and domain less than 10 minutes apart count as one,
divided by the hours of benign traffic tested. Reported for each benign set, and again with the
Tranco top 100k allowlisted (as deployed), because popular CDNs and anti-virus lookups are the
known false-alarm sources (README §7.8.3); `top_domains` lists what an allowlist would need.

Each run writes `ml/runs/tunnel/<tag>/w<window>-f<groups>/<mode>/`: `metrics.json` (window
metrics with bootstrap 95% intervals, per tool, per benign set, every detection), `run_info_<mode>.json`
(settings, versions, timings, headline numbers) and the figures. `--windows 30 60 120` repeats
everything for E8's window-size factor.

## Windows

Windows end on a fixed grid (every 10 s) and hold the key's queries of the last 60 s. A key is
judged at a window end only if it had a new query since it was last judged, so idle keys cost
nothing and a tunnel's first verdict comes at most 10 s after its first query. Training feeds
the captured queries through the same `SlidingWindowDetector` the analyzer feeds live ones
through: there is no separate training window. In a tunnel capture only the tunnel's domain
(the one it queries most) is used; the lab machine's other lookups are left out.

## Features

| Group | Features |
|---|---|
| V, volume and timing | `query_count`, `active_seconds`, `mean_interval`, `interval_cv` (tunnels poll steadily) |
| N, the names below the registrable domain | `unique_subdomain_count` and `_ratio` (tunnel data never repeats), `mean`/`max_subdomain_length`, `mean`/`max_label_length` (labels packed up to 63 bytes), `mean_subdomain_labels`, `mean_subdomain_entropy`, `pooled_entropy` (base32 ~5 bits, words ~4), `distinct_characters` (hex 16, base32 32), `digit_ratio`, `unusual_character_ratio` (bytes a hostname can't have: binary encodings) |
| R, record types and responses | `data_type_ratio` (types other than A, AAAA, HTTPS, PTR, ...: TXT, NULL, CNAME, MX, SRV, KEY, private), `mean`/`max_response_size`, `nxdomain_ratio` |
| D, the data carried (added 2026-10-31) | `unique_subdomain_bytes` (bytes of the distinct subdomains: what was sent up, a repeat counted once), `long_label_ratio` (labels of 32 bytes or more), `hex_ratio` (bytes in 0-9 a-f), `length_cv` (how much the subdomain lengths vary) |

Lengths and characters are those of the wire labels, decoded from the resolver's escaped text
form. No feature names the domain, so a model can't memorise the datasets' tunnel domain.
`--features V,N,R V,N,R,D` runs one after the other: the ablation that decides on D.

D answers the first full run's misses. DNS-shell asks every name twice (only half its
subdomains are unique) and writes hex in A records with small answers: the boosting libraries,
which learned a sharp "unique subdomains above about 0.8" rule, flagged almost none of its
windows; the data it carries up, counted once, is still a tunnel's.

## Models, and how we choose

Candidates: **random forest** and **LightGBM** (README §7.8.3), XGBoost and HistGradientBoosting
from the same wrappers as the DGA model, and an **Isolation Forest** fitted on benign windows
only (no tunnel examples, as in reality). E8's baselines run alongside: **queries per minute**
to one domain over a threshold, and the **hand-written rules** (`score_features`).

Decided before the results:
1. **Primary:** recall on tools never trained on (`unknown`) and on the left-out known tool
   (`tool`), at 0.01% FPR on benign windows.
2. False alerts a day on real browsing (`cv`) must stay low; on a tie, fewer wins.
3. E8's targets (`rates`): at least 95% of tunnels caught at their default rate, within 60 s;
   R_min reported.
4. A difference counts only if the bootstrap intervals and McNemar's test (p < 0.05) agree;
   otherwise the smaller, faster model wins.

## Results

**First full run** (2026-10-31, Kaggle, 4 CPUs, 26 min: 255 captures, 2.94M queries, 1.74M
windows; features V, N, R; threshold on all benign sets together; one flagged window an alert):

| | RF | XGBoost | LightGBM | HistGB | Isolation Forest | Queries/min | Rules |
|---|---|---|---|---|---|---|---|
| Unseen tools (`unknown`, window recall) | 0.963 | 0.956 | 0.968 | 0.968 | 0.870 | 0.814 | 0.644 |
| Left-out known tool (`tool`) | **1.000** | 0.994 | 0.775 | 0.944 | 0.820 | 0.652 | 0.522 |
| Cross-validation window recall | **1.000** | 0.901 | 0.900 | 0.900 | 0.906 | 0.801 | 0.684 |
| Tunnels caught in 10 min at 1/100 | 117/117 | 116/117 | 117/117 | 117/117 | 51/117 | 0 | 8 |
| Browsing false alerts a day (`cv`; allowlisted) | 31.4 (5.4) | 18.7 (0.6) | 35.7 (5.4) | 33.8 (7.3) | 51.4 (9.7) | 38.1 (5.4) | 0.6 (0) |

The random forest wins on the primary questions (McNemar against LightGBM on `cv`: 739 windows
to 113, p ≈ 1e-101); it is the final model (`--final-model rf`). E8 at the default rate: all
117 held-out captures caught, median delay 4.7 s (90th percentile 8.5 s, target 60 s), R_min at
least 1/100, the slowest rate tested then. Cobaltstrike, never trained on, is the hardest tool
(0.78-0.84 of its windows). The weak spot is false alerts on real browsing, from where the
threshold sat (above): the per-set threshold, benign weights, two-window alerts, features D and
tuning are the answer, measured by the next run.

## Tuning

```bash
python -m ml.tunnel.pipeline --mode tune --models rf,lgbm,xgboost --trials 40 --timeout-hours 9 \
    --features V,N,R V,N,R,D
python -m ml.tunnel.pipeline --mode all --params <out>/main/w60-f<groups>/tune/best_params.json --features <groups>
```

The settings chosen go to `ml/tunnel/params/`, as the DGA model's do, for the notebook's `PARAMS`.

Each trial asks `tool` mode's question of the training data only (`tune.py`): it trains once
per known tool without it, sets the threshold on a held-out part of the benign training
captures (0.01% of each set's windows), and scores the left-out tool at full speed and at 1/10.
The objective is that recall, averaged over the tools; the threshold being fixed by benign
windows, a trial can't buy recall with false alerts. `benign_balance` is searched with each
library's settings, and the first trial is the defaults. The benign test captures, wildcard DNS
and the unknown tools are never seen, so `unknown` afterwards is the untouched check (`tool`
asks the question tuned on, so it flatters the tuned settings).

## In the analyzer

```bash
python -m analyzer.tunnel_analyzer events.jsonl --model ml/runs/tunnel/main/w60-fVNR/final
```

reads `model.json` (features, threshold, window, step, alert rule) and the model it names
(`tunnel_rf.pkl`, pickled: load only models trained here, with the library versions the card
records; or `tunnel_lgbm.txt`) and gives every window a verdict: `high` above the threshold,
with the rules' reasons as the explanation. `"alert": true` marks the windows that complete two
consecutive `high` ones of a client and domain. Without `--model` the hand-written rules judge
alone.

## Your own captures

E8 also wants tunnels made in our lab (iodine and dnscat2 through DNSentinel, at set rates) and
false alerts on our own devices' traffic (W1). Capture with
`sudo tcpdump -i <if> -w day1.pcap port 53` (or Wireshark's dumpcap), then

```
captures/benign/<device>/day1.pcap           normal use, one capture per session
captures/tunnel/<tool>/<tool>-txt-slow.pcap  one tunnel session per capture, nothing else running
```

and `python -m ml.tunnel.data --out ml/data/tunnel --local captures`: they become the `local` set,
trained and tested with the known tools and benign captures.

## Tests

```bash
python3 -m unittest discover -s tests/ml -t .   # also run by ctest as ml_python
```
