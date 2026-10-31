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
| `plots.py`, `leaderboard.py` | F10, F11, ROC/PR; every run side by side |
| `scorer.py` | The final model as the analyzer runs it |
| `../notebooks/tunnel_pipeline.ipynb` | Runs all of it on Kaggle or Colab |

## Run it

On Kaggle or Colab: open `ml/notebooks/tunnel_pipeline.ipynb`; its first cell lists the setup.

Locally (`ml/requirements.txt`):

```bash
python3 -m venv ~/venvs/dnsentinel-ml && ~/venvs/dnsentinel-ml/bin/pip install -r ml/requirements.txt
~/venvs/dnsentinel-ml/bin/python -m ml.tunnel.data --out ml/data/tunnel     # downloads ~7.5 GB, keeps ~1.5 GB
~/venvs/dnsentinel-ml/bin/python -m ml.tunnel.pipeline --mode all           # or cv, tool, unknown, rates, final
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
| `final` | everything | — | `tunnel_lgbm.txt`, `model.json` |

Captures, not windows, are split: windows of one capture overlap and must not be on both sides
(`tests/ml/test_tunnel_pipeline.py` checks it). Outside `cv`, the same 20% of each benign set's
captures is the test set. In every split 10% of each benign set's training captures is held back,
and each model's threshold is set so that at most 0.01% (`--fpr`) of their windows are flagged:
per set, so the real browsing's harder windows always help set it, not only the crawl's easy
ones. The hand-written rules keep their own "high" threshold.

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
(`--train-slowdowns`), so the models see slow tunnels; `rates` tests 1, 2, 10 and 100. A tunnel
counts as **detected** if an alert comes within 10 minutes of its first query (`--within`);
**R_min** is the slowest rate at which at least 95% are. **Delay** is seconds from the first
query to the first alert; **bytes before** is what the client had sent up in names by then.
**Capacity** (T5) is upstream bytes per hour at a rate: what an attacker slow enough to slip
under R_min can still send.

**False alerts a day**: flagged windows of one client and domain less than 10 minutes apart
count as one alert, divided by the hours of benign traffic tested. Reported for each benign
set, and again with the Tranco top 100k allowlisted (as deployed), because popular CDNs and
anti-virus lookups are the known false-alarm sources (README §7.8.3).

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

Lengths and characters are those of the wire labels, decoded from the resolver's escaped text
form. No feature names the domain, so a model can't memorise the datasets' tunnel domain.
`--features V,N R ...` runs an ablation.

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

## In the analyzer

```bash
python -m analyzer.tunnel_analyzer events.jsonl --model ml/runs/tunnel/main/w60-fVNR/final
```

reads `tunnel_lgbm.txt` and `model.json` (features, threshold, window and step) and gives every
window a verdict: `high` above the threshold, with the rules' reasons as the explanation.
Without `--model` the hand-written rules judge alone.

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
