# DNSentinel: results for the report

Every number here comes from a run whose raw data and settings are kept: the source is under each
table. Targets are EVALUATION.md's. The "Status" column says whether a target is met, missed, or
still to run.

| Part | Experiments | Status |
|---|---|---|
| 1. DGA classifier, on its own | E7, E9 | done |
| 2. Tunnel detector, on its own | E8 | done |
| 3. The full pipeline, end to end | E-pipeline: C0 (Unbound) to C5 (everything) | **to run** (the lab is ready) |
| Supporting | E1 correctness (done), S1 (done); E2, E5+A1, E6, E10, E11 | partly done |

---

## Part 1: the DGA classifier (E7, E9)

**What it is.** LightGBM over 20 features of a name's registrable label (character n-grams, entropy,
digits, vowels, word segmentation, TLD, label rhythm). It runs in the resolver on each new
registrable domain. "Recall at 0.1% FPR" means the threshold flags 0.1% of benign names.

**Table D1: the shipped model** (features A–E + G, tuned; benign = Tranco ranks beyond the top 100k)

| Test | Recall at 0.1% FPR | 95% CI |
|---|---|---|
| Unseen families (leave one family out; mean of 50) | **0.613** | per family in metrics.json |
| Unseen families, at 1% FPR | 0.800 | |
| Real DGA names (Netlab) of the families we generate | **0.630** | 0.628–0.632 |
| Cross-validation (families seen in training) | 0.847 | 0.846–0.849 |
| Names dated after training | **0.900** | 0.894–0.905 |
| Dictionary DGAs (concatenated words) | 0.000 | ROC-AUC 0.44: they look like real sites |

Source: `ml/dga/README.md` "Final model"; Kaggle run 2026-10-20 (`dga_results (11).zip`, leaderboard row `final-r2g`).

**Table D2: against the E7 baselines** (same test names; features A–E, round-1 settings)

| Detector | Unseen-family recall @0.1% | @1% | Real-name recall | CV recall | PR-AUC (CV) | Later dates |
|---|---|---|---|---|---|---|
| **LightGBM (ours)** | **0.595** | **0.805** | **0.562** | **0.788** | **0.994** | **0.850** |
| Entropy threshold | 0.061 | 0.163 | 0.050 | 0.081 | 0.591 | 0.094 |
| Blocklist alone | 0.000 | 0.000 | 0.000 | 0.000 | 0.322 | 0.000 |

Source: `dga_results (3).zip` leaderboard (`tuned`, stable benign). Against the unfiltered Tranco tail
(`dga_results (2).zip`, `tuned-allbenign`), LightGBM drops to 0.458 unseen and 0.510 real names; the
entropy rule to 0.054 and 0.046.

**Model comparison** (phase 2, 2026-10-19; features A–E, untuned, unseen-family recall at 0.1% FPR):
- LightGBM, XGBoost and HistGB tied at 0.570–0.573;
- the random forest was behind at 0.553, and 80× larger;
- the char-CNN (untuned) reached 0.577, but was 3× slower.

LightGBM was best on cross-validation and real names, and smallest and fastest, so it was tuned
and shipped. Source: `ml/dga/README.md` "Models". The per-model table needs that run's
leaderboard, which isn't among the local zips; see "To do", item 4.

**Table D3: on real traffic** (2026-11-01; the tunnel dataset's 39.7 h of Stratosphere browsing and
24.4 h of a client resolving Cloudflare's top 1M; the model as the resolver runs it)

| | Domains scored | Flagged | Rate |
|---|---|---|---|
| Browsing, before `provider_suffixes` | 3,204 | 534 (529 CloudFront distributions) | 16.7% |
| Browsing, with `provider_suffixes` (shipped) | 2,671 | **1** (`wedfrwd.co`) | **0.04%** |
| Cloudflare top 1M crawl, beyond the top 100k | 855,021 | 9,021 | 1.1% (many junk registrations) |

Source: `ml/dga/README.md` "On real traffic"; the replay in `docs/results.md` §Method notes.

**Table D4: cost in the resolver (E9; target ≤ 50 µs median per new name)**

| | Median | p90 | p99 |
|---|---|---|---|
| New name, scored (C++) | **40.8 µs** | 54.0 µs | 63.2 µs |
| Name seen before (verdict cache) | 0.34 µs | 0.53 µs | 1.07 µs |

| Daemon throughput (dnsperf, best of 5) | Queries/s | vs ML off |
|---|---|---|
| ML off | 43,259 | — |
| DGA on, verdict cache | 41,692 | −3.6% |
| DGA on, scoring every query | 10,889 | −74.8% |

Target met for latency (40.8 ≤ 50 µs). The "< 1% throughput cost with a warm cache" target is
**missed** (−3.6%), because of per-query bookkeeping in a mix that is 27% DGA names. Source:
`bench/README.md`; `bench/results/e9/`.

---

## Part 2: the tunnel detector (E8)

**What it is.** One verdict per (client, registrable domain), on the last 60 s of queries, every 10 s.
It runs in the slow path, `analyzer.live`, off the event stream. There are 24 features in four groups:
- **V:** volume and timing;
- **N:** the names;
- **R:** record types and responses;
- **D:** data carried.

The threshold flags 0.01% of the windows of each benign set, and an alert needs **two
consecutive** flagged windows. The model is never shown the test tools ("unseen") or the left-out
tool, nor wildcard DNS.

**Table T1: model comparison** (final runs, 2026-11-01, Kaggle, tuned settings; columns with
features V,N,R,D unless marked)

| | RF | **LightGBM (shipped)** | XGBoost | RF without D | LightGBM without D |
|---|---|---|---|---|---|
| Unseen tools: mean recall per tool | 0.965 | **0.966** | 0.967 | 0.954 | 0.966 |
| Unseen-tool captures caught | 42/43 | **42/43** | 42/43 | 42/43 | 42/43 |
| Left-out known tool: recall | 0.999 | **0.999** | 0.992 | 0.805 | 0.922 |
| Known-tool captures caught at 1/100 rate (1/1000) | 117 (98) | **117 (101)** | 117 (101) | 117 (97) | 116 (100) |
| Browsing false alerts in 39.7 h (with allowlist) | 7 (1) | **6 (1)** | 8 (1) | 7 (1) | 6 (1) |
| Wildcard-DNS false alerts a day, allowlisted | 215 | 262 | 239 | 215 | 262 |
| Model size | 2.4 MB | **0.65 MB** | 0.11 MB | | |
| Per window, in the analyzer | 0.33 ms (JSON trees) | **0.16 ms** | | | |

Source: `ml/tunnel/README.md` "Final runs"; `tunnel_results (3).zip` (V,N,R,D) and `tunnel_results (4).zip` (V,N,R).

- **Why LightGBM.** RF and LightGBM tie once significance is counted: McNemar's test favours RF
  22 to 5 on CV windows (p = 0.002), but the bootstrap intervals overlap. The pre-registered
  tie-break, the smaller and faster model, then picks LightGBM. XGBoost drops out on left-out
  iodine (2,353/2,446 windows, CI 0.955–0.969, against RF's 0.996–1.000).
- **What D does.** Without D, the forest catches 35 of 644 DNS-shell windows when that tool is
  left out of training, and LightGBM 451 of 644. With D, both catch all but one.

**Table T2: against the E8 baselines** (V,N,R,D run; the same test)

| Detector | Unseen-tool recall | Left-out tool | Slowest rate caught ≥95% (R_min) | Caught at 1/100 | Browsing false alerts a day |
|---|---|---|---|---|---|
| **LightGBM (ours)** | **0.966** | **0.999** | **1/100** | **1.000** | 3.6 |
| Isolation Forest (benign only) | 0.814 | 0.684 | 1/10 | 0.239 | 5.4 |
| Queries per minute to one domain | 0.786 | 0.611 | none | 0.000 | 9.7 |
| Hand-written rules | 0.644 | 0.522 | none | 0.060 | 0.6 |

Source: `tunnel_results (3).zip` leaderboard.

**Table T3: rate and delay** (shipped model, 117 known-tool captures slowed down by stretching
their clock)

| Rate | Captures caught (two windows) | One window alone | Median delay to alert |
|---|---|---|---|
| full speed | 117/117 | 117/117 | **14.7 s** (p90 18.5 s; target ≤ 60 s) |
| 1/2, 1/10, 1/100 | 117/117 each | 117/117 | |
| 1/1000 | 101/117 (86%) | 99% | |
| 1/10000 | 96/117 (82%) | 99% | |

Source: `tunnel_results (3).zip`, `main/w60-fVNRD/rates/metrics.json`; figures F10 (recall vs rate)
and F11 (delay) in the same folder.

**Weak spots, for the report:**
- **Cobalt Strike** is the hardest unseen tool for every model: 0.82–0.84 of its windows.
- **Wildcard DNS** gets about 240–260 false alerts a day, even with the allowlist. Wildcard DNS
  means random names under a domain that answers every one.
- At 1/1000 and slower, two windows come too late for 14–18% of captures.

---

## Part 3: the full pipeline, end to end

### So far: one attack at a time, through the real daemon (tests/integration/tunnel_e2e.py)

| | Rules only | Trained model + fusion |
|---|---|---|
| Tunnel (2 TXT queries/s): time to alert and block | 25–28 s | **13–15 s** |
| DGA malware's command server (20 failed names, then one that resolves): time to block after it resolves | 4–10 s | 4–10 s |
| Collateral (the same domain for another client; the 20 failed names) | none blocked | none blocked |

**Score fusion's false alerts on benign traffic** (the dataset's captures replayed through
`analyzer.live`): **0** command-server alerts in 39.7 h of browsing, 24.4 h of a 1M-domain
crawl, and 1 h of wildcard DNS. Without the popular-site allowlist, wildcard DNS drew 191 tunnel
alerts in an hour (on `google.com`, `facebook.com` and the like); with it, 10. Source: `ml/tunnel/README.md` "Score fusion".

### To run: configurations C0–C5 (the main comparison)

| Config | What it is |
|---|---|
| C0 | Unbound: a standard resolver, no protection |
| C1 | DNSentinel, no ML (block lists and policy only) |
| C2 | + the DGA classifier, monitor mode |
| C3 | + the DGA classifier, enforce mode |
| C4 | + the slow path with the hand-written rules, enforce |
| C5 | everything: DGA + tunnel model + fusion, enforce |

**Traffic**, the same under every config:
- benign browsing (W2);
- DGA malware: real families' names, plus a command server that resolves;
- tunnels: real iodine carrying a file, plus synthetic tunnels at full rate and 1/10.

**Metrics:**
- attacks detected;
- time to alert, and time to block;
- bytes exfiltrated before the block;
- malicious queries answered;
- false alerts, and benign queries blocked;
- latency p50/p95/p99, maximum throughput, CPU and memory.

Table P1 and figures P1–P3 go here when it has run.

---

## Supporting experiments

**E1: correctness against Unbound** (lab, both resolvers cold, same root; target ≥ 99% agreement,
no unexplained mismatch)

| Name set | Queries | Agreement | Notes |
|---|---|---|---|
| W3: Tranco top 10,000 × {A, AAAA} | 20,000 | **100%** | no SERVFAIL on either side |
| The hierarchy's crafted cases | 33 | **100%** | 1 transient: Unbound timed out once on the 800 ms server, DNSentinel answered in 904 ms |
| Policy (block lists, cloaked trackers, rebinding) | 6 | differs by design | DNSentinel answers 0.0.0.0 / `::` or strips the private address |

The crafted cases are CNAME chains of 1–8 hops, five-level and glueless delegations, a lame
server, a server that drops 0x20, out-of-bailiwick records, a TXT that needs TCP, NXDOMAIN and
empty non-terminals.

**Target met.** Cold-cache latency in the lab was 1.9 ms median for DNSentinel against 1.4 ms for
Unbound (p95 3.0 ms against 2.3 ms); E2 measures this properly. Source: `bench/results/E1/20261101T164840Z/`.

**S1: what encrypted DNS costs per access link** (ns-3; a stand-in server, the link isolated)

| Link | UDP median | DoT/DoH reused | DoT/DoH new connection |
|---|---|---|---|
| 4G (60 ms, 1% loss) | 60.1 ms | 60.2 ms | 181.2 ms (p95 381 ms) |
| Lossy (50 ms, 5% loss) | 50.2 ms (p95 **1,050 ms**) | 50.3 ms (p95 301 ms) | |
| GEO satellite (600 ms) | | | 1,802 ms |

- A new encrypted connection costs three round trips against UDP's one.
- On a reused connection, encrypted DNS costs the same as UDP.
- On a lossy link TCP recovers faster than UDP's 1 s retry.

Source: `sim/ns3/README.md`; `~/dnsentinel-sim/summary.txt`.

**Known limitation found in the lab.** DNSentinel's DoH speaks HTTP/1.1 only. RFC 8484 recommends
HTTP/2 as the minimum, and `kdig` and browsers expect it.

---

## Method notes
- **The lab** (`lab/README.md`) is a Docker network with no route to the internet:
  - NSD as root, TLDs and authoritative servers, plus a Python server for misbehaviour;
  - DNSentinel, with the analyzer on its event stream, and Unbound as the baseline;
  - clients, an infected host and attackers.
  - `lab/lab.sh check` runs 23 checks.
- **Runs** go through `bench/run.py <config>`. Each run folder keeps its raw CSVs, `summary.json`
  and `metadata.json`: git commit, config hashes, image IDs, kernel, CPU, seed.
- **Assumptions:**
  - W1 (a week of our own traffic) was not collected. Real-traffic false positives use the
    dataset's 39.7 h of browsing.
  - W2's Zipf exponent is 0.9, an assumption from the literature.
  - The real-internet runs of E1/E2 are left for later.

## To do (these are the user's)
1. Commit the score-fusion work and the lab (commit blocks in the session).
2. Freeze the targets before the final runs (EVALUATION.md §9 rule 1): one dated commit.
3. Optional, only if the report needs the per-model DGA table: a Kaggle run of
   `python -m ml.dga.pipeline --mode all --models rf,lgbm,xgboost,histgb --features A,B,C,D,E,G`.
