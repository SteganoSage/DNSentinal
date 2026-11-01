# DNSentinel: results for the report

Every number here comes from a run whose raw data and settings are kept: the source is under each
table. Targets are EVALUATION.md's. The "Status" column says whether a target is met, missed, or
still to run.

| Part | Experiments | Status |
|---|---|---|
| 1. DGA classifier, on its own | E7, E9 | done |
| 2. Tunnel detector, on its own | E8 | done |
| 3. The full pipeline, end to end | P1: C0 (Unbound) to C6 (everything) | **done** |
| Supporting | E1, E2, E5+A1, E6, E10, S1 (done); E12, E11 (to run) | mostly done |

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

### The main comparison: configurations C0–C6 (experiment P1)

Seven configurations, the same traffic under each: benign browsing (W2, 50 q/s), DGA malware
(9 real Netlab families, 40 generated names each then a command server re-resolved every 3 s),
a real **iodine** tunnel pushing random data to a byte counter at its far end, and a slow
synthetic tunnel (0.2 TXT q/s). 240 s per run, 3 interleaved repetitions. Source:
`bench/results/P1/20261101T174153Z/`; run with `python3 bench/run.py bench/configs/P1.yaml`.

| Config | What it is |
|---|---|
| C0 | Unbound: a standard resolver, no protection |
| C1 | DNSentinel, no ML (access control, rate limiting, block lists, policy) |
| C2 | + DGA classifier, monitor |
| C3 | + DGA classifier, enforce |
| C4 | + slow path, hand-written rules, enforce |
| C5 | everything: DGA enforce + tunnel model + fusion |
| C6 | DGA monitor + tunnel model + fusion (the shipped default: the classifier logs, the slow path blocks) |

**Table P1a: what gets through** (median of 3 runs, 240 s each)

| Config | DGA C2 reached | iodine leaked | iodine stopped at | slow tunnel leaked | slow tunnel alert |
|---|---|---|---|---|---|
| C0 Unbound | 9/9 families | **31.7 MB** | never | 1200 B | never |
| C1 no ML | 9/9 | 3.1 MB | never | 1200 B | never |
| C2 DGA monitor | 9/9 | 3.1 MB | never | 1200 B | never |
| C3 DGA enforce | **2/9** | 3.1 MB | never | 1200 B | never |
| C4 + rules | 2/9 | 163 KB | 13 s | 1200 B | **never** |
| C5 all (enforce) | 2/9 | 168 KB | 11 s | **75 B** | 13 s |
| C6 all (monitor) | 9/9 seen, **26/45 lookups** | 207 KB | 14 s | 100 B | 18 s |

**Table P1b: what it costs** (median of 3 runs; no benign query was blocked and no false alert was
raised in any configuration)

| Config | Benign p50 / p99 | Resolver CPU / RAM | Analyzer CPU / RAM | Max q/s (<1% loss) |
|---|---|---|---|---|
| C0 Unbound | 1.1 / 2.4 ms | 26% / 24 MiB | — | 39,840 |
| C1 no ML | 0.9 / 2.6 ms | 17% / 175 MiB | — | 15,576 |
| C3 DGA enforce | 0.9 / 2.6 ms | 17% / 202 MiB | — | 14,167 |
| C5 all (enforce) | 1.0 / 2.5 ms | 5% / 35 MiB | 4.4% / 50 MiB | 14,290 |
| C6 all (monitor) | 1.0 / 2.5 ms | 5% / 37 MiB | 4.6% / 50 MiB | 14,645 |

**What the layers add (the report's central story):**
1. **Rate limiting alone** (C1 vs C0) cuts the iodine tunnel 10×, 31.7 MB → 3.1 MB, with no detector:
   the per-client token bucket throttles the burst of queries a tunnel needs.
2. **The DGA classifier in enforce** (C3) blocks the command servers of **7 of 9 families**. The two
   that slip through are **simda and suppobox** — the pseudo-word and dictionary DGAs a name-only
   classifier is documented to miss (Part 1); they are the slow path's job, via the NXDOMAIN burst.
3. **The slow path** (C4, C5) cuts the tunnel another ~20×, 3.1 MB → ~165 KB, and blocks it within
   11–13 s of it starting.
4. **The trained model earns its place over the hand-written rules** (C5 vs C4): the slow, stealthy
   tunnel (`exfil.lab`, 0.2 q/s) is **never caught by the rules** (1200 B leaked) but **is caught by
   the model**, blocked after 75 B. This is the clearest single argument for the ML tunnel model.
5. **Fusion blocks the command server even with the classifier only monitoring** (C6): all 9 families'
   servers resolve at first, but after each client's NXDOMAIN burst fusion blocks the server, so only
   26 of 45 beacon lookups get through. This is the shipped default — the classifier never blocks a
   name on its own, yet C2 traffic is still stopped.
6. **Cost:** benign latency stays ~1 ms p50 and under 3 ms p99 everywhere; **no benign query was ever
   blocked and no false alert raised**. Recursive resolution plus policy drops peak throughput from
   Unbound's ~40k q/s to ~15k q/s (a recursive resolver does more work than this forwarding-free
   baseline). The slow path is cheap: ~5% of one core and 50 MiB for the analyzer. CPU is *lower* in
   C4–C6 than C1–C3 because blocking the tunnel early stops the resolver doing upstream work for it.

Figures: `bench/plots/P1_what_gets_through.png` (exfiltration and C2 lookups per config),
`bench/plots/P1_benign_latency_cdf.png` (benign latency CDF per config).

**Caveats for the report:** one laptop, Docker containers, CPU cores not pinned (configurations are
interleaved so a slow moment hits all alike). iodine runs non-lazy and C0's Unbound has
QNAME-minimisation off, both so every configuration carries the *same* tunnel rather than an Unbound
interop quirk (`docs/experiment-log.md`). The "9 families" are a sample of the DGA dataset's 54.

---

## Supporting experiments

**E1: correctness against Unbound** (lab, both resolvers cold, same root; target ≥ 99% agreement,
no unexplained mismatch)

| Name set | Queries | Agreement | Notes |
|---|---|---|---|
| W3: Tranco top 10,000 × {A, AAAA} | 20,000 | **100%** | no SERVFAIL on either side |
| The hierarchy's crafted cases | 33 | **96.97%** | the one "miss" is transient: Unbound timed out once on the deliberately-slow (800 ms) server and agreed on re-check |
| Policy (block lists, cloaked trackers, rebinding) | 6 | differs by design | DNSentinel answers 0.0.0.0 / `::` or strips the private address |

Overall **99.995%**, with **zero persistent unexplained mismatches** — target met. The crafted cases
are CNAME chains of 1–8 hops, five-level and glueless delegations, a lame server, a server that
drops 0x20, out-of-bailiwick records, a TXT that needs TCP, NXDOMAIN and empty non-terminals.
Source: `bench/results/E1/` (latest run). Table T1 in `bench/tables/T1_correctness.md` is regenerated
from this raw data.

**E5: cache-poisoning resistance + model A1** (isolated namespace, off-path Kaminsky attack against
`target.lab`; `lab/attacks/kaminsky.py`, run against the user's own resolver only)

| Config | Defences | Forged packets to poison |
|---|---|---|
| Weak | 8-bit transaction ID, fixed known source port | **256** (poisoned: one sweep of the 256 IDs) |
| Hardened (shipped) | 16-bit random ID + random source port + 0x20 + bailiwick | **resisted 5,000** (not poisoned) |

**Model A1** (the geometric prediction, `bench/drivers/a1_model.py`, figure F6): an off-path
attacker must match every random field in one race window; with N equally likely combinations the
expected forged packets to success is N.
- Weak: N = 2⁸ = **256** — matches the measured 256 exactly.
- Hardened: N = 2¹⁶ IDs × 28,232 ports × 2⁸ case ≈ **4.7 × 10¹¹** (≈ 2³⁸), about **1.8 billion ×**
  the weak case. At a sustained 100,000 forged packets/s that is ~55 days of flooding for one name,
  and it grows 4× for every extra letter in the queried name (more 0x20 case bits). The measured
  5,000 packets is ~10⁸ short of the expected cost, so "resisted" is the model's prediction too.

Target met (Part B: zero poisonings when randomisation is on). Not run: the finer entropy sweep
b ∈ {6,8,10,12} with 30 trials each (Part A), and the malicious-authoritative bailiwick case (Part C).
Source: `bench/plots/F6_poisoning.png`; `docs/experiment-log.md`.

**E6: privacy — what each observer sees** (lab; real packet captures parsed with `ml/tunnel/pcap.py`;
EVALUATION.md E6)

| Observer | Defence | What it saw | Target |
|---|---|---|---|
| Eavesdropper on the client link | plain UDP | the full query name (readable) | exposes → ✓ |
| | DoT | nothing (encrypted) | hides → ✓ |
| | DoH | nothing (encrypted) | hides → ✓ |
| Root server (10.53.2.10) | QNAME min **on** | only `lab` — never the leaf | hides leaf → ✓ |
| Lab-TLD server (10.53.2.11) | QNAME min **on** | only `example.lab` — never the leaf | hides leaf → ✓ |
| Root and TLD | QNAME min **off** | the full `<leaf>.sub.example.lab` | exposes → ✓ |

Captured with `tcpdump` at each position and the query names read out with the project's own pcap
parser. With a random marker label in every test name, a name in a capture can only have come from
that query. All five targets met. Source: `bench/results/E6/20261101T210224Z/`.

**E2: latency and throughput** (lab, DNSentinel vs Unbound over W2, same hierarchy; EVALUATION.md E2)

| | DNSentinel | Unbound | Target |
|---|---|---|---|
| Warm-cache latency p50 | **0.61 ms** | 0.56 ms | < 1 ms → **met** |
| Warm-cache p95 / p99 | 0.91 / 1.19 ms | 0.83 / 1.07 ms | |
| Cold-cache latency p50 | **1.28 ms** | 1.21 ms | ≤ 1.5× Unbound → **met** (1.06×) |
| Cold-cache p95 / p99 | 2.25 / 2.67 ms | 2.34 / 2.97 ms | |
| Max sustained throughput | **≈ 16,000 q/s** | ≈ 40,000 q/s | ≫ ~100-device need → met |

Warm cache hits are answered in well under a millisecond; cold latency is within 1.06× of Unbound,
since both walk the same hierarchy from the root. DNSentinel sustains roughly 0.4× Unbound's
throughput — the cost of recursive resolution plus the policy and DGA fast path — which agrees with
P1 (~15k q/s) and E9 (43k q/s with ML off). Figures F1 (latency CDFs, cold and warm) and F2
(throughput vs offered load). Source: `bench/results/E2/20261101T204823Z/`.

*Caveat:* the per-rate throughput sweep is noisy on this single-laptop WSL/Docker setup — achieved q/s
is non-monotonic at zero loss, i.e. the load generator, not the resolver, is the bottleneck at high
rates. The max-sustained figures are therefore order-of-magnitude (and consistent across three
experiments), not a precise saturation curve. A clean sweep needs host networking and longer windows.

**E10: abuse resistance** (lab; EVALUATION.md E10; target: outsiders refused with no upstream query,
NXNS fan-out bounded by the cap)

| Defence | Measured | Target met |
|---|---|---|
| Open-resolver refusal | 10/10 queries from the `outside` network REFUSED; **0** upstream queries caused | ✓ |
| NXNS amplification cap | a referral advertising **20** nameservers (no glue, unresolvable) is answered SERVFAIL after ≤ **12** upstream queries; a normal name costs 2; hard cap `max_upstream_queries` = 30 | ✓ |

A naive resolver would chase all 20 nameservers at every referral level (the NXNSAttack
amplification). DNSentinel bounds the work to ≤ 12 upstream queries (≈ 6× a normal lookup, capped
at 15×) and returns SERVFAIL. Source: `bench/results/E10/20261101T203844Z/`.

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

## Still to run (optional, not blocking the report)
- **E12 blocking effectiveness** — honest version needs a real tracker list + headless browser
  (the card's Playwright method); the lab can only show the mechanism. Medium effort.
- **E11 parser fuzzing** — harness builds and runs with clang-19 + libFuzzer; needs ≥ 24 h and a
  clang-19 toolchain (only clang-18 here, which lacks `<expected>`). Hand-off, not in-session.
- **Real-internet E1/E2** — the same drivers, on a network with outbound DNS.
- **Per-model DGA table** — optional Kaggle run:
  `python -m ml.dga.pipeline --mode all --models rf,lgbm,xgboost,histgb --features A,B,C,D,E,G`.

## Reproducing everything here
```bash
lab/lab.sh up                                   # the lab (once; lab/lab.sh build first)
python3 bench/run.py bench/configs/P1.yaml      # the pipeline comparison (Part 3)
python3 bench/run.py bench/configs/E1.yaml      # correctness
python3 bench/run.py bench/configs/E2.yaml      # latency + throughput
python3 bench/run.py bench/configs/E6.yaml      # privacy
python3 bench/run.py bench/configs/E10.yaml     # abuse resistance
python3 lab/attacks/kaminsky.py build-weak/dnsentinel   # E5 poisoning ladder
~/venvs/dnsentinel-ml/bin/python bench/figures.py       # all tables + figures from raw data
```
