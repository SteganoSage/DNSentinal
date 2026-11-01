# Experimental setup

How every experiment was run: the lab, what each component is and the role it played, the workloads,
and how to reproduce it. Read alongside `docs/results.md` (the numbers) and `docs/experiment-log.md`
(every deviation from the plan, with reasons).

## 1. The one-line summary

**DNSentinel and the baseline resolver (Unbound) are the real software; the "internet" they resolve
against is a private, fully controlled one we built.** Nothing in the lab touches the real internet —
its Docker networks are `internal`, with no route out. This is deliberate and is standard practice for
DNS-security evaluation (EVALUATION.md §3.1): the real internet changes minute to minute, and you
cannot make the real root servers lie to test cache poisoning, run a lame delegation on demand, or
guarantee a CNAME-cloaked tracker exists. A controlled hierarchy makes every tricky case present and
every measurement repeatable. The resolver logic under test — recursion, caching, 0x20, bailiwick
checking, QNAME minimisation, the ML fast and slow paths — is real and does not care whether the root
is IANA's or ours.

One experiment, **real-internet E1/E2** (prepared, `lab/realnet.sh`), is the exception: the same real
DNSentinel and Unbound recurse into the **real IANA root**. It is the only part that needs outbound DNS.

## 2. The machine

- 13th Gen Intel Core i5-13500H (16 logical cores), Linux 6.18 (WSL2), Docker Engine 29.5.
- Everything runs in Docker containers. CPU cores are **not** pinned (a shared laptop); experiments
  that compare configurations interleave them by repetition, so a slow moment of the machine hits all
  configurations alike rather than biasing one.

## 3. The lab (`lab/`, `lab/README.md`)

A Docker Compose network — a private mini-internet. Three isolated networks: `lan` (10.53.1.0/24,
the clients), `wan` (10.53.2.0/24, the "internet" / authoritative side), `outside` (10.53.3.0/24, a
client network DNSentinel is *not* configured to serve). Bring it up with `lab/lab.sh up`; 23 built-in
checks (`lab/lab.sh check`) confirm every part answers correctly before any experiment.

### 3.1 What each component is, and the role it played

| Component | Address | Real or ours | Software | Role in the experiments |
|---|---|---|---|---|
| **DNSentinel** | 10.53.1.2 / 10.53.2.2 | **Real — the system under test** | our binary, Release build, commit `e5686c9`, from this repo | The recursive resolver being evaluated. Listens UDP/TCP 53, DoT 853, DoH 443, and `/metrics` 9153. Full stack: access control, rate limiting, block lists, policy, the DGA classifier (fast path) and the event stream to the slow path. |
| **Unbound** | 10.53.1.3 / 10.53.2.3 | **Real — the baseline** | Unbound 1.19.2 | A production recursive resolver, the thing we compare correctness and latency against (E1, E2). Same root hints as DNSentinel, so the comparison is fair. |
| **Analyzer** | (socket only) | **Real — part of the system** | `python -m analyzer.live` with the shipped LightGBM tunnel model + score fusion | The slow path. Reads DNSentinel's event stream over a Unix socket, detects tunnels and DGA command servers, and sends back time-limited block rules. |
| **Root / TLD / authoritative** | 10.53.2.10 / .11 / .20 | **Ours (the fake internet)** | NSD 4.8.0 serving zones we generate | The DNS hierarchy DNSentinel recurses into: our own root `.`, our TLDs (`lab test com net org info`), and ~10,024 authoritative zones (`example.lab`, `bank.lab`, `cloaked.lab`, and 10,000 fake "popular" domains built from Tranco's names). |
| **Quirks server** | 10.53.2.30–.35 | **Ours** | a small Python authoritative server (`lab/servers/quirks.py`) | The misbehaviour NSD will not do: a server that answers 800 ms late (server selection), one that drops 0x20 case (fallback), one returning out-of-bailiwick records that try to hijack `bank.lab` (poisoning, E5 Part C), an NXNS server that refers to 20 unresolvable nameservers per query (amplification, E10), a 5-level deep delegation chain, and a TXT "exfil" endpoint for the synthetic tunnel. |
| **iodined** | 10.53.2.40 | **Real attack tool** | iodine (IP-over-DNS) server | The far end of a **real** DNS tunnel. The infected client runs the iodine client through DNSentinel; a byte counter at this end measures what actually gets exfiltrated. |
| **Clients / infected / attacker / outsider** | 10.53.1.10/.20/.21/.22, 10.53.2.66, 10.53.3.66 | **Real tools** | `dig`, `dnsperf`, iodine, a raw-socket Kaminsky flooder, our Python drivers | The traffic sources: benign load, DGA malware, tunnels, the off-path poisoner, and a client outside the allowed subnets. |

### 3.2 The hierarchy's crafted cases (`lab/hierarchy/build.py`)

One generator writes all the zones so the tricky cases cannot drift apart: varied TTLs (1 s to 1 day),
CNAME chains of 1–8 hops, a CNAME into another zone, five-level and glue-less delegations, empty
non-terminals, a TXT record large enough to force TCP, a lame delegation, `attacker.lab` with
out-of-bailiwick records, `bank.lab` (the poisoning target), a CNAME-cloaked tracker, and the DGA
families' command servers (one resolving name per family, the rest absent).

## 4. The harness (`bench/run.py`)

Every experiment is one command: `python3 bench/run.py bench/configs/<EXP>.yaml`. For each run the
harness makes a timestamped folder under `bench/results/<EXP>/` holding the raw CSVs, `summary.json`
(the reduced numbers), and `metadata.json` — the git commit (and whether the tree was dirty), a
SHA-256 of every config used, the Docker image IDs, kernel, CPU, the random seed, and the parameters.
`bench/figures.py` regenerates every table (`bench/tables/`) and figure (`bench/plots/`) from that raw
data; nothing is edited by hand (EVALUATION.md §9 rule 10). Configurations are switched through Compose
environment variables (`DNSENTINEL_CONFIG`, `DNSENTINEL_BIN` for the weak-mode binary, `ANALYZER_JUDGE`
for model-vs-rules), so the same lab serves every configuration.

## 5. Workloads

| ID | What | Real or ours | Used by |
|---|---|---|---|
| **W2** | Synthetic benign trace: Zipf-popular names (exponent 0.9, an assumption) over the fake popular zones, Poisson arrivals | ours (generated, `lab/traffic_gen/w2.py`) | E2, P1 benign load |
| **W3** | Tranco's top 10,000 names, as the lab serves them (real names, fake answers) | names real, answers ours | E1, E2 |
| **DGA malware** | 9 real DGA families' names from the Netlab 360 dataset (40 generated names each) plus a command server that resolves | **names real**, command server ours | P1, E7 |
| **Tunnels** | a **real iodine** tunnel carrying random bytes, and a synthetic slow tunnel (0.2 TXT q/s) | iodine real, slow tunnel ours | P1, E8 |
| **Attack (poisoning)** | a real off-path forged-referral flood against `bank.lab` | real | E5 |

**W1 (a 7-day capture of our own devices) was not collected** — out of scope. Real-traffic
false-positive rates instead come from the tunnel dataset's 39.7 h of real browsing and a 24 h crawl
of Cloudflare's top 1M (used when the DGA/tunnel models were evaluated). This is logged in
`docs/experiment-log.md`.

## 6. Per-experiment setup

- **E1 correctness** (`bench/experiments/e1.py`): DNSentinel and Unbound, both cold, resolve the same
  names at the same instant; answers compared by a fixed rule (same RCODE, and same final CNAME target
  or overlapping address sets). Every mismatch is re-queried and classed transient/persistent.
- **E2 latency & throughput** (`bench/experiments/e2.py`): per-query latency cold (empty cache, walks
  the hierarchy) and warm (cache hits), then a `dnsperf` load sweep for max sustained throughput.
- **E6 privacy** (`bench/experiments/e6.py`): `tcpdump` captures at three observer positions (the
  client's link, the root, the TLD); the query names are read back out with the project's own pcap
  parser. Random marker labels make a captured name traceable to one query. Tests plain vs DoT vs DoH,
  and QNAME minimisation on vs off.
- **E10 abuse** (`bench/experiments/e10.py`): an outsider (on the `outside` network) is refused; a
  fresh name under the NXNS server measures how many upstream queries a 20-way malicious referral costs.
- **E5 poisoning** (`lab/attacks/kaminsky.py`): a real off-path forged-packet race against our own
  resolver, weak-mode binary (8-bit ID, fixed port) vs hardened (16-bit ID, random port). Model A1
  (`bench/drivers/a1_model.py`) is the analytical prediction overlaid on the measured point.
- **P1 the full pipeline** (`bench/experiments/pipeline.py`): all of the above traffic at once, through
  seven configurations C0 (Unbound) → C6 (everything), 3 interleaved repetitions, 240 s each.
- **S1** (`sim/ns3/`): an ns-3 simulation of encrypted-DNS cost per access-link type — a stand-in
  server, so the link, not the resolver, is what is measured.

## 7. Honesty and limitations (state these in the report)

- One laptop, Docker, no CPU pinning; absolute latencies are lab figures, not datacentre numbers.
- The fake hierarchy proves *logic*, not real-internet behaviour; real-internet E1/E2 covers that gap.
- The throughput sweep is noisy on WSL/Docker (the load generator saturates before the resolver), so
  max-throughput figures are order-of-magnitude and consistent across three experiments, not a precise
  curve.
- W2's Zipf exponent and the absence of W1 are assumptions, logged in `docs/experiment-log.md`.
- P1 uses a 9-family sample of the DGA dataset's 54 families and a synthetic benign load.

## 8. Reproducing it

```bash
lab/lab.sh build && lab/lab.sh up && lab/lab.sh check     # the lab (needs Docker)
python3 bench/run.py bench/configs/P1.yaml                # the pipeline comparison
python3 bench/run.py bench/configs/E1.yaml                # correctness
python3 bench/run.py bench/configs/E2.yaml                # latency + throughput
python3 bench/run.py bench/configs/E6.yaml                # privacy
python3 bench/run.py bench/configs/E10.yaml               # abuse resistance
python3 lab/attacks/kaminsky.py build-weak/dnsentinel     # E5 poisoning ladder
~/venvs/dnsentinel-ml/bin/python bench/figures.py         # all tables + figures from raw data
lab/realnet.sh up && lab/realnet.sh e1 && lab/realnet.sh e2   # real-internet (needs outbound DNS)
```
