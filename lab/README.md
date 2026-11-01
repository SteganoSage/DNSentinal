# The lab: a private mini-internet for the experiments

EVALUATION.md §3 asks for one shared lab that every experiment reuses. This is it: a Docker
Compose network with
- its own DNS hierarchy (root, TLDs, authoritative zones), on real NSD;
- DNSentinel with the slow path running beside it;
- Unbound to compare against;
- clients, an infected host and attackers.

Its networks are `internal`, so nothing in the lab can reach the real internet. Forged
packets and tunnels stay inside.

```bash
lab/lab.sh build            # the images (once; DNSentinel is built from this checkout)
lab/lab.sh up               # start the lab
lab/lab.sh check            # every part answers as it should
lab/lab.sh client dig www.example.lab    # run a command on the client
lab/lab.sh down
```

Needs Docker (on WSL: Docker Desktop with WSL integration on for this distro).

## Who is where

```
            lan 10.53.1.0/24                                  wan 10.53.2.0/24 (the "internet")
  client    .10 ──┐                                   ┌── .10 root      NSD   .
  infected  .20 ──┤  (iodine)                         ├── .11 tld       NSD   lab. test. com. net. info. org.
  infected2 .21 ──┤  (DGA malware)                    ├── .20 auth      NSD   example.lab, bank.lab, 10,000 popular, ...
  infected3 .22 ──┼── .2 DNSentinel ── .2 ────────────┼── .30-.35 quirks Python: slow, lame, no-0x20, NXNS, deep, exfil
                  └── .3 Unbound    ── .3 ────────────┤
  analyzer (no network: the event socket only)       │
                                                      ├── .40 iodined   tunnel.lab   (E8)
  outside 10.53.3.0/24                                ├── .41 dnscat2   dnscat.lab   (delegated; server not built yet)
  outsider  .66 ── .2 DNSentinel                      └── .66 attacker  off-path spoofer (E5)
```

- **DNSentinel** (`lab/config/dnsentinel.yaml`) listens on 53, 853 (DoT), 443 (DoH) and 9153
  (`/metrics`), with the lab's root hints. It answers only `lan`, so `outside` is refused (E10).
  It streams its events to the analyzer over a socket in a shared volume, and writes its query
  log to `lab/results/querylog/`.
- **The analyzer** is `analyzer.live` in enforce mode with the shipped tunnel model and score fusion.
- **Unbound** has the same root hints: the production resolver E1 and E2 compare against.
- **The hierarchy** is crafted so every case of EVALUATION.md §3.1 exists (`lab/hierarchy/`):
  - varied TTLs, CNAME chains of 1-8 hops, a CNAME into another zone;
  - deep delegations with and without glue, empty non-terminals, a TXT large enough for TCP;
  - a lame delegation, a slow server, a server that doesn't preserve letter case;
  - `attacker.lab` with out-of-bailiwick records, and `bank.lab`, the poisoning target;
  - a cloaked tracker, and a DGA command server under `.info`.

**Switching configurations.** The experiments do this through compose variables (`bench/run.py`'s `Lab.recreate`):
- `DNSENTINEL_CONFIG` picks DNSentinel's config file;
- `DNSENTINEL_BIN=dnsentinel-weak` runs the weak-mode binary (E5);
- `ANALYZER_JUDGE` picks the model (`--model models/tunnel`) or the hand-written rules (`""`);
- `ANALYZER_ALERTS` sets where the analyzer's alerts go.

The client (10.53.1.10) is exempt from DNSentinel's per-client rate limit, so load tests measure
the resolver. The infected hosts are limited like anyone else.

## Running an experiment

```bash
python3 bench/run.py bench/configs/E1.yaml       # bench/results/E1/<time>/: raw CSVs, summary.json, metadata.json
python3 bench/run.py bench/configs/P1.yaml       # the full pipeline, configurations C0-C6 (about 2 h)
python3 bench/figures.py                         # bench/tables/ and bench/plots/ from the latest runs
```

## Which experiment uses what

| Experiment | Parts of the lab |
|---|---|
| E1 correctness | client, DNSentinel and Unbound over the whole hierarchy; answers compared |
| E2 latency, E3 cache | client with dnsperf (W2, W3); DNSentinel vs Unbound; `tc netem` link profiles |
| E4 serve-stale | auth stopped mid-run |
| E5 poisoning | attacker (off-path, on `wan`) against `bank.lab`; DNSentinel weak and hardened |
| E6 privacy | captures on `lan` and at the root, TLD and auth: plain vs DoT/DoH, QNAME minimisation on/off |
| E7 DGA | infected host: DGA families' names and their command server; the resolver's classifier and fusion |
| E8 tunnels | infected host: real iodine through DNSentinel; a slow synthetic tunnel (`exfil.lab`); the analyzer's alerts and blocks |
| P1 the full pipeline | everything at once, under configurations C0 (Unbound) to C6 (`bench/experiments/pipeline.py`) |
| E10 abuse | outsider (access control), quirks (NXNS referrals), spoofed floods (RRL) |
| E12 blocking | client: tracker and cloaked names; the block lists |
| E13 rebinding | a rebinding domain (Singularity), DNSentinel's filter |

E9 (ML cost), E11 (fuzzing) and E14 run on the host, without the lab (`bench/`, `tests/fuzz/`).
