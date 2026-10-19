# ML data: sources, licences and limitations

The DGA dataset is not committed: `python -m ml.dga.data --out ml/data` downloads and
generates it into `ml/data/` (git-ignored) from pinned sources, so every build is the same.
`ml/data/dataset_info.json` records what was built. Two small lists the resolver also needs
are committed under `config/`.

## DGA dataset (`ml/dga/data.py`)

| Part | Source | Pinned at | Licence | Used for |
|---|---|---|---|---|
| Benign | [Tranco](https://tranco-list.eu/) list `64VVX` (2026-10-16; CrUX, Farsight, Majestic, Radar, Umbrella over 30 days) | list ID | free for research; cite Le Pochat et al., NDSS 2019 | ranks 1-100k: the resolver's allowlist (`allowlist_top100k.txt`); ranks beyond 100k: benign names |
| Stability | Tranco lists `VQYYN` (2026-04-16) and `8LZGV` (2025-10-16), same configuration | list IDs | as above | a benign name is **stable** if both have it too |
| Generated DGA | [baderj/domain_generation_algorithms](https://github.com/baderj/domain_generation_algorithms): reimplementations of real malware DGAs | commit `0faef45` | GPL-2.0: run as separate programs, never copied here; only their output is kept | 46 families, plus 3 dictionary families (gozi, nymaim2, suppobox) |
| Real DGA | [chrmor/DGA_domains_dataset](https://github.com/chrmor/DGA_domains_dataset): names observed by Netlab 360 | commit `9dcc29e` | free for research; cite Cucchiarelli et al., *Expert Systems with Applications* 170:114551 (2021), doi:10.1016/j.eswa.2020.114551 | families we can't generate (conficker, cryptolocker, emotet, rovnix; matsnu as dictionary) are trained on; the other 20 are the `external` test (`external_netlab.csv`); its benign half is not used |
| Blocklist | abuse.ch [ThreatFox](https://threatfox.abuse.ch/) and [URLhaus](https://urlhaus.abuse.ch/) host files | download time and SHA-256 in `dataset_info.json` (live feeds) | CC0 | E7's blocklist-only baseline; benign names on them are dropped |

Families seeded by date run from 2019-01-01 to 2024-12-31 (weekly, or more often for those
with few names a day), so any later stretch can be held out (`future` mode). Families seeded
by a number run with many random seeds from a fixed generator: the names differ from the
malware's real ones, the algorithm doesn't. The rest give one fixed list each, some small
(ramdo 20, dmsniff 70, reconyc 100, vawtrak 150, darkcracks 192). Every family is capped at
6000 names (`--per-family`). Names are deduplicated across the dataset, a generated name that
is also a Tranco top-million site is dropped, and real names already in the dataset are left
out of the external test.

Built 2026-10-18: 899,903 benign names (460,570 stable), 218,532 DGA names in 50 families,
23,998 dictionary names in 4 families, 266,515 external names.

`ml/dga/dga_domains_full.csv` (chrmor's file, committed earlier) was removed: `data.py`
downloads the same file at the pinned commit.

## Committed lists (`config/`)

| File | Source | Licence |
|---|---|---|
| `public_suffix_list.dat` | [Public Suffix List](https://publicsuffix.org/), `VERSION: 2026-10-16_09-29-46_UTC`, commit `91b4bd8` | MPL-2.0 |
| `english_words.txt` | every word of 3+ letters in [SCOWL](https://github.com/en-wl/wordlist)'s en_US Hunspell dictionary, release `rel-2026.02.25` (SHA-256 in the file); rebuild with `python -m ml.dga.data --words` | SCOWL's permissive licence (notice in the file) |

## Known limitations

- **The benign tail is noisy.** Tranco ranks beyond 100k include random-looking, short-lived
  names (`sajkwjdjawj.com`), some likely malicious: the DNS-based sources see malware traffic
  too. Keeping only names that lasted a year removes most of them, but also new legitimate
  sites; `--benign all` reports the unfiltered tail, and E7's false alerts per day on real
  traffic (W1) is the deployment check.
- **Generated is not observed.** The reimplementations reproduce the algorithms, not which
  names were registered or queried; the `external` mode checks how far results carry over.
- **Free dynamic-DNS providers missing from the PSL.** Some external kraken names are under
  providers the Public Suffix List doesn't list (mooo.com, dynserv.com, yi.org), so the
  provider's label is scored instead of the generated part.
- **The real names are a fixed snapshot** (published 2021-2022). They test names from a
  different source, not names from later dates; that is the `future` mode's question.
- **DGArchive** (Fraunhofer FKIE) is the largest source of real DGA names; access is by
  request (CC BY-NC-SA 3.0) and can be added as another source once granted.
