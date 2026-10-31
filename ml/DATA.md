# ML data: sources, licences and limitations

The datasets are not committed: `python -m ml.dga.data --out ml/data` and `python -m
ml.tunnel.data --out ml/data/tunnel` download and build them (git-ignored) from pinned
sources, so every build is the same; each `dataset_info.json` records what was built. Two
small lists the resolver also needs are committed under `config/`.

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

## Tunnel dataset (`ml/tunnel/data.py`)

Every capture becomes its DNS queries with their answers' rcode and size (`ml/tunnel/pcap.py`),
the events the resolver gives the detector: `events.csv.gz`, one row per query, and
`captures.csv`, one row per capture (its set, tool, record type, tunnel domain, hours, hash).

| Part | Source | Pinned at | Licence | Used for |
|---|---|---|---|---|
| Tunnels | [ggyggy666/DNS-Tunnel-Datasets](https://github.com/ggyggy666/DNS-Tunnel-Datasets), the GraphTunnel paper's data: `tunnel/` (dnscat2, dnspot, iodine, DNS-shell, tuns, in each record type they support), `unkownTunnel/` (cobaltstrike, dns2tcp, ozymandns, tcp-over-dns), `crossEndPoint/` (AndIodine) | commit `e3dccb8`; every file's size and git blob SHA-1 in `ml/tunnel/graphtunnel_files.json`, checked after download | none stated; its README asks to cite the dataset and *GraphTunnel: Robust DNS Tunnel Detection Based on DNS Recursive Resolution Graph* | the `known` tools (trained on), the `unknown` and `android` tools (never trained on in `unknown` mode) |
| More tunnels | [Korving-F/dns-tunnel-dataset](https://github.com/Korving-F/dns-tunnel-dataset): 136 short lab sessions (C2 and file transfer) of iodine (CNAME, MX, NULL, PRIVATE, SRV, TXT x base32, base64, base128, raw), dns2tcp (KEY, TXT) and dnscat2, each through one of four resolvers (BIND 9, CoreDNS, dnsmasq, PowerDNS) | commit `bdc4486`; every archive's size and git blob SHA-1, and each session's settings from its `.metadata`, in `ml/tunnel/korving_files.json` | the DACA framework that made it is MIT (Frank Korving, 2022); cite the repository | iodine and dnscat2 join the `known` tools; dns2tcp stays in `unknown`, as GraphTunnel's does. Captured on the lab resolver: only the client's queries (192.168.0.30) are kept, not the resolver's copies sent upstream |
| Crawl | the same repository's `normal/`: one client resolving Cloudflare's top million domains | as above | as above | benign; mostly single queries per domain |
| Wildcard | the same repository's `wildcard/`: subdomains of wildcard-DNS domains, enumerated | as above | as above | benign, **test only**: false alerts on traffic shaped like a tunnel |
| Browsing | [Stratosphere Lab](https://www.stratosphereips.org/datasets-normal) normal captures CTU-Normal-4 (a home network, DNS only), 20-31 (Windows and Kali machines browsing Alexa/Moz top sites for hours, 2017; full captures, of which only DNS is kept) and 32 (DNS only) | file sizes in `data.py`; SHA-256 in `dataset_info.json` (no published hashes) | free to use citing Garcia, S., *Malware Capture Facility Project*, stratosphereips.org | benign: real people's browsing, the false alerts a day that matter |
| Allowlist | Tranco top 100k of list `64VVX` (as the DGA dataset) | list ID | as Tranco above | false alerts with popular domains skipped, as deployed |
| Yours | `--local DIR`: `DIR/benign/**` and `DIR/tunnel/<tool>/**` captures | your files' SHA-256 in `dataset_info.json` | yours | E8's lab tunnels and W1 |

The subfolders of the GraphTunnel repository hold the same captures again, split into pcapng
parts, and are not used (`tunnel/dns2tcp-key/` is `unkownTunnel/dns2tcp-key.pcap`). Every tunnel
there uses one domain (`ggy666.tk`) and every Korving session another (`example.attack`); no feature
names the domain, so a model can't learn it. Korving's sessions are short (seconds to minutes, file
transfers at full speed): they add many more tunnel sessions and settings, not many windows.

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
- **Tunnels from one lab.** GraphTunnel captured each tool once per record type, from a few
  lab machines; their settings beyond the record type aren't published. Slower tunnels are
  emulated by stretching a capture's clock (the same queries further apart); a tool's own slow
  mode might also poll differently. Our own lab captures (`--local`, E8) are the check.
- **Benign traffic is not ours.** The crawl is a script, not a person; the browsing captures are
  2017 virtual machines visiting top-site lists. E8's false alerts a day on our own devices (W1)
  is the deployment number. CIC-Bell-DNS-EXF-2021 (DNSExfiltrator) is not used: it is
  downloaded through a registration form, which a notebook can't fill in.
- **Upstream bytes are encoded bytes.** "Bytes sent before detection" and T5's capacity count
  the bytes in the names' subdomains: base32 or hex carries 5/8 or 1/2 of that as data.
