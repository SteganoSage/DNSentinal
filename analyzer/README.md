# DNS slow-path analyzer

The tunnel detector (README §7.8.3) and the NXDOMAIN-burst signal (§7.8.4), run live on the
resolver's event stream (`analyzer.live`, below), or offline over a file of events
(`analyzer.tunnel_analyzer`). Both judge the same windows the tunnel model was trained on.

## Live, against the resolver

The resolver publishes every answered query on a Unix socket (`telemetry.events` in
`config/dnsentinel.yaml`, the event bus of README §6.2) and takes commands on the same socket.
`analyzer.live` is the slow path that reads it:

```bash
build/dnsentinel -c config/dnsentinel.yaml                                  # the resolver
python -m analyzer.live                                                     # monitor: alerts only
python -m analyzer.live --model models/tunnel --enforce                      # high risk becomes block rules
```

Each event is one JSON line, in the form the tunnel model was trained on (names in the
resolver's escaped text form, types and rcodes as mnemonics, the answer's size in bytes):

```json
{"type":"query","timestamp":1730400000.123456,"client":"192.168.1.23","transport":"udp","qname":"x.tunnel.example","qtype":"TXT","rcode":"NOERROR","answers":1,"response_size":250,"latency_us":900,"action":"answer","dga":0.03}
```

`action` is what decided the answer: `answer`, `block` (a list), `cname_block`, `dynamic_rule`,
`dga` (enforce mode), `refused`, `rate_limited`, `rejected` or `rebinding`; `rule` names the rule
behind a block. Events wait in a buffer per reader: a reader that falls 4 MB behind loses events
(and is then sent `{"type":"dropped","count":N}`) rather than slowing an answer. Nothing is
built when nobody is reading.

**Score fusion** (`analyzer/fusion.py`, README §7.8.5) turns the signals into one risk per client and
registrable domain. Each signal already has its own threshold, set for a false-positive rate, so
they are not averaged: an average would dilute one certain signal. Two cases are **high**:

- **A tunnel:** the model's consecutive `high` windows (`"alert": "tunnel"`).
- **DGA malware's command server:** a domain the resolver's DGA classifier flagged, which
  *resolved*, while its client was in an NXDOMAIN burst over the same 60 s
  (`"alert": "dga_c2"`). Of the many generated names malware tries, most fail; the one that
  answers is the live server.

  This works with `ml.dga.mode: monitor` too: the resolver lets flagged names through,
  and fusion blocks just the server, for just that client. It needs the resolver built with ML,
  since the `dga` score comes from the events.

Each alert carries the risk and the signals behind it: `"risk": {"level": "high", "kind": "dga_c2",
"reasons": [...], "signals": {"tunnel_alert": false, "dga": 0.997, "burst": true, "resolved": true}}`.
NXDOMAIN bursts alone are reported client-wide (`"alert": "nxdomain_burst"`, never blocked).
Every DGA-flagged name is already reported by the resolver (its log, and the event's `dga`).
Rules that were measured and left out are listed in `ml/tunnel/README.md`, "Score fusion".

In enforce mode a high risk becomes a **dynamic
rule** (README §7.6.6): that domain and everything below it, for that client only, answered
NXDOMAIN for `--rule-ttl` seconds (1 h), renewed while the alerts go on and left to expire when
they stop. The rules live in the resolver's own table, checked before the block lists; an
allowlisted name outranks them, and they never touch the lists, so a wrong verdict undoes
itself. The commands, one JSON object per line, each answered with one line:

| Command | Reply |
|---|---|
| `{"op":"add_rule","domain":"tunnel.example","client":"192.168.1.23","ttl":3600,"reason":"tunnel","score":0.97,"source":"analyzer.live"}` | `{"type":"reply","op":"add_rule","ok":true,"id":7,"ttl":3600,"renewed":false}` |
| `{"op":"remove_rule","id":7}` | `{"type":"reply","op":"remove_rule","ok":true}` |
| `{"op":"list_rules"}` | `{"type":"reply","op":"list_rules","ok":true,"rules":[{"id":7,...,"hits":12}]}` |
| `{"op":"ping"}` | `{"type":"reply","op":"ping","ok":true}` |

Without `client` a rule applies to everyone. Whoever can connect can block names, so the socket
is mode 0600 (the resolver's user only), in a directory made 0700. The resolver logs every rule
added, renewed and expired, and sums them up at exit.

## Offline, over a file

`analyzer.tunnel_analyzer` reads newline-delimited JSON (JSONL) events, one per query (the
live stream's lines work as they are). Each line contains:

```json
{"timestamp": 1710000000.0, "client_ip": "192.0.2.10", "qname": "www.example.com", "qtype": "A", "rcode": "NOERROR", "response_size": 82}
```

`client_id` may be used instead of `client_ip`. `timestamp` is Unix time in seconds; `qname` is
in the resolver's text form (lower case, `\DDD` and `\.` escapes); `rcode` and `response_size`
come from the answer to that query (`response_size` defaults to zero; rcode `NONE` marks a
captured query whose answer wasn't captured).

```bash
python -m analyzer.tunnel_analyzer events.jsonl --output tunnel-windows.jsonl
python -m analyzer.tunnel_analyzer events.jsonl --model ml/runs/tunnel/main/w60-fVNR/final
```

The tunnel detector groups events by `(client, registrable domain)` and judges each key on its
last 60 s of queries, at window ends every 10 s, whenever the key had a new query since it was
last judged; its first verdict comes at most 10 s after its first query. With `--model` the
trained model decides (`high` above its threshold) and the hand-written rules' reasons explain
the verdict; without it the rules judge alone (`high` from 0.75). `"alert": true` marks a window
that completes two consecutive `high` windows of the client and domain (`--alert-after`, or the
model's own setting): tunnels last minutes, a CDN's burst of lookups mostly one window. Either way
it only reports: it does not block. Training (`ml/tunnel`) feeds captured queries through the same
`SlidingWindowDetector`, so the model is trained on exactly these windows.

`nxdomain_burst` records are emitted per client after each complete window. By default, a burst
requires at least 10 NXDOMAIN responses and an NXDOMAIN ratio of at least 50%; tune these with
`--nxdomain-min-count` and `--nxdomain-min-ratio`.

## Tunnel features

Per `(client, registrable domain, window)`, in three groups (`FEATURE_GROUPS`); lengths and
characters are those of the wire labels, decoded from the escaped text:

- **V, volume and timing:** `query_count`, `active_seconds` (first to last query),
  `mean_interval` and `interval_cv` (the gaps' standard deviation over their mean).
- **N, the names below the registrable domain:** `unique_subdomain_count` and `_ratio`,
  `mean`/`max_subdomain_length`, `mean`/`max_label_length`, `mean_subdomain_labels`,
  `mean_subdomain_entropy`, `pooled_entropy` (all the window's subdomain bytes together),
  `distinct_characters`, `digit_ratio`, `unusual_character_ratio` (bytes outside `a-z 0-9 - _`).
- **R, record types and responses:** `data_type_ratio` (types other than A, AAAA, HTTPS, SVCB,
  PTR, SOA, NS, DS, DNSKEY, CAA), `mean`/`max_response_size` (answered queries only),
  `nxdomain_ratio`.
- **D, the data carried:** `unique_subdomain_bytes` (the distinct subdomains' bytes: a repeat
  counted once), `long_label_ratio` (labels of 32 bytes or more), `hex_ratio` (bytes in 0-9 a-f),
  `length_cv` (how much the subdomain lengths vary).

`ml/tunnel/README.md` has the data, training and results.
