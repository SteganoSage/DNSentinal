# DNS slow-path analyzer

The tunnel detector (README §7.8.3) and the NXDOMAIN-burst signal (§7.8.4) run on
newline-delimited JSON (JSONL) events, one per query. Each line contains:

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
the verdict; without it the rules judge alone (`high` from 0.75). Either way it only reports: it
does not block. Training (`ml/tunnel`) feeds captured queries through the same
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

`ml/tunnel/README.md` has the data, training and results.
