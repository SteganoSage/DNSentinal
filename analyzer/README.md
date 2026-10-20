# DNS slow-path analyzer

The tunnel detector currently runs offline against newline-delimited JSON
(JSONL). Each input line must contain:

```json
{"timestamp": 1710000000.0, "client_ip": "192.0.2.10", "qname": "www.example.com", "qtype": "A", "rcode": "NOERROR", "response_size": 82}
```

`client_id` may be used instead of `client_ip`. `timestamp` is Unix time in
seconds, and `response_size` defaults to zero. The detector groups events by
`(client_id, registrable domain)`, maintains a 60-second window, and emits
features every 10 seconds after the first complete window.

Run it from the repository root:

```bash
python -m analyzer.tunnel_analyzer events.jsonl --output tunnel-windows.jsonl
```

The output contains the feature vector and an explainable monitor-only
baseline verdict. A `high` verdict is an alert; it does not block queries.
It also emits `nxdomain_burst` records for each client after a complete
window. By default, a burst requires at least 10 NXDOMAIN responses and an
NXDOMAIN ratio of at least 50%; tune these with
`--nxdomain-min-count` and `--nxdomain-min-ratio`.
The thresholds are intentionally a baseline for synthetic/offline validation,
not a production-trained model. The next step is to collect labelled windows
and compare a supervised model with an Isolation Forest before wiring this
interface to the resolver event bus.

## Tunnel behaviour features

Each completed `(client, registrable-domain, time-window)` contains:

- `query_count` and `query_rate_per_second`: total queries and total queries
  divided by the observed first-to-last query interval.
- `mean_query_name_length` and `max_query_name_length`: lengths of complete
  query names, excluding dots and a trailing root dot.
- `mean_query_label_length` and `max_query_label_length`: lengths of all
  non-empty labels in those names.
- `mean_query_name_entropy`: Shannon entropy over the characters in each
  complete query name, excluding dots.
- `unique_subdomain_count` and `unique_subdomain_ratio`: distinct names below
  the event's registrable domain.
- `nxdomain_ratio`: queries whose matched response has RCODE `NXDOMAIN` (or
  numeric RCODE `3`) divided by the query count.
- `mean_interquery_seconds` and `interquery_variance`: mean and population
  variance of non-negative gaps between chronologically ordered queries.

The JSONL input is expected to contain one normalized query event per line,
with response fields (`rcode`, `response_size`) populated from the response
matched by the resolver using its transaction identity (for example, DNS ID,
client, server, transport, and query name/type). An unmatched query should
retain the default `NOERROR` only if that is the resolver's explicit policy;
otherwise its response status should be represented separately before
calculating response-dependent features.
