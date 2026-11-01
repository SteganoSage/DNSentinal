# Experiment log

EVALUATION.md §9 rule 1: the targets in EVALUATION.md §6 are frozen by a dated commit before the
final runs. Every change after that, to a target, a method or a workload, is logged here with its
reason. Newest first.

| Date | Experiment | Change | Reason |
|---|---|---|---|
| 2026-11-01 | P1 (new) | Added the full-pipeline comparison: configurations C0 (Unbound) to C6, the same benign and attack traffic under each (`bench/configs/P1.yaml`) | The report needs one end-to-end table showing what each layer adds and costs. It combines E7/E8 in the lab with E9's cost. |
| 2026-11-01 | E1 | Run in the lab (DNSentinel vs Unbound, the same lab root; W3 = Tranco's top 10,000 as the lab serves them), not on a cloud VM against the real root | No outbound DNS on the network used; the real-internet run is kept for later, with the same driver |
| 2026-11-01 | E1 | `collect.tracker.lab` AAAA moved from the hierarchy set to the policy set | It is on the block list: its `::` answer is policy by design, not a disagreement. Found when reviewing the first run's mismatches. |
| 2026-11-01 | W1 | Not collected | Not part of this project's scope any more. Real-traffic false positives (E7, E8) use the tunnel dataset's 39.7 h of Stratosphere browsing; E2's throughput "need" and W2's Zipf exponent become stated assumptions. |
| 2026-11-01 | W2 | Zipf exponent 0.9 (an assumption) | It was to be fitted to W1, which wasn't collected; 0.9 is in the range DNS measurement studies report |
| 2026-11-01 | E2, P1 | CPU cores not pinned | The resolvers run in Docker containers on one laptop. Configurations are interleaved by repetition, so a slow moment affects them all alike. |
| 2026-11-01 | E7 | The DGA classifier's `provider_suffixes` (CloudFront, Azure cloudapp, Fastly: never scored) | On real browsing, 16.7% of scored domains were flagged, 529 of them CloudFront distributions whose labels are random by design. With the list, 0.04%. The model and its threshold are unchanged. |
| 2026-11-01 | E8 | The live analyzer skips popular sites (Tranco top 100k) and CDN-assigned names | The evaluation's allowlisted false-alert figures assumed it. Without it, wildcard DNS under `google.com` and the like drew 191 alerts an hour. |
| 2026-11-01 | E8 | LightGBM shipped, not the random forest | By the pre-registered rules (`ml/tunnel/README.md`), RF and LightGBM tie; the tie-break picks the smaller, faster model |
