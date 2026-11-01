#!/usr/bin/env bash
# Real-internet E1/E2: DNSentinel vs Unbound resolving from the real root. NEEDS OUTBOUND DNS.
#
#   lab/realnet.sh up        start both resolvers (waits for DNSentinel to prime the real root)
#   lab/realnet.sh e1 [N]    correctness: N real Tranco names (default 2000) x {A,AAAA}, both resolvers
#   lab/realnet.sh e2 [N]    latency: N real names (default 1500) cold then warm, each resolver
#   lab/realnet.sh down
set -euo pipefail
lab="$(cd "$(dirname "$0")" && pwd)"
repo="$(dirname "$lab")"
C=(docker compose -f "$lab/realnet.yml")
stamp() { date -u +%Y%m%dT%H%M%SZ; }
ip_of() { "${C[@]}" exec -T "$1" sh -c "hostname -i" | awk '{print $1}'; }

case "${1:-}" in
  up)
    "${C[@]}" up -d
    echo "realnet: waiting for DNSentinel to prime the REAL root (needs outbound DNS)"
    ok=0
    for _ in $(seq 40); do
      if "${C[@]}" logs dnsentinel 2>/dev/null | grep -q "primed the root"; then ok=1; break; fi
      if "${C[@]}" logs dnsentinel 2>/dev/null | grep -q "priming failed"; then break; fi
      sleep 1
    done
    "${C[@]}" logs dnsentinel 2>&1 | grep -E "primed|priming failed|listening" | tail -2
    [ $ok = 1 ] && echo "realnet: ready" || { echo "realnet: NO outbound DNS — switch network, then 'lab/realnet.sh up' again" >&2; exit 1; }
    ;;
  e1)
    n="${2:-2000}"; dt=$(ls "$repo"/config/lists/feeds/tranco_top100k.txt)
    out="$repo/bench/results/E1-realnet/$(stamp)"; mkdir -p "$out"
    awk -F, "NR<=$n {print \$2\" A real\"; print \$2\" AAAA real\"}" "$dt" > "$out/names.txt"
    de=$(ip_of dnsentinel); ub=$(ip_of unbound)
    echo "realnet E1: $(wc -l < "$out/names.txt") queries, DNSentinel $de vs Unbound $ub"
    "${C[@]}" exec -T client python3 /dnsentinel/bench/drivers/e1_compare.py \
      --names "/bench-results/E1-realnet/$(basename "$out")/names.txt" \
      --out "/bench-results/E1-realnet/$(basename "$out")/e1.csv" \
      --test "$de" --baseline "$ub" --rate 80 | tee "$out/summary.json"
    echo "realnet: $out"
    ;;
  e2)
    n="${2:-1500}"; dt=$(ls "$repo"/config/lists/feeds/tranco_top100k.txt)
    out="$repo/bench/results/E2-realnet/$(stamp)"; mkdir -p "$out"
    awk -F, "NR<=$n {print \$2\" A\"}" "$dt" > "$out/names.txt"
    inside="/bench-results/E2-realnet/$(basename "$out")"
    for r in dnsentinel unbound; do
      ip=$(ip_of "$r")
      echo "realnet E2 $r ($ip): cold then warm over $n names"
      "${C[@]}" exec -T client python3 /dnsentinel/bench/drivers/latency.py --server "$ip" \
        --names "$inside/names.txt" --rate 60 --out "$inside/$r-cold.csv"
      "${C[@]}" exec -T client python3 /dnsentinel/bench/drivers/latency.py --server "$ip" \
        --names "$inside/names.txt" --rate 150 --out "$inside/$r-warm.csv"
    done
    "$repo/lab/realnet_e2_summary.py" "$out"
    echo "realnet: $out"
    ;;
  down) "${C[@]}" down -v --remove-orphans ;;
  *) sed -n '2,8p' "$0"; exit 2 ;;
esac
