#!/usr/bin/env bash
# The lab (lab/README.md): build, start, check, use and stop it.
#
#   lab/lab.sh build      the hierarchy, the lab's TLS certificate and the images (once, or after changes)
#   lab/lab.sh up         start everything; then `check`
#   lab/lab.sh check      every part answers as it should (exit status 0 if so)
#   lab/lab.sh client CMD...    run CMD on the client (also: infected, attacker, outsider, any service)
#   lab/lab.sh logs [SERVICE]   follow the logs
#   lab/lab.sh down       stop and remove everything (results in lab/results stay)
set -euo pipefail
lab="$(cd "$(dirname "$0")" && pwd)"
repo="$(dirname "$lab")"
compose=(docker compose -f "$lab/docker-compose.yml")
popular_count="${LAB_POPULAR:-10000}"

build() {
    local tranco="$repo/config/lists/feeds/tranco_top100k.txt"
    if [[ ! -s $tranco ]]; then
        echo "lab: fetching Tranco and the public block lists (config/lists/download_feeds.sh)"
        "$repo/config/lists/download_feeds.sh"
    fi
    python3 "$lab/hierarchy/build.py" --popular "$tranco" --count "$popular_count"
    mkdir -p "$lab/state/certs" "$lab/results/querylog"
    if [[ ! -s $lab/state/certs/server.crt ]]; then
        # the repository's script, run on a copy so the lab's CA stays its own
        cp "$repo/certs/make_certs.sh" "$lab/state/certs/"
        "$lab/state/certs/make_certs.sh" dns.lab dnsentinel.lab 10.53.1.2
    fi
    docker build -t dnsentinel-lab/tools "$lab/images/tools"
    docker build -t dnsentinel-lab/analyzer "$lab/images/analyzer"
    docker build -t dnsentinel-lab/dnsentinel -f "$lab/images/dnsentinel/Dockerfile" "$repo"
}

up() {
    [[ -s $lab/hierarchy/out/root.conf ]] || { echo "lab: run lab/lab.sh build first" >&2; exit 1; }
    mkdir -p "$lab/results/querylog"
    "${compose[@]}" up -d
    echo "lab: up; waiting for auth to load its zones (about a minute with 10,000 popular names)"
    for _ in $(seq 300); do
        if "${compose[@]}" logs auth 2>/dev/null | grep -q "nsd started"; then break; fi
        sleep 1
    done
    "${compose[@]}" restart dnsentinel >/dev/null   # prime again, with every zone there
    echo "lab: waiting for DNSentinel to prime the root"
    for _ in $(seq 60); do
        if "${compose[@]}" logs dnsentinel 2>/dev/null | grep -q "primed the root"; then break; fi
        sleep 0.5
    done
    "${compose[@]}" logs dnsentinel | tail -n 20
}

run_on() {
    local service=$1
    shift
    "${compose[@]}" exec -T "$service" "$@"
}

# One check: description, then the command; passes when the command's output matches the pattern.
pass=0 fail=0
expect() {
    local what=$1 pattern=$2
    shift 2
    local out
    out="$("$@" 2>&1 || true)"
    if grep -Eq -- "$pattern" <<<"$out"; then
        printf '  ok    %s\n' "$what"
        pass=$((pass + 1))
    else
        printf '  FAIL  %s\n        expected /%s/, got: %s\n' "$what" "$pattern" "$(head -c 300 <<<"$out")"
        fail=$((fail + 1))
    fi
}

check() {
    local dig=(run_on client dig +tries=1 +time=5)
    echo "the hierarchy (asked directly, from the wan side):"
    expect "the root refers lab. to the TLD server" "lab\..*NS.*ns\.nic\.lab" run_on attacker dig +norec @10.53.2.10 www.example.lab
    expect "the TLD refers example.lab to auth" "example\.lab\..*NS" run_on attacker dig +norec @10.53.2.11 www.example.lab
    expect "auth answers www.example.lab" "192\.0\.2\.1" run_on attacker dig +norec +short @10.53.2.20 www.example.lab
    expect "quirks serves the deep chain's last level" "192\.0\.2\.110" run_on attacker dig +norec +short @10.53.2.35 www.e.d.c.b.a.deep.lab
    echo "DNSentinel (10.53.1.2):"
    expect "resolves from the root" "192\.0\.2\.1" "${dig[@]}" +short @10.53.1.2 www.example.lab
    expect "follows an 8-hop CNAME chain" "192\.0\.2\.1" "${dig[@]}" +short @10.53.1.2 chain8.example.lab
    expect "follows the deep delegations" "192\.0\.2\.110" "${dig[@]}" +short @10.53.1.2 www.e.d.c.b.a.deep.lab
    expect "resolves a name server without glue" "192\.0\.2\.101" "${dig[@]}" +short @10.53.1.2 www.noglue.lab
    expect "survives the lame delegation" "192\.0\.2\.90" "${dig[@]}" +short @10.53.1.2 www.lame.lab
    expect "falls back for the server that drops 0x20" "192\.0\.2\.121" "${dig[@]}" +short @10.53.1.2 www.nocase.lab
    expect "keeps attacker.lab's records out of bank.lab" "192\.0\.2\.80" sh -c "$(printf '%q ' "${compose[@]}") exec -T client dig +short @10.53.1.2 www.attacker.lab >/dev/null; $(printf '%q ' "${compose[@]}") exec -T client dig +short @10.53.1.2 www.bank.lab"
    expect "gets the big TXT over TCP" "status: NOERROR" "${dig[@]}" @10.53.1.2 big.example.lab TXT
    expect "blocks an ad host" "0\.0\.0\.0" "${dig[@]}" +short @10.53.1.2 ads.example.lab
    expect "blocks a cloaked tracker" "0\.0\.0\.0" "${dig[@]}" +short @10.53.1.2 metrics.cloaked.lab
    expect "strips a private address (rebinding)" "status: NXDOMAIN" "${dig[@]}" @10.53.1.2 router.example.lab
    expect "resolves a popular name (W3)" "198\.18\." "${dig[@]}" +short @10.53.1.2 "www.$(sed -n 1p "$lab/hierarchy/out/popular.txt" | cut -d, -f2)"
    expect "answers over DoT" "192\.0\.2\.1" run_on client kdig +short +tls-ca=/dnsentinel/lab/state/certs/ca.crt +tls-hostname=dns.lab @10.53.1.2 www.example.lab
    # over HTTP/1.1: DNSentinel's DoH doesn't speak HTTP/2, which kdig requires
    expect "answers over DoH (HTTP/1.1)" "192\.0\.2\.1" run_on client python3 lab/tools/dnsq.py --doh --ca lab/state/certs/ca.crt --hostname dns.lab 10.53.1.2 www.example.lab
    expect "refuses the outside network" "status: REFUSED" run_on outsider dig +tries=1 +time=5 @10.53.3.2 www.example.lab
    expect "serves /metrics" "dnsentinel_queries_total" run_on client curl -s http://10.53.1.2:9153/metrics
    expect "writes the query log" "\"qname\":\"www.example.lab\"" sh -c "sleep 1; cat '$lab'/results/querylog/queries-*.jsonl"
    echo "the slow path:"
    expect "the analyzer is connected" "connected to /run/dnsentinel/events.sock" "${compose[@]}" logs analyzer
    echo "Unbound (10.53.1.3):"
    expect "resolves from the same root" "192\.0\.2\.1" "${dig[@]}" +short @10.53.1.3 www.example.lab
    echo
    echo "$pass passed, $fail failed"
    [[ $fail -eq 0 ]]
}

case "${1:-}" in
    build) build ;;
    up) up ;;
    check) check ;;
    down) "${compose[@]}" down -v --remove-orphans ;;
    logs) shift; "${compose[@]}" logs -f "$@" ;;
    ps) "${compose[@]}" ps ;;
    root|tld|auth|quirks|iodined|dnsentinel|analyzer|unbound|client|infected|infected2|infected3|attacker|outsider)
        service=$1; shift; "${compose[@]}" exec "$service" "$@" ;;
    *) sed -n '2,10p' "$0"; exit 2 ;;
esac
