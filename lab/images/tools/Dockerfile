# Everything in the lab that isn't DNSentinel or the analyzer: the hierarchy (NSD), Unbound,
# the quirks server, clients, attackers, the iodine tunnel. One image, a different command each.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        nsd unbound iodine dnsperf dnsutils knot-dnsutils tcpdump iproute2 iputils-ping \
        python3 python3-scapy curl ca-certificates procps netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /dnsentinel
