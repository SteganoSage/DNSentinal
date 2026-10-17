# ns-3: DNS lookup latency by access link

A small ns-3 simulation of the question behind EVALUATION.md's S1: **what does
encrypting DNS (DoT/DoH) cost on different kinds of access link?**

```bash
sudo apt install ns3 libns3-dev      # once (Ubuntu 24.04 packages ns-3.41)
sim/ns3/run.sh                       # build, run, plot: results in ~/dnsentinel-sim
```

It takes a few seconds and writes `link_profiles.csv` (every lookup),
`summary.txt` (the table below) and `link_profiles.png` (the figure).

## What it simulates

For each link profile from EVALUATION.md §3.4, a client and a server sit at
the two ends of one point-to-point link with that profile's delay, bandwidth
and packet loss:

| Profile | RTT | Loss | Bandwidth |
|---|---|---|---|
| LAN | 1 ms | 0% | 1 Gbps |
| 4G | 60 ms | 1% | 20 Mbps |
| Rural broadband | 80 ms | 0.5% | 4 Mbps |
| Lossy link | 50 ms | 5% | 10 Mbps |
| GEO satellite | 600 ms | 0.5% | 10 Mbps |

The client makes 100 DNS-sized lookups three ways:

- **Plain DNS (UDP):** one query datagram, one answer; resent after 1 s if lost (as a stub resolver does).
- **DoT/DoH, new connection:** a TCP handshake, a TLS 1.3 handshake (ClientHello, then the server's ~2 KB flight with its certificate), then the query.
- **DoT/DoH, reused connection:** the query alone, on a connection already open.

## What it shows

```
profile    transport    median ms     p95 ms
4G         udp               60.1       60.1
4G         tls-reused        60.2       60.2
4G         tls-fresh        181.2      381.2
Lossy      udp               50.2     1050.2
Lossy      tls-reused        50.3      301.5
Satellite  tls-fresh       1802.3     1802.3
```

- A **new** encrypted connection costs **three round trips** (TCP, then TLS, then the query) against one for UDP, so its penalty grows with link delay: +2 ms on a LAN, about +120 ms on 4G, +1.2 s by satellite.
- On a **reused** connection, encrypted DNS costs the same as plain DNS: one round trip. So DNSentinel's DoT/DoH listeners keep connections open (idle timeout, pipelining), and clients should reuse them.
- On a **lossy** link, one lost UDP query costs the stub's whole 1 s retry timer (p95 ≈ 1050 ms), while TCP recovers from a loss in about 200 ms (p95 ≈ 300 ms on a reused connection).

## What it is not

The server is a stand-in that answers with realistic message sizes, not
DNSentinel: this isolates what the **link** does to each transport. The full
S1 (EVALUATION.md §5) runs the real resolver, real clients and the lab
hierarchy behind ns-3 links in emulation mode, and adds Wi-Fi contention and
QNAME minimisation; that needs the lab (EVALUATION.md §3) and comes later.

One modelling note: TCP runs without the timestamp option. With small
requests and answers whose ACKs ride on the next message after idle gaps,
ns-3's timestamp-based RTT samples counted the idle time, and its
retransmission timeout grew to 30–70 s on a 60 ms link. Without timestamps it
samples RTT the classic way. Details are in the comments of `link_profiles.cc`.
