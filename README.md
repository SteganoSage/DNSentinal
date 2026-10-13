# DNSentinel — A Secure, Private, Self-Defending DNS Gateway

> A recursive DNS resolver built from scratch that blocks ads and trackers, resists cache poisoning, encrypts DNS for clients, and uses machine learning to catch malware domains and data exfiltration that no blocklist knows about yet.

*Working name. Computer Networks course project, Semester 5.*

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [DNS Primer: What You Must Understand First](#2-dns-primer-what-you-must-understand-first)
3. [Problem Statement](#3-problem-statement)
4. [Goals and Non-Goals](#4-goals-and-non-goals)
5. [Threat Model](#5-threat-model)
6. [Solution Overview](#6-solution-overview)
7. [Detailed Design](#7-detailed-design)
   - 7.1 [Wire Format Parser and Builder](#71-wire-format-parser-and-builder)
   - 7.2 [Transport Layer: UDP, TCP, EDNS0, DoT, DoH](#72-transport-layer-udp-tcp-edns0-dot-doh)
   - 7.3 [Iterative Recursive Resolver](#73-iterative-recursive-resolver)
   - 7.4 [Cache](#74-cache)
   - 7.5 [Anti-Spoofing and Cache Poisoning Defence](#75-anti-spoofing-and-cache-poisoning-defence)
   - 7.6 [Policy Engine](#76-policy-engine)
   - 7.7 [Privacy: QNAME Minimisation and Encrypted DNS](#77-privacy-qname-minimisation-and-encrypted-dns)
   - 7.8 [ML Subsystem](#78-ml-subsystem)
   - 7.9 [DNSSEC Validation (Stretch Goal)](#79-dnssec-validation-stretch-goal)
   - 7.10 [Observability and Dashboard](#710-observability-and-dashboard)
8. [The Life of a Query (End-to-End Walkthrough)](#8-the-life-of-a-query-end-to-end-walkthrough)
9. [Technology Stack and Repository Layout](#9-technology-stack-and-repository-layout)
10. [Testbed and Attack Lab](#10-testbed-and-attack-lab)
11. [Evaluation Plan](#11-evaluation-plan)
12. [Design Decisions: The Complete Defence](#12-design-decisions-the-complete-defence)
13. [Limitations and Honest Trade-offs](#13-limitations-and-honest-trade-offs)
14. [Project Plan: Team, Timeline, Milestones](#14-project-plan-team-timeline-milestones)
15. [Viva Preparation: Questions We Expect](#15-viva-preparation-questions-we-expect)
16. [Getting Started (Planned Interface)](#16-getting-started-planned-interface)
17. [Glossary](#17-glossary)
18. [References](#18-references)

---

## 1. Executive Summary

Every connection a device makes starts with a DNS lookup. That makes DNS the best place to observe and control a network, and also one of the most abused protocols on the internet:

- **Ads and trackers** are served from known domains that every device resolves.
- **Malware** reaches its command-and-control (C2) servers through algorithmically generated domains that change daily, so blocklists are always behind.
- **Attackers exfiltrate data** by hiding it inside DNS queries, because DNS is almost never blocked by firewalls.
- **Resolvers can be poisoned** with forged answers that silently redirect users to attacker-controlled servers.
- **Plain DNS is unencrypted.** Anyone on the path (Wi-Fi operator, ISP) sees every domain you visit, and the resolver leaks your full query to every server it contacts.

**DNSentinel** is a single system that sits between the devices on a network and the internet, and addresses all of these problems:

| Layer | What it does |
|---|---|
| **Protocol core** | A recursive resolver written from scratch: its own packet parser, iterative resolution from the root servers, caching, UDP/TCP/EDNS0 |
| **Security** | Blocklists, CNAME-cloaking detection, cache-poisoning hardening (TXID + port randomisation, 0x20 encoding, bailiwick checks), DNS rebinding protection, response rate limiting |
| **Privacy** | DNS-over-TLS and DNS-over-HTTPS for clients, QNAME minimisation towards upstream servers |
| **ML** | A DGA (malware domain) classifier, a DNS tunnelling detector, and an NXDOMAIN-burst signal, fused into one risk score. *Optional, if time allows:* ML tracker discovery, a look-alike (phishing) domain detector, and learned prefetching |
| **Observability** | Per-client query logs, metrics, and a dashboard that explains every block and alert |

The project is evaluated experimentally, and every claim is checked against evidence at up to four levels: **analytical models** (MATLAB/Python), **network simulation** (ns-3 in emulation mode), **emulated labs** (Mininet/namespaces) and **real-network measurement**. Experiments cover correctness and latency against a production resolver, cache effectiveness against caching theory, resistance to a real poisoning attack against a probability model, the cost of privacy features across simulated link types, and ML precision, recall, false-positive rate and added latency. The full plan, including the report structure, is in **[EVALUATION.md](EVALUATION.md)**.

**Why this project:** every feature maps to core Computer Networks theory (application-layer protocols, UDP vs TCP, caching, hierarchical naming, TLS, security), and because we implement the protocol ourselves rather than calling a library, we understand every byte that goes over the wire.

---

## 2. DNS Primer: What You Must Understand First

This section is the minimum theory every team member must know before touching code.

### 2.1 The namespace is a tree

```
                         . (root)
          ┌──────────────┼───────────────┐
         com            org              in
      ┌───┴───┐          │           ┌───┴───┐
   google  example    wikipedia     co      ac
                                     │
                                  example
```

A domain like `www.example.co.in.` is read right to left: root → `in` → `co` → `example` → `www`. Each level is a **label** (max 63 bytes); a full name is at most 255 bytes on the wire.

Authority is delegated down the tree. The root servers do not know the IP of `www.example.com`. They only know who is responsible for `com`. The `com` servers only know who is responsible for `example.com`. That server finally knows the answer.

### 2.2 The four roles

| Role | Job | Example |
|---|---|---|
| **Stub resolver** | Library on the device (`getaddrinfo`). Asks one server and waits. | Your laptop's OS |
| **Recursive resolver** | Does the full walk down the tree on behalf of stubs, caches results. | **DNSentinel**, Unbound, 1.1.1.1 |
| **Authoritative server** | Holds the actual records for a zone. Only answers for its zone. | `a.gtld-servers.net` for `com` |
| **Forwarder** | Passes queries to another recursive resolver instead of walking the tree. | A home router, default Pi-hole |

DNSentinel is a **recursive resolver**, not just a forwarder. That distinction is central to the project (defended in §12).

### 2.3 Iterative resolution

When a stub asks for `www.example.com A`, a recursive resolver with an empty cache does:

```
Resolver → root server:        "www.example.com A?"
root     → Resolver:           "Don't know. Ask com: a.gtld-servers.net (192.5.6.30)"   ← referral
Resolver → a.gtld-servers.net: "www.example.com A?"
com      → Resolver:           "Don't know. Ask example.com: ns1.example.com (…)"       ← referral
Resolver → ns1.example.com:    "www.example.com A?"
example  → Resolver:           "www.example.com A 93.184.215.14, TTL 3600"             ← answer
Resolver → stub:               the answer (and caches everything it learned)
```

A **referral** is a response with no answer, an NS record set in the Authority section, and (usually) the IP addresses of those name servers in the Additional section. Those IPs are called **glue records**.

### 2.4 Resource records you will handle

| Type | Code | Meaning |
|---|---|---|
| A | 1 | IPv4 address |
| NS | 2 | Name server for a zone |
| CNAME | 5 | Alias: "this name is really that name" |
| SOA | 6 | Start of authority: zone metadata, used for negative caching |
| PTR | 12 | Reverse lookup |
| MX | 15 | Mail server |
| TXT | 16 | Arbitrary text (SPF, verification, and abused by tunnels) |
| AAAA | 28 | IPv6 address |
| OPT | 41 | EDNS0 pseudo-record (not real data) |
| DS, RRSIG, NSEC, DNSKEY | 43, 46, 47, 48 | DNSSEC |

Every record carries a **TTL**, the number of seconds it may be cached.

### 2.5 The message format (RFC 1035 §4)

Every DNS message, query or response, has the same shape:

```
+---------------------+
|        Header       |  12 bytes, fixed
+---------------------+
|       Question      |  what is being asked
+---------------------+
|        Answer       |  RRs answering the question
+---------------------+
|      Authority      |  RRs pointing to authoritative servers (referrals, SOA)
+---------------------+
|      Additional     |  RRs that help (glue IPs, OPT)
+---------------------+
```

Header layout:

```
 0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      ID                       |   16-bit transaction ID
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    QDCOUNT                    |
|                    ANCOUNT                    |
|                    NSCOUNT                    |
|                    ARCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

- **QR** 0 = query, 1 = response
- **AA** authoritative answer
- **TC** truncated (response did not fit, retry over TCP)
- **RD** recursion desired (set by stubs)
- **RA** recursion available (set by recursive resolvers)
- **AD / CD** DNSSEC authenticated data / checking disabled
- **RCODE** 0 NOERROR, 2 SERVFAIL, 3 NXDOMAIN, 5 REFUSED

### 2.6 Transport

DNS normally runs over **UDP port 53**: one packet out, one packet back, no handshake. Classic UDP responses are limited to 512 bytes. **EDNS0** lets a client advertise a larger buffer. If a response still doesn't fit, the server sets **TC**, and the client retries over **TCP port 53**, where each message is prefixed by a 2-byte length.

**Encrypted variants:** DNS-over-TLS (DoT, TCP port 853) and DNS-over-HTTPS (DoH, HTTPS port 443, path usually `/dns-query`).

### 2.7 Why the design matters for security

UDP has no handshake, so **the only thing that ties a response to a query is the 16-bit ID, the source port, and the question**. An attacker who can guess those, and whose forged packet arrives before the real one, can inject a fake answer. Most of §7.5 follows from this single fact.

---

## 3. Problem Statement

> **Every device on a network depends on DNS before it can do anything else, yet on the small networks most people actually use (homes, hostels, college labs, small offices) DNS is handled by an opaque, unencrypted, easily abused service that nobody controls or observes. It leaks users' browsing to anyone on the path, can be tricked into handing out forged answers, can be turned into a weapon against others, and is blind to the malware and data theft that use it as a hidden channel. There is no single, locally controlled, understandable system that resolves names securely and privately, stops both known and never-before-seen malicious domains, detects DNS-based exfiltration, and explains its decisions. DNSentinel is built to be that system, from first principles, and to measure how well each of its defences actually works.**

### 3.1 The problem in detail

DNS was designed in 1987 for a small, trusted network. It trusts the first matching answer it receives, sends everything in plain text, and has no idea whether a lookup comes from a person, an app or malware. The internet around it has changed completely, and on a typical small network that one design now fails in several connected ways at once.

**It cannot be trusted.** A resolver accepts an answer if it matches a 16-bit transaction ID, a port and the question. An attacker who guesses those and gets a forged packet in first can **poison the cache**; Kaminsky's 2008 attack made this practical by racing queries for endless random subdomains. One success silently sends every user of that resolver to the attacker's server for a bank, email or software update. A related trick, **DNS rebinding**, has a public domain suddenly resolve to `192.168.1.1`, which lets a web page's JavaScript reach the victim's own router. Many naïve resolvers, including most student ones, use predictable IDs and a fixed port, and none of them stop a public name from resolving to a private address.

**It is not private.** Plain DNS travels unencrypted, so the Wi-Fi operator, college network or ISP can log every site every device visits. The resolver also sends the **full name** to every server in the chain, so root and TLD operators learn `private-clinic.example.in` when they only needed to know about `in`. Browsers now offer their own encrypted DNS, but that hands every query to one outside company and bypasses any protection the local network provides. Today, users effectively choose between privacy and local control.

**It is a hidden channel for attackers.** Firewalls almost always let DNS through, so attackers use it:
- **Ads and trackers** on every device, including TVs and IoT devices that cannot run an ad blocker. They increasingly hide behind **CNAME cloaking** (`metrics.newsite.com` quietly aliasing `tracker.example-analytics.net`) to slip past blocklists.
- **Malware** reaches its command-and-control servers through **Domain Generation Algorithms**: thousands of fresh pseudo-random domains every day (`qx7vk2mzp0lfa.com`), one of which the attacker registers. A blocklist, by definition, has never seen today's domain.
- **DNS tunnelling** tools such as `iodine` and `dnscat2` encode stolen data into query names and receive commands in responses. Every single query is legal; only the *behaviour over time* gives it away.

**It can be turned against others and fails badly.** A resolver that answers anyone can be used for **amplification DDoS**: small spoofed queries produce large responses aimed at a victim. And when upstream servers are slow or unreachable, every device on the network loses access to everything, even sites visited seconds ago, while the network owner has no idea which device is talking to what.

### 3.2 Why existing approaches fall short

Each part of this problem has a partial fix, but only in a different tool, and none cover the whole problem:

| Existing approach | What it misses |
|---|---|
| ISP / router default DNS | No filtering, no encryption, no visibility, often poorly hardened |
| Browser ad blockers | One browser only; TVs, phones and IoT devices are unprotected |
| Pi-hole-style blockers (forwarding) | Only block names already on a list; miss CNAME cloaking in basic setups, new DGA domains and tunnels; still send all queries to a third party |
| Public encrypted DNS (e.g. browser DoH to a big provider) | Encrypts, but moves all browsing data to one company and removes local protection |
| Enterprise DNS security products | Expensive, closed, and unsuitable for the small networks most people use |

The missing piece is **one system that brings these together**: it resolves names itself, is hardened against forgery, encrypts traffic for clients, blocks known threats, uses learning to catch unknown ones, keeps working during outages, and shows the owner exactly why it did what it did.

### 3.3 What a solution must therefore do

From this problem, any real solution must provide:

- **R1. Trustworthy answers**: resolve names itself and resist forged responses and rebinding.
- **R2. Privacy with local control**: encrypted DNS from devices to a resolver the owner controls, and minimal leakage to upstream servers.
- **R3. Protection against known threats**: network-wide blocking of ad, tracker and malware domains, including cloaked ones.
- **R4. Protection against unknown threats**: detection of never-before-seen malicious domains and of DNS tunnelling from their behaviour.
- **R5. Safety for others**: never become an amplification weapon.
- **R6. Resilience and visibility**: keep working when upstream fails, and explain every decision to the network owner.

Every design choice in the rest of this document traces back to one of these six requirements.

---

## 4. Goals and Non-Goals

### Goals

| ID | Goal | Requirement (§3.3) |
|---|---|---|
| G1 | Correct, RFC-compliant recursive resolution from the root, over UDP and TCP, with EDNS0 | R1 |
| G2 | A cache with TTL handling, negative caching, serve-stale and prefetch | R6 |
| G3 | Blocklist + allowlist filtering, including CNAME-cloaking detection | R3 |
| G4 | Poisoning resistance: random TXID, random source port, 0x20, bailiwick checks | R1 |
| G5 | DNS rebinding protection | R1 |
| G6 | Response rate limiting and access control | R5 |
| G7 | DoT and DoH for clients; QNAME minimisation upstream | R2 |
| G8 | ML detection of DGA domains and DNS tunnelling | R4 |
| G9 | Per-client logging, metrics and an explainable dashboard | R6 |
| G10 | Rigorous experimental evaluation of every feature | All |

### Optional goals (only after the core is done, in this order)

| Priority | ID | Optional goal | Requirement | Design |
|---|---|---|---|---|
| **1 (first)** | O1 | **ML tracker discovery:** find ad and tracker domains that aren't on any blocklist yet | R3 | §7.8.7 |
| 2 | O2 | **Look-alike domain detector:** flag domains imitating well-known brands (typos, homographs) | R4 | §7.8.7 |
| 3 | O3 | **Learned prefetching:** predict which names each device will query next and resolve them in advance | R6 | §7.8.7 |
| 4 | O4 | **DNSSEC validation** (stretch goal) | R1 | §7.9 |

**Rules for optional work:**
- Optional work starts only when the core milestones are on track (see §14), and the queue is taken **in order, one item at a time**. O1 is the first thing to add if there is time.
- Each optional item is designed now so that it can be picked up without redesign, but **the project's claims do not depend on any of them.**
- Anything not completed goes into the report's *Future Work* chapter, with its design from §7.8.7.

### Non-Goals

- **Being an authoritative server** for public zones. We may serve a few local names (e.g. `nas.home`), nothing more.
- **Competing with Unbound or BIND on raw performance.** We aim for "fast enough for a network of ~50–100 devices" and measure honestly against them.
- **Stopping a determined attacker who controls a client device.** Such an attacker can use hard-coded IPs or other protocols. We raise the cost and create visibility.
- **DNSSEC and the optional ML extensions** (O1–O4 above) are optional goals, not promises.
- **Deep packet inspection of non-DNS traffic.**

---

## 5. Threat Model

A security design is only meaningful against a stated adversary.

### 5.1 Assets we protect

1. **Integrity of answers** — clients get the true IP for a name.
2. **Confidentiality of queries** — who looked up what.
3. **Availability** — resolution keeps working under load and upstream failure.
4. **Data on client devices** — not exfiltrated via DNS.
5. **Local services** — routers and LAN devices not reachable via rebinding.

### 5.2 Adversaries

| Adversary | Capability | Our defence |
|---|---|---|
| **A1: Off-path spoofer** | Can send forged UDP packets to our resolver from anywhere, cannot see our traffic | TXID + port randomisation, 0x20, bailiwick checks, TCP fallback on suspicion |
| **A2: On-path observer** | Can see traffic between clients and resolver (shared Wi-Fi) | DoT/DoH between clients and DNSentinel |
| **A3: Curious upstream servers** | Root/TLD/authoritative servers log what they receive | QNAME minimisation |
| **A4: Malware on a LAN host** | Can issue arbitrary DNS queries through our resolver | DGA detection, tunnelling detection, NXDOMAIN-burst signal, per-client alerts and blocking |
| **A5: Malicious website** | Controls a domain and its authoritative server | Rebinding protection, blocklists, ML |
| **A6: External abuser** | Sends queries with spoofed source IPs to use us for amplification | Access control (LAN only), response rate limiting |
| **A7: Tracker companies** | Hide tracking domains behind first-party CNAMEs | CNAME-chain inspection |

### 5.3 Trust assumptions

- The DNSentinel host itself is not compromised.
- The root trust anchor and root hints file are obtained from an authentic source.
- Clients are configured (via DHCP or manually) to use DNSentinel.

### 5.4 Explicitly out of scope

- An **on-path attacker between DNSentinel and authoritative servers** can forge answers unless DNSSEC is validated. Without the DNSSEC stretch goal, we mitigate only off-path attackers upstream. We state this openly (§13).
- Clients that **deliberately bypass** DNSentinel (hard-coded DoH to a public resolver, VPNs).
- Denial of service by saturating the network link itself.

---

## 6. Solution Overview

### 6.1 Architecture

```
                   ┌──────────────────────────── DNSentinel ────────────────────────────┐
                   │                                                                   │
  Clients          │  ┌──────────────┐   ┌──────────────┐   ┌───────────────────────┐  │
 (laptops,  ─UDP/TCP 53─▶│              │   │              │   │                       │  │
  phones,   ─DoT 853──▶ │  Listeners   │──▶│ Policy engine│──▶│ ML fast path (DGA)    │  │
  TVs, IoT) ─DoH 443──▶ │              │   │              │   │                       │  │
                   │  └──────────────┘   └──────────────┘   └───────────┬───────────┘  │
                   │                                                     ▼              │
                   │                                         ┌───────────────────────┐  │
                   │                                         │        Cache          │  │
                   │                                         └───────────┬───────────┘  │
                   │                                                     │ miss         │
                   │                                                     ▼              │
                   │                                         ┌───────────────────────┐  │    Root / TLD /
                   │                                         │  Recursive resolver   │◀─┼──▶ authoritative
                   │                                         │  (hardened upstream)  │  │    servers
                   │                                         └───────────────────────┘  │
                   │                                                                   │
                   │   every query/response ──▶ Event bus ──▶ ML slow path (tunnelling,│
                   │                                          NXDOMAIN bursts)         │
                   │                                      └──▶ Logs + metrics ──▶ Dashboard
                   └───────────────────────────────────────────────────────────────────┘
```

### 6.2 Two paths: fast and slow

A key design idea is to split decisions into two paths.

**The fast path (synchronous)** runs on every query before it is answered. It must add at most a millisecond or so. It contains: access control, rate limiting, blocklist lookup, and the DGA classifier, which judges a single domain name and whose verdict is cached per domain.

**The slow path (asynchronous)** receives a copy of every query and response event through an in-memory queue and never blocks resolution. It holds the detectors that need **history**: tunnelling detection and NXDOMAIN bursts. When the slow path decides something is malicious, it pushes a new rule (e.g. "block `*.attacker.com` for client 192.168.1.23") back into the policy engine, which the fast path then enforces.

**Why:** tunnelling cannot be judged from one query, and we refuse to make every DNS answer wait on a model that looks at a sliding window. This is the same split used in real network security systems (inline enforcement, out-of-band analysis).

**An offline path (optional O1).** If ML tracker discovery is built, it runs as a third, **offline** path: a nightly batch job outside the resolver that analyses crawl data and proposes new tracker domains for the blocklist. It never touches live queries, so it cannot slow down or destabilise resolution (§7.8.7).

### 6.3 How each part of the problem maps to the solution

| Part of the problem | Component(s) | Section |
|---|---|---|
| Ads and trackers (incl. CNAME cloaking) | Policy engine: blocklists, CNAME-chain inspection | 7.6 |
| DGA malware | ML fast path: DGA classifier + NXDOMAIN-burst signal | 7.8 |
| DNS tunnelling | ML slow path: per-client-per-domain behavioural detector | 7.8 |
| Cache poisoning | Hardened resolver: randomisation, 0x20, bailiwick, ranking | 7.3, 7.4, 7.5 |
| Privacy | DoT/DoH listeners, QNAME minimisation | 7.2, 7.7 |
| DNS rebinding | Policy engine: private-address response filter | 7.6 |
| Amplification abuse | ACLs, response rate limiting | 7.6 |
| Reliability and visibility | Serve-stale, prefetch, logs, dashboard | 7.4, 7.10 |

---

## 7. Detailed Design

### 7.1 Wire Format Parser and Builder

**Responsibility:** Convert bytes ↔ structured messages. Everything else depends on this being correct and *safe*, because it parses untrusted input from the network.

#### Data model

```cpp
struct Question   { Name qname; uint16_t qtype; uint16_t qclass; };
struct RR         { Name name; uint16_t type; uint16_t cls; uint32_t ttl; RData rdata; };
struct Message    {
    Header header;
    std::vector<Question> questions;
    std::vector<RR> answers, authority, additional;
    std::optional<EdnsInfo> edns;   // extracted from the OPT record
};
```

`Name` stores labels in canonical (lower-case) form for comparison, *plus* the original case (needed for 0x20, §7.5).

#### Name compression

To save space, a name can end with a **pointer** to an earlier occurrence in the same message. A length byte whose top two bits are `11` is a pointer; the remaining 14 bits are an offset from the start of the message.

```
Offset 12: 03 'w' 'w' 'w' 07 'e' 'x' 'a' 'm' 'p' 'l' 'e' 03 'c' 'o' 'm' 00
Later:     04 'm' 'a' 'i' 'l' C0 10          ← "mail" + pointer to offset 16 ("example.com")
```

**Parsing is where most security bugs in DNS software have historically been.** Our parser enforces:

| Rule | Why |
|---|---|
| Every read is bounds-checked against the buffer length | Prevent out-of-bounds reads |
| A pointer must point **strictly backwards** from the current position | Prevents infinite loops (`C0 0C` pointing to itself) |
| At most 128 pointer jumps per name | Second guard against loops |
| Label ≤ 63 bytes, total name ≤ 255 bytes | RFC limits; rejects crafted oversized names |
| Label types `01`/`10` rejected | Reserved / obsolete |
| Section counts are sanity-checked against remaining bytes | A header claiming 65,535 answers in a 40-byte packet is dropped early |
| RDATA length must match the parsed content for known types | Detects malformed records |

Malformed packets are **dropped** (for queries) or treated as **SERVFAIL-worthy** (for upstream responses).

**The builder** writes messages with compression (a map from name suffix → offset) and respects the maximum size: if a response exceeds the client's advertised UDP size, it is truncated at a record-set boundary and TC is set.

**Testing:** The parser is fuzzed with libFuzzer/AFL++ (§11), and round-trip tested (`parse(build(m)) == m`) against real captured traffic.

### 7.2 Transport Layer: UDP, TCP, EDNS0, DoT, DoH

#### Client-facing listeners

| Listener | Port | Notes |
|---|---|---|
| UDP | 53 | Main path. Response size limited to client's EDNS0 buffer (or 512 without EDNS) |
| TCP | 53 | 2-byte length prefix per message; supports multiple queries per connection; idle timeout |
| DoT | 853 | TLS (OpenSSL) over the TCP framing above |
| DoH | 443 | HTTPS, `POST` and `GET ?dns=<base64url>` on `/dns-query`, media type `application/dns-message` |

#### Concurrency model

An **epoll-based event loop per CPU core**, with `SO_REUSEPORT` so the kernel spreads incoming UDP packets across cores. Each loop owns its sockets and outstanding upstream queries. The cache is shared, protected by sharded locks (the name hash picks the shard) to avoid a single global lock.

**Why not a thread per query?** DNS is thousands of tiny, I/O-bound requests. Threads would spend more time context-switching than working. Event-driven I/O is how every production resolver is built, and learning `epoll` is itself part of the course goals.

#### EDNS0 (RFC 6891)

- We parse the client's OPT record to learn its UDP buffer size.
- Upstream, we advertise a buffer of **1232 bytes**, the value recommended by DNS Flag Day 2020, because it avoids IP fragmentation on almost all paths. Fragmented UDP is both unreliable and a known poisoning vector.
- If a client sends no OPT record, responses are capped at 512 bytes.

#### TCP fallback

When an upstream response has TC set, the resolver retries that same query over TCP. We also use TCP deliberately as a **security response** (§7.5): if we see many mismatched responses for a query (a sign of a spoofing attempt), we retry over TCP, where an off-path attacker cannot inject.

### 7.3 Iterative Recursive Resolver

**Responsibility:** Given a question not in cache, find the answer by walking the delegation tree.

#### Algorithm

```text
resolve(qname, qtype):
    zone_cut ← closest ancestor of qname with cached NS records (fallback: root, from root hints)
    loop (max 30 upstream queries, max depth 16):
        servers ← addresses of NS for zone_cut (resolve missing addresses as sub-queries)
        server  ← pick_best(servers)                    # lowest smoothed RTT, with exploration
        send query (minimised name, §7.7) to server; wait with timeout

        on timeout / error:   penalise server RTT; try next server; if all fail → SERVFAIL
        on response:
            validate (ID, port, question, 0x20 case, bailiwick)   # §7.5; if invalid → discard, keep waiting
            case ANSWER:      cache; if CNAME and qtype≠CNAME → restart for target (max 8 hops); else return
            case REFERRAL:    ensure NS is below current zone_cut (no upward/sideways referral)
                              cache NS + in-bailiwick glue; zone_cut ← referred zone; continue
            case NXDOMAIN / NODATA: cache negatively using SOA (§7.4); return
            case SERVFAIL/REFUSED:  mark server bad for this zone; try next
```

#### Details that matter

**Root hints.** On start-up, we load the IANA root hints file (the 13 root server names and addresses) and "prime" by asking a root for the current root NS set.

**Server selection.** We keep a **smoothed RTT (SRTT)** per upstream server IP, updated like TCP's RTT estimator: `srtt = 0.875·srtt + 0.125·sample`. We pick the lowest SRTT but occasionally try others so we notice when a server becomes faster. Timeouts count as a large RTT penalty. This is a direct application of the TCP RTT-estimation theory from class.

**Timeouts and retries.** Initial timeout ~800 ms, backing off exponentially per retry, bounded by an overall per-query deadline (e.g. 5 s).

**Referral sanity.** A referral must point *downwards* toward the query name. Referrals to unrelated zones are discarded (classic poisoning trick).

**Resource limits.** Hard caps on referral depth, CNAME chain length, and total upstream queries per client query. The 2020 **NXNSAttack** showed that a malicious authoritative server can return referrals listing many name servers *without glue*, forcing a resolver to launch a flood of sub-queries against a victim. We cap how many glue-less NS names we resolve per referral.

**In-flight deduplication.** If 20 clients ask for the same uncached name at once, we send **one** upstream query and fan the answer out to all 20. This reduces load and also removes the "many outstanding identical queries" condition that makes birthday-style spoofing attacks easier.

### 7.4 Cache

**Responsibility:** Answer repeated questions instantly, while respecting TTLs and never storing untrustworthy data.

#### Structure

- **Key:** `(canonical qname, qtype, qclass)`.
- **Value:** the record set(s) with an absolute expiry time, the data's **trust rank**, and metadata (hit count, last access).
- **Eviction:** LRU when the memory limit is reached.
- **Sharding:** N shards by key hash, each with its own lock and LRU list.

#### TTL handling

We store `expires_at = now + ttl` and, when answering, return `ttl_remaining = expires_at - now`. Configurable floor and ceiling (e.g. min 0 s, max 1 day) prevent absurd values.

#### Trust ranking (RFC 2181 §5.4.1)

Not all data in a response is equally trustworthy. An authoritative **answer** outranks **glue** from a referral, which outranks data from the **additional** section. We never let lower-ranked data overwrite higher-ranked data in the cache. This blocks a class of poisoning attacks in which the attacker sneaks records into the additional section of an otherwise legitimate response.

#### Negative caching (RFC 2308)

NXDOMAIN ("name does not exist") and NODATA ("name exists, but not this type") answers are cached too. The TTL is `min(SOA record TTL, SOA MINIMUM field)` from the Authority section.

This matters for three reasons:
1. Performance: repeated typos and blocked lookups don't hit upstream.
2. Malware generates many NXDOMAINs; negative caching limits the load, and the count feeds the ML NXDOMAIN-burst signal.
3. Kaminsky-style attacks rely on uncached random names; negative caching does not stop that by itself, which is why §7.5 matters.

#### Serve-stale (RFC 8767)

If upstream resolution fails (timeout/SERVFAIL) and we hold an **expired** answer for the name, we return it with a short TTL (the RFC recommends 30 seconds), and keep trying to refresh in the background. Stale data is kept up to a configurable maximum age (the RFC suggests 1–3 days).

**Defence:** A slightly old IP address almost always still works; no answer never works. This directly serves the resilience requirement (R6) and is easy to demonstrate: kill the upstream network link and show that browsing to recently visited sites still works.

#### Prefetch

When a popular entry is requested in the last ~10% of its TTL, we answer from cache *and* launch a background refresh. Popular names then practically never expire from the user's point of view.

### 7.5 Anti-Spoofing and Cache Poisoning Defence

#### Why naïve resolvers are poisonable

To be accepted, a forged response must match: **transaction ID**, **destination port** (our source port), **source IP** (the server we queried) and **question**. The attacker usually knows the server IP and the question. So the defence rests on the randomness of the ID and port.

| Configuration | Attacker must guess | Search space |
|---|---|---|
| Sequential ID, fixed port | Nothing meaningful | ~1 |
| Random ID, fixed port | ID | 2^16 = 65,536 |
| Random ID + random port | ID × port | ~2^16 × ~2^15 ≈ 2^31 |
| + 0x20 encoding | ID × port × case pattern | multiplied by 2^(number of letters in name) |

#### Defences we implement

1. **Cryptographically random transaction IDs** (from `getrandom()`, never `rand()`).
2. **Random source port per upstream query** from the ephemeral range. Each upstream query opens a fresh UDP socket bound to a random port (or draws from a pool).
3. **0x20 encoding** (Dagon et al., 2008). DNS names are case-insensitive, but servers echo the question's case exactly. We randomise the case of each letter in the query (`wWw.ExAmPlE.cOm`) and **reject responses whose question does not match the case exactly**. This adds up to one bit of entropy per letter, with no protocol changes. A small fraction of broken servers do not preserve case; we fall back to normal case for those, and record them.
4. **Strict response matching.** Answers must come from the exact IP we queried, to the exact port, with the exact question.
5. **Bailiwick checking.** A server authoritative for `example.com` may only give us records within `example.com`. If its response contains `bank.com A 6.6.6.6`, we discard that record. This defeats the classic attack of stuffing unrelated records into a legitimate-looking answer.
6. **Trust ranking** (§7.4) prevents weak data overwriting strong data.
7. **Spoofing-attempt detection.** If we receive many responses with wrong IDs/ports for one outstanding query, that is an active attack. We log an alert and re-issue the query over TCP.

#### How we demonstrate it (Attack Lab, §10)

We build a deliberately weak mode (sequential IDs, fixed port) and run a Kaminsky-style attack using Scapy in an isolated network namespace, then repeat against each defence level. Metric: **forged packets needed until successful poisoning** (or failure within a fixed budget).

### 7.6 Policy Engine

Runs on the fast path, before the cache and resolver.

#### 7.6.1 Access control

By default, only clients from configured subnets (e.g. `192.168.0.0/16`, `10.0.0.0/8`) are answered. Everyone else gets REFUSED or is silently dropped. An **open resolver** is the root cause of most DNS amplification abuse (requirement R5).

#### 7.6.2 Blocklists and allowlists

- Loaded from public hosts-format and domain-list feeds, plus local custom lists.
- Stored in a **reversed-label trie** (`com → example → ads`) so a rule for `example.com` can optionally match all its subdomains with one lookup that walks from the TLD down. Lookup cost is proportional to the number of labels, not the list size.
- **Allowlist beats blocklist.** Allowlisting exists because false positives in DNS blocking break real websites.
- Lists reload periodically without restarting (build new trie, atomically swap pointer).

**What do we return for blocked names?**

| Option | Pro | Con |
|---|---|---|
| **NXDOMAIN** | Honest, fast failure; apps stop retrying | Some apps retry aggressively on NXDOMAIN |
| **0.0.0.0 / ::** (null IP) | Connection fails immediately, locally | Looks like a real answer; can confuse debugging |
| **Sinkhole IP** (our server) | Can show a "blocked" page and log the connection attempt | HTTPS shows certificate errors |

**Default: `0.0.0.0` / `::` for ad/tracker lists, NXDOMAIN for malware verdicts**, both configurable. Blocked responses carry a small TTL so unblocking takes effect quickly.

#### 7.6.3 CNAME-cloaking detection

A blocklist check on the queried name alone misses cloaked trackers. So after resolution, **every name in the CNAME chain is checked against the blocklist**. If any hop is blocked, the whole answer is blocked. The check costs one trie lookup per CNAME hop and only runs on responses that contain CNAMEs.

#### 7.6.4 DNS rebinding protection

After resolution, if a **public** domain resolves to an address in a private or special range, we strip that record. Ranges: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`, `0.0.0.0/8`, `100.64.0.0/10`, and IPv6 `::1`, `fc00::/7`, `fe80::/10`, plus IPv4-mapped forms of these. Local domains (e.g. `*.home`, `*.lan`) are exempt through configuration.

#### 7.6.5 Rate limiting

Two separate mechanisms:

- **Per-client query rate limiting** — a token bucket per client IP (e.g. 100 queries/s, burst 200). Stops a single misbehaving or infected device from overwhelming the resolver.
- **Response Rate Limiting (RRL)** — limits identical responses sent to the same client network (/24 for IPv4, /56 for IPv6) per second. Excess responses are dropped, or occasionally sent truncated ("slip") so a *legitimate* client whose IP is being spoofed can retry over TCP, which cannot be spoofed. This defeats amplification while keeping real users working.

Token buckets are the same algorithm studied in traffic shaping.

#### 7.6.6 Dynamic rules from the ML slow path

The slow path (and a high-risk fast-path verdict in enforce mode) can insert time-limited rules like "block `*.suspicious-domain.net` for client X for 1 hour". These have an expiry, a reason and a model score, all shown on the dashboard.

**Dynamic rules are kept separate from the blocklist trie.** They live in a small hash table keyed by domain (and optionally client), checked *before* the blocklist on every query, and removed when they expire. ML never edits the trie directly, because:
- ML can be wrong; a temporary rule undoes itself, a permanent list entry does not.
- An attacker could deliberately trigger false verdicts to get legitimate domains blocked permanently.
- Tunnel and burst verdicts are per client, while the trie is network-wide.
- The trie is rebuilt from list files and swapped in atomically (§7.6.2); live edits from another process would complicate that.

**The only ways into the permanent blocklist** are the public list feeds, and the **local custom blocklist file**. A domain reaches the custom file when a person confirms an alert on the dashboard, or (optional O1) when the tracker-discovery candidate list is approved. The custom file is loaded into the trie at the next reload. Alerts marked as false alarms go to the allowlist and are saved as labelled examples for retraining.

### 7.7 Privacy: QNAME Minimisation and Encrypted DNS

#### QNAME minimisation (RFC 9156)

Instead of sending the full name to every server, we reveal only as much as each level needs:

```
Traditional:                              Minimised:
root  ← "www.private-clinic.in A?"        root  ← "in NS?"
in    ← "www.private-clinic.in A?"        in    ← "private-clinic.in NS?"
auth  ← "www.private-clinic.in A?"        auth  ← "www.private-clinic.in A?"
```

The root and TLD servers learn only what they need to route us.

**Edge cases:** Some broken servers answer NXDOMAIN for intermediate names that exist only as "empty non-terminals". RFC 9156 describes how to handle this; we fall back to the full name for that zone if minimisation fails. For names with many labels, the number of extra queries is capped.

**Cost:** Extra round trips on a cold cache. We measure it (§11). With a warm cache (the usual case), the cost mostly disappears because zone cuts are cached.

#### DoT and DoH for clients

- **DoT (RFC 7858):** TLS on TCP 853, same length-prefixed framing as DNS over TCP. Android's "Private DNS" setting uses DoT, so it is easy to demo with a real phone.
- **DoH (RFC 8484):** DNS messages carried in HTTPS requests to `/dns-query`. Browsers (Firefox, Chrome) can be pointed at a custom DoH URL.
- Certificates: self-signed with a local CA for the lab; Let's Encrypt if deployed with a real domain.

Encrypting client ↔ DNSentinel protects against the on-path observer (A2), while keeping filtering local, rather than handing all queries to a third-party DoH provider.

**Honest scope:** Upstream traffic (DNSentinel ↔ authoritative servers) remains plain DNS, because authoritative servers do not generally offer encryption. This is a property of today's internet, not our design; QNAME minimisation is what reduces the leakage there.

### 7.8 ML Subsystem

#### 7.8.1 Design philosophy

1. **ML only where rules can't work.** Blocklists handle known-bad; ML handles *unseen* bad (new DGA domains, new tunnels).
2. **Small, explainable models.** Every alert must show *why* it fired (which features). We must be able to explain any model in the viva.
3. **Our own data where possible.** Public intrusion datasets are known to contain labelling errors and artefacts (the CICIDS2017 audits are a well-documented example), so we generate our own malicious traffic in the lab and capture our own benign traffic.
4. **Evaluate like an attacker would.** Test on malware families the model never saw during training (§7.8.6).
5. **Measure the network cost.** Added latency per query is a first-class metric, not an afterthought.

#### 7.8.2 Detector 1: DGA classifier (fast path)

**Input:** a single domain name. We classify the **registrable domain** (eTLD+1, computed using the Public Suffix List), e.g. `x7kq2.example.co.uk` → `example.co.uk`, because that is what a DGA generates.

**Model A — feature-based baseline (Random Forest / Gradient Boosting):**

| Feature | Intuition |
|---|---|
| Length of registrable label | DGA names are often long and uniform in length |
| Shannon entropy of characters | Random strings have high entropy |
| Ratio of digits, vowels, consonants | Human names are pronounceable |
| Longest consonant run | `xkqzvt` is not English |
| n-gram (2/3-gram) log-likelihood under a model trained on benign domains | "How English-like / brand-like does this look?" |
| Fraction of characters that are hex digits | Many DGAs output hex |
| Number of distinct characters | |
| TLD category | Some DGAs favour specific TLDs |

**Model B — character-level neural model (1D CNN or small LSTM):** learns character patterns directly from the raw string, no manual features. Embedding (dim ~32) → 1D convolutions → pooling → dense → sigmoid.

We compare A and B on accuracy, cross-family generalisation, size and inference latency.

**Deployment:**
- Model A is exported to plain C/C++ code (e.g. with `m2cgen` or Treelite) and runs in-process, in microseconds.
- Model B is exported to ONNX and run with ONNX Runtime in C++, or via a local sidecar process over a Unix socket (measured both ways if time permits).
- **Verdicts are cached per registrable domain**, so each domain is scored once, not on every query.
- **Allowlist of popular domains** (e.g. top 100k of Tranco): never scored, eliminating most false-positive risk on everyday browsing (and CDN names that look random, like `d1a2b3c4.cloudfront.net`, whose registrable domain `cloudfront.net` is benign).

**Data:**
- **Benign:** the Tranco top-sites list (a research-grade, manipulation-resistant ranking).
- **Malicious:** domains generated by running open-source reimplementations of real malware DGAs (many families), plus DGArchive-style public feeds where available.

#### 7.8.3 Detector 2: DNS tunnelling detector (slow path)

**Unit of analysis:** `(client IP, registrable domain)` over a sliding window (e.g. 60 s, sliding every 10 s). One query cannot reveal a tunnel; a minute of behaviour can.

| Feature (per window) | Why it separates tunnels from normal use |
|---|---|
| Query count | Tunnels send many queries to one domain |
| Number of **unique** subdomains | Every tunnel query carries new data, so subdomains never repeat |
| Mean/max subdomain length | Data is packed into labels up to 63 bytes |
| Mean character entropy of subdomains | Encoded data (base32/64) is high-entropy |
| Fraction of TXT / NULL / CNAME / MX queries | Tunnels prefer record types that carry more data back |
| Mean response size | Downstream data comes back in responses |
| Mean inter-query time and its variance | Tunnels poll steadily |
| Ratio of NXDOMAIN responses | |

**Model:** Random Forest or Gradient Boosting (tabular features, explainable via feature importance). An **Isolation Forest** (unsupervised anomaly detection trained only on benign traffic) is evaluated as a comparison, because in reality we would not have labelled examples of every tunnel tool.

**Data:** we generate tunnel traffic with **iodine** and **dnscat2** between our own VMs (we run the "attacker" authoritative server on a cloud VM with a domain we control), at several data rates, including deliberately *slow* tunnels designed to evade detection. Benign traffic: captured from our own devices' normal use (with consent, only our own devices), plus replayed traffic from multiple days.

**Known false-positive sources:** some legitimate services use DNS in high-entropy ways (anti-virus reputation lookups, some CDNs, DNS-based blocklists such as `*.zen.spamhaus.org`). These are handled by allowlisting and measured explicitly in evaluation.

#### 7.8.4 Signal 3: NXDOMAIN bursts (slow path)

A DGA-infected host tries many generated domains, most of which are unregistered, producing a burst of NXDOMAINs. We track per-client NXDOMAIN count and ratio over a window. Alone it is noisy (typos, broken apps), but combined with DGA scores it is strong: "this client got 150 NXDOMAINs in a minute, and 90% of those names score as DGA".

#### 7.8.5 Score fusion and actions

```
risk = f(dga_score, tunnel_score, nxdomain_burst_score, blocklist_hit)
```

Start with a simple, explainable rule-based fusion (weighted sum with thresholds), and optionally a logistic regression on top. Actions per threshold:

| Risk | Action |
|---|---|
| Low | Log only |
| Medium | Alert on dashboard with explanation |
| High | Block domain for that client (time-limited dynamic rule) + alert |

Operating mode is configurable: **monitor-only** (alert, never block) vs **enforce**. Thresholds are chosen from the ROC curve for a target false-positive rate, not accuracy.

#### 7.8.6 Evaluation methodology (how we avoid fooling ourselves)

- **No random split alone.** We also split **by DGA family** (leave-family-out): train on some families, test on unseen ones. That is the real-world question.
- **Per-class metrics**: precision, recall, F1 per family, confusion matrices, ROC and precision-recall curves. Never just "accuracy", which is meaningless with class imbalance.
- **False positives per day of real browsing**, measured on held-out benign traffic from our devices. For a network tool, "3 false alarms a day" is the number users care about.
- **Adversarial check:** dictionary-based DGAs (concatenated English words) are known to evade character-statistics models. We test on them and report the result honestly.
- **Latency:** microseconds added per query (fast path), and detection delay (seconds from tunnel start to alert) for the slow path.

#### 7.8.7 Optional ML extensions (O1–O3)

These are designed now but **built only if time allows**, in priority order (§4). Their experiments are E15–E17 in EVALUATION.md.

##### O1 — ML tracker discovery (optional, priority 1)

**Problem.** Ad and tracker blocklists are maintained by people, so new tracker domains get through until someone reports them. O1 finds likely trackers **before** they reach the lists.

**Key idea.** Trackers behave differently from ordinary sites in DNS traffic:
- **Prevalence:** a tracker is looked up during visits to many unrelated websites, while a site's own domains appear only when that site is visited. Only a network-wide resolver sees this.
- **Company they keep:** trackers tend to be looked up in the same burst as other trackers.
- **Shared infrastructure:** they often share IP addresses, CNAME targets or name servers with known trackers.

**Data.** A headless browser (Playwright) loads the top 1,000–5,000 Tranco sites through DNSentinel. This reuses the crawler built for experiment E12. Each page load produces a burst of DNS lookups tagged with the site that caused it.

**Labels.** DuckDuckGo Tracker Radar (an open dataset of third-party domains with purpose categories and prevalence) plus public tracker blocklists. Negatives are domains seen only as first-party or content domains.

**Features.**

| Group | Feature | Intuition |
|---|---|---|
| Prevalence | Number of distinct, unrelated sites whose page loads include the domain | Third-party behaviour, visible at the DNS level |
| Co-occurrence embedding | Vector from a word2vec (skip-gram) model in which each page-load burst is a "sentence" and each domain a "word" (the Dns2Vec idea) | Trackers sit close to other trackers in embedding space |
| Lexical | Character n-grams and tokens (`pixel`, `metrics`, `tag`, `ads`, …) | Naming conventions |
| Infrastructure | Shares IPs, CNAME targets or NS with known trackers | Same operators, same hosting |

word2vec is a **shallow** neural network; we describe it as such.

**Model.** Gradient boosting (or a small MLP) on the combined features, giving a tracker probability per domain.

**How it plugs in.** O1 runs as the **offline path** (§6.2), nightly:
1. Score every third-party domain seen in the crawl and in the network's own traffic that isn't already on a list.
2. Write a **candidate list** with scores and the evidence behind each (prevalence, nearest known trackers).
3. Candidates are reviewed on the dashboard. Optionally, candidates above a very high threshold are auto-approved.
4. Approved domains go into the **local custom blocklist file**, which is loaded into the trie at the next reload (§7.6.6).

**Limits (stated in the report).** DNS sees domain names only, so domains that serve both content and tracking cannot be blocked without breaking sites. First-party subdomain trackers are already handled by the CNAME-chain check (§7.6.3). Browser-based research systems such as AdGraph and WebGraph see full URLs and page structure; O1's research question is **how much of that is possible from DNS alone**, network-wide, for devices that can't run a browser extension.

##### O2 — Look-alike (phishing) domain detector (optional, priority 2)

**Problem.** Phishing domains imitate well-known brands: typos (`paypa1.com`), added words (`paypal-login-secure.com`), the brand placed in a subdomain (`paypal.com.verify-account.net`), and **Unicode homographs**, where a character from another alphabet looks identical to a Latin one (on the wire these names travel in punycode form, `xn--…`).

**Where it runs.** On the fast path, next to the DGA classifier. It scores the registrable domain, caches the verdict per domain, and feeds the same fusion and actions (§7.8.5). Exact protected names and allowlisted popular domains are skipped.

**Pipeline.**
1. Decode punycode (RFC 3492) to Unicode.
2. Map confusable characters to a "skeleton" using the Unicode confusables data (UTS #39), so homographs become plain look-alikes.
3. Compare against a **protected list**: top Tranco brands plus user-defined names (e.g. the college portal, local banks).
4. Features: edit distance from the skeleton to the nearest protected name, protected name contained as a token, brand appearing in a subdomain, suspicious words (`login`, `secure`, `verify`, `account`), TLD, length.
5. Model: gradient boosting on these features, compared with a character CNN reusing the DGA pipeline (§7.8.2). A Siamese network comparing a candidate with its nearest brand is a further option.

**Data.** Positives: permutations of protected names generated with dnstwist (typos, homoglyphs, bit flips, added words), plus real phishing domains from public feeds (OpenPhish, PhishTank). Negatives: Tranco domains, deliberately including legitimate names that resemble brands (e.g. `apple.com` vs `applebees.com`).

##### O3 — Learned prefetching (optional, priority 3)

**Problem.** Even with a good cache, some lookups are misses, and the user waits for a full resolution. The core resolver already prefetches popular entries near expiry (§7.4). O3 tries to **predict** what each device will look up next and resolve it before it is asked for. This is ML used to improve network *performance*, not security.

**Models (in order of complexity).**
1. Baseline: the existing TTL-based prefetch (§7.4).
2. A first-order **Markov model** per device: "after A, B usually follows".
3. A small **LSTM or GRU** over each device's recent sequence of domain IDs (vocabulary = the most common domains seen on the network).

**How it plugs in.** On the slow path: for each event, predict the next names; if a prediction's probability is above a threshold and the name is not fresh in the cache, resolve it in the background.

**Safeguards.**
- A **prefetch budget** caps extra upstream queries (e.g. at most 10% of real query volume), so prefetching cannot load upstream servers or waste bandwidth. Wasted prefetches (never used before expiry) are counted.
- Prefetched names are sent upstream even if the user never visits them, which is a small extra privacy leak; QNAME minimisation still applies, and the report states it.

**Honest expectation.** The cache model (EVALUATION.md A2) suggests most remaining misses come from rarely queried names, which are the hardest to predict, so gains may be modest. Measuring exactly how much a learned model adds over simple prefetching is itself a useful result.

### 7.9 DNSSEC Validation (Stretch Goal)

DNSSEC adds signatures so a resolver can verify answers cryptographically:

- **DNSKEY** — a zone's public keys.
- **RRSIG** — signature over a record set.
- **DS** — hash of a child zone's key, published in the **parent** zone. This links the chain.
- **NSEC/NSEC3** — signed proof that a name does *not* exist.

Validation builds a **chain of trust**: root trust anchor → root DNSKEY → `com` DS → `com` DNSKEY → `example.com` DS → `example.com` DNSKEY → RRSIG over the answer. If any link fails, the answer is **bogus** and we return SERVFAIL.

**Why it is a stretch goal:** it involves canonical wire-format ordering, several signature algorithms (RSA/SHA-256, ECDSA P-256, Ed25519), NSEC/NSEC3 proofs, and key rollovers. It is valuable but large. Our plan: validate positive answers for zones using ECDSA P-256 or RSA/SHA-256, set the AD bit on success, and treat NSEC3 proof validation as future work if time runs out.

**Why it matters for our security story:** it is the only defence against an **on-path** attacker upstream (§5.4). Without it, we are explicit that we defend only against off-path spoofing.

### 7.10 Observability and Dashboard

#### Query log (one event per query)

```json
{
  "ts": "2026-10-14T10:22:31.412Z",
  "client": "192.168.1.23",
  "transport": "doh",
  "qname": "cdn.example.com",
  "qtype": "A",
  "rcode": "NOERROR",
  "answer_count": 2,
  "cache": "hit",
  "latency_us": 184,
  "policy": { "action": "allow", "rule": null },
  "ml": { "dga": 0.03, "tunnel": null }
}
```

Events go to a ring buffer → a collector process → SQLite (or a time-series DB) with retention limits. Logging can be anonymised or disabled per client, because a DNS log is itself sensitive data.

#### Metrics (Prometheus format)

`queries_total{transport,qtype,rcode}`, `cache_hits_total`, `cache_misses_total`, `resolution_latency_seconds` (histogram), `upstream_timeouts_total`, `blocked_total{list}`, `ml_alerts_total{detector}`, `spoof_attempts_total`, `rrl_dropped_total`.

#### Dashboard views

- **Overview:** queries/s, cache hit ratio, p50/p99 latency, % blocked.
- **Clients:** per-device activity, top domains, blocked counts.
- **Alerts:** every ML alert with score, contributing features ("unique subdomains: 412/min, mean entropy 4.8 bits/char"), and one-click allowlist/block.
- **Security:** spoofing attempts detected, RRL activity, rebinding blocks.

---

## 8. The Life of a Query (End-to-End Walkthrough)

Client `192.168.1.23` asks `metrics.newsite.com A` over DoH.

1. **Listener:** HTTPS request arrives on 443; TLS decrypted; body parsed by the wire parser (§7.1).
2. **Access control:** client in allowed subnet → continue (§7.6.1).
3. **Rate limit:** client under its token bucket → continue (§7.6.5).
4. **Dynamic rules:** no active rule for this client/domain.
5. **Blocklist on qname:** `metrics.newsite.com` not listed.
6. **DGA fast path:** registrable domain `newsite.com` is in the popular-domain allowlist → skip scoring.
7. **Cache lookup:** miss.
8. **In-flight check:** nobody else is resolving it → start resolution.
9. **Resolver:** closest cached zone cut is `com` (from earlier lookups). Sends minimised query `newsite.com NS?` with random ID, random port, 0x20 case (`nEwSiTE.cOm`) to the fastest `com` server by SRTT.
10. **Validation:** response matches ID, port, source IP, exact-case question; referral to `ns1.newsite.com` is below `com` → accepted; NS and glue cached with correct trust rank.
11. **Resolver:** asks `ns1.newsite.com` for `metrics.newsite.com A`. Answer: `CNAME tr.adtrack-example.net`.
12. **CNAME chase:** resolves `tr.adtrack-example.net A` (new walk from `net`).
13. **CNAME-cloaking check:** `adtrack-example.net` is on the tracker blocklist → **whole answer blocked**.
14. **Response:** `0.0.0.0` with a short TTL, sent back over the DoH connection.
15. **Event:** logged with `policy.action = block, rule = cname:adtrack-example.net`; slow-path detectors update their windows for this client.
16. **Dashboard:** blocked counter increments; the block reason is visible for this device.

A second client asking the same name 10 seconds later gets the cached block result in microseconds.

---

## 9. Technology Stack and Repository Layout

### Stack

| Component | Choice | Reason |
|---|---|---|
| Resolver core | **C++20** | Low-level control of sockets, memory and latency; teaches systems programming |
| Event loop | `epoll` directly (or standalone Asio) | Learn the mechanism; no hidden magic |
| TLS | OpenSSL | DoT and DoH |
| HTTP/2 for DoH | nghttp2 (HTTP/1.1 acceptable for the prototype) | RFC 8484 recommends HTTP/2 |
| Build / tests | CMake, GoogleTest, libFuzzer | Standard tooling |
| ML training | Python: scikit-learn, PyTorch, pandas | Fast experimentation |
| ML serving | m2cgen/Treelite (C++ trees), ONNX Runtime (neural) | Keep inference in-process and fast |
| Slow-path analyser | Python service reading events over a Unix socket | Easy to iterate on features |
| Metrics + dashboard | Prometheus + Grafana, plus a small custom web page for alerts | Standard, low effort for charts |
| Lab | Linux network namespaces, Docker, 2–3 cloud VMs | Isolated, reproducible |
| Traffic tools | `dig`, `kdig`, `dnsperf`/`resperf`, Scapy, iodine, dnscat2, Wireshark | Testing, attacks, measurement |
| Lab DNS hierarchy | NSD or BIND in containers (our own root, TLD and authoritative zones) | Repeatable experiments with crafted edge cases |
| Lab topology | Mininet (+ `tc netem`) | One-command, reproducible attack lab |
| Network simulation | ns-3 in emulation mode (`TapBridge`, real-time scheduler) | Realistic links (Wi-Fi contention, mobile, satellite) around our real binary |
| Analytical models | MATLAB (or Python/NumPy, GNU Octave) | Predict results from theory and check them against measurements |
| Results & plots | Python (pandas, matplotlib), `make figures` | Every report figure regenerated from raw data |
| Crawler | Playwright (Python), headless Chromium | Blocking experiments (E12); training data for optional O1 |
| Optional ML extensions | gensim (word2vec), scikit-learn, PyTorch; dnstwist; Unicode confusables data | O1 tracker discovery, O2 look-alike detection, O3 learned prefetching |

### Repository layout (planned)

```
dnsentinel/
├── README.md                 ← this document
├── EVALUATION.md             ← claims, experiments, tests, report structure
├── LEARNING_PATH.md          ← theory to learn before coding
├── docs/                     ← design notes, experiment log, report drafts
├── core/                     ← C++ resolver
│   ├── wire/                 ← parser, builder, name handling
│   ├── net/                  ← event loop, UDP/TCP/DoT/DoH listeners
│   ├── resolver/             ← iterative resolution, server selection, QNAME min.
│   ├── cache/                ← sharded LRU cache, negative cache, serve-stale
│   ├── security/             ← randomisation, 0x20, bailiwick, RRL
│   ├── policy/               ← ACL, blocklist trie, CNAME check, rebinding
│   ├── ml/                   ← DGA inference (generated tree code / ONNX)
│   ├── server/               ← config loading, query pipeline (listeners → resolver)
│   └── telemetry/            ← event bus, metrics
├── analyzer/                 ← Python slow path (tunnelling, NXDOMAIN bursts, fusion)
├── ml/                       ← training notebooks, feature code, model export
│   ├── dga/
│   ├── tunnel/
│   ├── tracker/              ← optional O1: embeddings, classifier, candidate list
│   ├── lookalike/            ← optional O2
│   └── prefetch/             ← optional O3
├── crawler/                  ← Playwright crawler (E12, and O1 training data)
├── dashboard/                ← Grafana dashboards + alert web UI
├── lab/                      ← Mininet topology, lab DNS hierarchy zones, attack scripts
├── sim/ns3/                  ← ns-3 emulation scenarios, DnsQueryApp
├── theory/                   ← analytical models A1–A3 (MATLAB/Octave or Python)
├── bench/                    ← experiment configs and runner, raw results, `make figures`
├── tests/                    ← unit, integration, fuzz targets
└── config/dnsentinel.yaml
```

---

## 10. Testbed and Attack Lab

### 10.1 Topology

```
   ┌──────────── Laptop (Linux) ─────────────────────────────┐
   │  netns: client-1, client-2 (normal users)               │
   │  netns: infected  (runs DGA simulator, tunnel client)   │
   │  netns: attacker  (Scapy spoofer for poisoning)         │       Internet
   │  netns: resolver  (DNSentinel)  ────────────────────────┼──▶ root/TLD/auth
   │  netns: fake-auth (our own authoritative server for     │
   │                   the poisoning lab, fully isolated)    │
   └─────────────────────────────────────────────────────────┘
   Cloud VM: authoritative server for a domain we own (tunnel endpoint)
```

Network conditions (latency, loss) between namespaces are set with `tc netem` to emulate realistic upstream paths. The topology is built with **Mininet**, so anyone can recreate it with one command.

Most experiments use a **lab DNS hierarchy**: our own root, TLD and authoritative servers (NSD or BIND in containers), with zones crafted for every edge case (CNAME chains, truncation, empty non-terminals, lame servers, out-of-bailiwick answers). This makes experiments repeatable, which the real internet is not. Experiments that need ground truth (correctness, real-world latency, blocking) run against the real internet. Details: EVALUATION.md §3.

### 10.2 Four levels of evidence

| Level | Tool | Used for |
|---|---|---|
| Analytical | MATLAB / Python / Octave | Predicting poisoning cost (A1), cache hit ratio (A2), latency under load (A3) |
| Simulation | ns-3 in emulation mode | Our real binary over simulated Wi-Fi, mobile, lossy and satellite links; outages; many clients (S1–S3) |
| Emulation | Mininet, namespaces, Docker | The attack lab and most system experiments |
| Real | Cloud VMs, real internet, our own devices | Correctness, real latency, real traffic, blocking |

ns-3 is used to simulate the **network around** our real programs rather than to model DNS itself: it has no DNS model, and writing one would test the model instead of our resolver. If ns-3's real-time emulation proves unstable at our scale, the same scenarios fall back to Mininet with `tc netem`.

### 10.3 Ethics and safety rules

- **Poisoning attacks are only run inside network namespaces** against our own resolver and our own fake authoritative server. Never against real resolvers or domains.
- **Tunnelling uses a domain we own** and our own VMs.
- **No real malware is executed.** DGAs are open-source reimplementations that only produce strings.
- **No capture of other people's traffic.** Benign datasets come from our own devices with consent.
- Rate-limited load tests are only run against our own infrastructure.

---

## 11. Evaluation Plan

The complete plan is in **[EVALUATION.md](EVALUATION.md)**: the claims we must prove, every experiment's hypothesis, setup, baseline and success criterion, the analytical models and ns-3 scenarios, the software test plan, a traceability matrix, statistics rules, threats to validity, the figure plan and the report structure. Summary:

| # | Question | Level(s) | Baseline |
|---|---|---|---|
| A1 | How much does each defence raise the cost of cache poisoning? | Analytical (probability model) | — |
| A2 | What cache hit ratio does theory predict for our traffic? | Analytical (TTL-cache + Zipf model) | — |
| A3 | How should latency grow with load? | Analytical (M/M/1, M/D/1 queues) | — |
| S1 | What do DoT/DoH and QNAME-min cost on Wi-Fi, mobile, lossy and satellite links? | Simulation (ns-3) | UDP, features off; `tc netem` cross-check |
| S2 | How well do serve-stale and prefetch handle outages of different lengths? | Simulation (ns-3) | Serve-stale off |
| S3 | Is the resolver fast and fair with many clients and one flooding client? | Simulation (ns-3) | Rate limiting off |
| E1 | Is resolution correct? | Real | Unbound |
| E2 | How fast is it? | Real + emulation + A3 | Unbound, forwarder |
| E3 | How effective is the cache? | Real trace + A2 | Cache disabled |
| E4 | Does serve-stale help? | Emulation + S2 | Serve-stale off |
| E5 | How resistant is it to poisoning? | Emulation + A1 | Weak mode, defence ladder |
| E6 | What does privacy gain and cost? | Real + emulation + S1 | UDP, QNAME-min off |
| E7 | How good is DGA detection on unseen families? | ML + real traffic | Blocklist-only, entropy rule |
| E8 | How good and how fast is tunnel detection? | Emulation + real | Threshold rule, Isolation Forest |
| E9 | What does ML cost per query? | Emulation | ML off |
| E10 | Does it resist amplification and referral abuse? | Emulation + analytical | RRL off, cap off |
| E11 | How robust is the parser? | Fuzzing | — |
| E12 | Does blocking work, and what breaks? | Real | No blocking, name-only blocking |
| E13 | Does rebinding protection work? | Emulation | Protection off |
| E14 | What does each fast-path stage cost? | Emulation | — |
| *E15* | *(Optional O1)* Does ML tracker discovery find trackers before the public lists do? | Real crawl + offline ML | Prevalence rule, lexical-only model |
| *E16* | *(Optional O2)* Does the look-alike detector catch brand imitations without false alarms? | ML + real traffic | Edit-distance rule, dnstwist exact match |
| *E17* | *(Optional O3)* Does learned prefetching beat TTL-based prefetching at the same upstream budget? | Trace replay | No prefetch, TTL-based prefetch |

**Why the baselines and models matter:** a number means little in isolation. "Our p99 latency is within X ms of Unbound", "ML catches Y% of DGA domains the blocklist missed" and "measured poisoning cost matches the model within its confidence interval" are claims that can be defended.

---

## 12. Design Decisions: The Complete Defence

Each decision below states the choice, the alternatives, and why we chose as we did.

### D1. Why build a resolver from scratch instead of configuring Pi-hole + Unbound?

Configuring existing software teaches configuration. Building the resolver teaches the protocol: packet formats, compression, delegation, caching semantics, and *why* poisoning works. That is the purpose of a networks course project. We still **use Unbound as the correctness and performance baseline**, so we are not reinventing blindly: we are measuring ourselves against the real thing.

### D2. Why a full recursive resolver instead of a forwarder?

A forwarder hands every query to someone else (e.g. 1.1.1.1). That (a) sends all our users' queries to a third party, defeating privacy goals; (b) makes QNAME minimisation, bailiwick checking and poisoning defences impossible to demonstrate, because the forwarder never talks to authoritative servers; and (c) teaches almost nothing about DNS. Forwarding mode will exist as a configuration option and a benchmark baseline.

### D3. Why C++ for the core?

A resolver is latency-sensitive, handles untrusted binary input, and is built around sockets and event loops. C++ gives direct control over memory layout, syscalls (`epoll`, `recvmmsg`, `SO_REUSEPORT`) and performance, all of which are course-relevant. We counter C++'s safety risk with bounds-checked parsing, sanitizers (ASan/UBSan) in tests, and fuzzing. Python is used where speed of iteration matters more than raw speed (ML, analytics).

### D4. Why an event loop, not threads per request?

DNS workload is many tiny I/O-bound requests. Thread-per-request wastes memory and CPU on context switches. An event loop per core with `SO_REUSEPORT` scales across cores without cross-thread coordination on the hot path.

### D5. Why split ML into fast and slow paths?

DGA detection needs only the name, so it can run inline and be cached. Tunnelling detection requires minutes of behaviour; running it inline would add latency to every query for no benefit. The slow path acts asynchronously and pushes rules back to the fast path. The cost is a short detection delay for tunnels (seconds), which we measure.

### D6. Why use ML at all? Isn't a blocklist enough?

A blocklist can only contain domains someone has already seen. DGA domains are new every day, and tunnels use the attacker's own new domain. ML generalises from patterns, catching threats that are unknown by name. We **quantify this directly** in E7: how many malicious domains ML catches that the blocklist missed.

### D7. Why small models (trees, small CNN) rather than large deep models?

1. Latency budget: microseconds per query in the fast path.
2. Explainability: every alert must show its reasons.
3. Data size: our datasets are moderate; big models would overfit.
4. Viva: we must understand and justify every part.

The small CNN/LSTM is included specifically to test whether deep learning adds value over hand-crafted features, which is a legitimate experimental question.

### D8. Why generate our own attack data instead of using public intrusion datasets?

Public NIDS datasets have documented labelling errors and artefacts, and models trained on them often don't generalise to other networks. Generating attacks ourselves gives correct labels, lets us vary attack parameters (e.g. tunnel speed), and matches the exact features our system observes.

### D9. Why classify the registrable domain (eTLD+1), not the full name?

DGAs generate registrable domains; the subdomain part of legitimate names (CDN hashes, cloud buckets) is often random-looking and would cause false positives. Using the Public Suffix List to find the registrable part is correct and standard.

### D10. Why 0x20 encoding when we already randomise ID and port?

Defence in depth. It is cheap, needs no protocol changes, and multiplies attacker effort. Port randomisation can be weakened by NATs that rewrite source ports sequentially; 0x20 still holds in that case.

### D11. Why an EDNS0 buffer of 1232 bytes upstream?

Larger UDP responses fragment at the IP layer. Fragments are often dropped by firewalls (causing timeouts), and fragmentation has been used for poisoning attacks, since later fragments carry no DNS ID or port. 1232 bytes fits within the IPv6 minimum MTU after headers, avoiding fragmentation on almost all paths; larger responses use TCP.

### D12. Why serve stale data? Isn't that incorrect?

For a user, a recently valid IP address almost always still works; a failed lookup never does. RFC 8767 standardises this behaviour with short TTLs on stale answers, and major resolvers implement it. Stale serving only happens when fresh resolution **fails**; it never replaces successful resolution.

### D13. Why check the whole CNAME chain for blocking?

Because CNAME cloaking exists specifically to evade name-based blocking. Checking every hop costs one trie lookup per hop, which is negligible.

### D14. Why answer only LAN clients?

An open resolver is the primary tool of DNS amplification attacks. Restricting clients is the most effective single measure against abuse (R5).

### D15. Why QNAME minimisation when it costs latency?

It removes unnecessary leakage of full query names to root and TLD operators at a cost we measure, which mostly disappears once zone cuts are cached. It is a standards-track mechanism and a clean privacy/performance trade-off to present experimentally.

### D16. Why not just use browser DoH to Cloudflare/Google for privacy?

That encrypts traffic but moves all trust (and all query data) to a single external company, and bypasses local protections such as blocking and malware detection. DNSentinel offers DoH/DoT *to itself*, so encryption and local control coexist.

### D17. Why validate at four levels instead of just measuring the system?

Each method has a blind spot: models simplify, simulations approximate links, labs are small, and the real internet can't be controlled. When a model's prediction matches a measurement, both become more credible, and models let us extrapolate to cases we can't test directly. Full-entropy poisoning is the clearest example: it would take months to attack, so we validate the model at reduced entropy and extrapolate (EVALUATION.md A1, E5).

### D18. Why ns-3 in emulation mode rather than a pure ns-3 DNS simulation?

ns-3 has no DNS model. Writing one would duplicate our resolver, and the results would describe the model rather than our code. In emulation mode ns-3 simulates only the links (including Wi-Fi contention that `tc netem` can't reproduce), while the real DNSentinel binary, real clients and real authoritative servers send real packets through them.

### D19. Why are the extra ML features optional, and why tracker discovery first?

The project's claims rest on the resolver, its security and privacy features, and the two core detectors. Each optional extension is roughly 3–4 weeks of work, so committing to them up front would put the core at risk. They are designed now so they can be added cleanly if time allows.

**O1 goes first** because it strengthens the most user-visible feature (ad and tracker blocking) against its main weakness (blocklist lag), asks a genuine research question (how far DNS-only tracker detection can go), reuses the crawler already built for E12, and runs offline, so it cannot hurt query latency or stability. **O2** is next because it is cheap: it reuses the DGA pipeline. **O3** comes after because its benefit is the least certain. **DNSSEC (O4)** is last because it is the largest piece of work.

### Alternatives considered

| Alternative | Why not chosen |
|---|---|
| Extend Pi-hole or Unbound | Would teach configuration, not protocol; much of the logic already exists and would not be ours |
| Use a DNS library (ldns, dnspython) for parsing | Parsing is a core learning goal and a security hotspot we want to own and fuzz |
| Forwarding-only design | Blocks privacy, poisoning, bailiwick and QNAME-min work (D2) |
| Detect tunnels with fixed thresholds only | Easy to evade by slowing down; kept as a baseline in E8 |
| Large transformer models for DGA | Latency, data size and explainability (D7) |
| Blocking all TXT queries | Breaks legitimate services (email verification, SPF lookups); behaviour-based detection is better |
| Pure ns-3 simulation of DNS | Would test a model of our resolver, not the resolver (D18) |
| UnetStack | Simulates underwater acoustic networks; irrelevant to DNS |

---

## 13. Limitations and Honest Trade-offs

We state these openly; they are part of the defence, not weaknesses to hide.

1. **No DNSSEC means no protection against on-path upstream attackers.** Our anti-spoofing defences address off-path attackers only. DNSSEC is a stretch goal (§7.9).
2. **Clients can bypass us.** Apps with hard-coded DoH servers or VPNs never touch our resolver. Mitigation (outside scope): firewall rules blocking outbound 53/853 and known DoH endpoints.
3. **ML can be evaded.** Dictionary-based DGAs look like real words; very slow tunnels look like normal traffic. We raise attacker cost and report our blind spots experimentally.
4. **False positives exist.** Some legitimate services use DNS in unusual ways. Mitigations: allowlists, monitor-only mode, time-limited blocks, explainable alerts.
5. **Upstream DNS stays unencrypted.** Authoritative servers don't generally support encryption; QNAME minimisation reduces what they see.
6. **Single-node design.** No high availability or clustering; a failure of the host stops DNS for the network. Clients can be given a secondary resolver.
7. **Logs are sensitive.** A DNS log reveals browsing history. We provide retention limits, anonymisation and per-client opt-out.
8. **Performance.** We do not expect to match Unbound's throughput; we measure the gap and explain its causes.
9. **Models and simulations simplify reality.** The analytical models assume Poisson arrivals and independent attack windows; ns-3 link models approximate real links; our lab hierarchy is simpler than the internet. We cross-check each against measurements and state the assumptions (EVALUATION.md §10).

---

## 14. Project Plan: Team, Timeline, Milestones

### Roles (4 members)

| Member | Owns | Also contributes to |
|---|---|---|
| **M1 — Protocol lead** | Wire parser/builder, iterative resolver, TCP/EDNS0, QNAME minimisation | Fuzzing, test frameworks, ns-3 help; E1, E11 |
| **M2 — Performance lead** | Event loop, cache (TTL, negative, serve-stale, prefetch), in-flight dedup | Benchmark harness, models A2/A3, **ns-3 S1–S3**; E2, E3, E4, E14 |
| **M3 — Security lead** | Anti-spoofing, policy engine, rebinding, RRL, DoT/DoH, attack lab | Lab DNS hierarchy, Mininet lab, model A1; E5, E6, E10, E12, E13 |
| **M4 — ML & observability lead** | Datasets, DGA + tunnel models, fusion, analyser, dashboard | Real traffic trace W1; E7, E8, E9 |

**Optional extensions (if built):** O1 tracker discovery — M3 (crawler and data) with M4 (model); O2 look-alike detector — M1 (punycode/IDN handling is protocol work) with M4 reviewing the model; O3 learned prefetching — M2 (owns the cache).

Everyone: code review each other's modules, write their section of the report, and be able to explain the whole system.

*(For a team of 3: merge M2 into M1 and M3.)*

### Timeline (14 weeks)

| Weeks | Milestone | Deliverable / demo |
|---|---|---|
| 1–3 | **Theory + skeleton** | LEARNING_PATH (incl. simulation & modelling); repo, CI, test frameworks; parser handles real captured packets; lab DNS hierarchy and Mininet lab started |
| 3–5 | **M-A: Working resolver** | Iterative resolution from root over UDP; basic cache; `dig @localhost example.com` works; benchmark harness; real trace W1 collection starts |
| 5–7 | **M-B: Robust core** | TCP fallback, EDNS0, negative caching, SRTT server selection, in-flight dedup; E1 passing; fuzzing started; **models A1–A3 under way (done by week 8)**; ML datasets built |
| 6 | **Targets frozen** | Experiment hypotheses and success criteria reviewed and committed (EVALUATION.md §9) |
| 7–9 | **M-C: Security & policy** | Blocklists + CNAME check, rebinding, ACL, RRL, TXID/port/0x20/bailiwick hardening; poisoning lab working; ns-3 emulation setup and S1 prototype |
| 9–10 | **M-D: Privacy & ML integration** | DoT/DoH listeners, QNAME minimisation; DGA model in fast path; analyser with tunnel + NXDOMAIN detectors; dynamic rules |
| 11 | **M-E: Observability** | Metrics, logs, dashboard with explainable alerts; serve-stale and prefetch |
| 9–13 | **Optional queue (gated)** | Only if M-C is complete by the end of week 9 and later milestones are on track. **O1 first:** crawler (shared with E12) in week 9, embeddings and classifier in weeks 10–11, candidate review flow and E15 in weeks 12–13. Then O2, then O3, then O4 (DNSSEC), each only if the previous one is done and time remains |
| 10–13 | **Evaluation** | All core experiments (E1–E14, S1–S3) run against frozen targets; optional experiments (E15–E17) for whatever optional items were built; figures generated; bug fixing |
| 10–14 | **Report** | Chapters written alongside (design and literature early, results as experiments finish) |
| 14 | **Final** | Final figures, report, demo script, viva preparation |

### Demo script (final presentation, ~10 minutes)

1. Point a phone (Android Private DNS / DoT) and a laptop (DoH) at DNSentinel; show pages loading and ads disappearing.
2. Show a CNAME-cloaked tracker being caught, with its chain on the dashboard.
3. Run the poisoning attack against weak mode (succeeds) and hardened mode (fails); show the counter of spoofing attempts.
4. Start an iodine tunnel from the "infected" namespace; show the alert, its feature explanation, and the automatic block.
5. Run the DGA simulator; show NXDOMAIN burst + DGA scores → client flagged.
6. Cut the upstream link; show serve-stale keeping recent sites working.
   - *If O1 was built:* show the nightly candidate list with a newly discovered tracker, its evidence, and approving it into the blocklist.
7. Close with the headline graphs: poisoning cost measured vs model (F6), cache hit ratio vs theory (F3), and privacy cost across simulated link types (F7). Figure IDs refer to EVALUATION.md §11.

---

## 15. Viva Preparation: Questions We Expect

**Q: Why does DNS use UDP instead of TCP?**
Most queries and answers fit in one packet; UDP avoids the 3-way handshake, so a lookup is one round trip. TCP is used when responses are large (TC bit), for zone transfers, and as an anti-spoofing measure.

**Q: What exactly is a Kaminsky attack and how do you stop it?**
The attacker triggers queries for random non-existent subdomains (`abc123.bank.com`), so there is always a fresh, uncached query to race against, and floods forged responses containing a malicious referral for `bank.com`. We stop it by making responses unguessable (random ID + random port + 0x20), rejecting out-of-bailiwick data, ranking cache data by trust, and falling back to TCP when we detect a flood of mismatched responses. DNSSEC is the complete fix.

**Q: What is bailiwick?**
The zone a server is authoritative for. We only accept records from a server if they fall inside the zone we asked it about.

**Q: Why cache negative answers? Won't a domain that gets registered stay broken?**
Negative TTLs come from the zone's SOA and are usually short (minutes to hours), so the effect is bounded. Without negative caching, typos and malware lookups would hammer upstream servers.

**Q: Your DGA model gets 99% accuracy. Why should we believe it?**
We don't report accuracy alone. We report per-family precision and recall, performance on families never seen in training, and false positives per day on our own real browsing. We also show where it fails (dictionary DGAs).

**Q: Can't an attacker just tunnel slowly to avoid detection?**
Yes, and we measure the rate at which detection stops working. Slowing a tunnel to that rate severely limits how much data can be exfiltrated, which is itself a meaningful defence outcome.

**Q: How is DoH different from DoT? Why support both?**
Both encrypt DNS with TLS. DoT uses a dedicated port (853), easy to identify and block; Android uses it natively. DoH looks like normal HTTPS on port 443, is used by browsers, and is harder to block. Supporting both covers phones and browsers.

**Q: Doesn't QNAME minimisation break things?**
Rarely, with non-compliant servers. We follow RFC 9156's fallback behaviour and measure the latency and failure impact.

**Q: What happens if your resolver goes down?**
All DNS on the network stops, a stated limitation. Clients can be configured with a secondary resolver. Serve-stale protects against *upstream* failure, not our own.

**Q: How does the DGA classifier avoid flagging CDN names like `d3kx9vq.cloudfront.net`?**
We classify only the registrable domain (`cloudfront.net`) and never score allowlisted popular domains.

**Q: How do you prevent your own resolver from being used in a DDoS?**
Only LAN clients are answered, and response rate limiting drops or truncates repeated responses to the same network, forcing legitimate clients to TCP where spoofing is impossible.

**Q: Your poisoning attack at full entropy would take months. How can you claim the defence works?**
We built a probability model of the attack, then measured attacks at deliberately reduced entropy (6–12 bits) where they succeed quickly. The measurements matched the model's predictions, so we use the validated model to extrapolate to full entropy, and we also ran the full-entropy attack for a fixed budget with zero successes.

**Q: Why use ns-3 if you have a real implementation?**
ns-3 gives us link conditions we can't create on a laptop, such as Wi-Fi with many contending stations or satellite delay, while our real binary handles real packets. We also cross-checked the simple link profiles against `tc netem` to see where the richer model matters.

**Q: How do you know your results aren't just tuned to look good?**
Hypotheses and success criteria were frozen in a dated commit before the final runs, test sets were never used for tuning, every figure is regenerated from raw data, and missed targets are reported with explanations.

**Q: Does the ML update the blocklist when it flags something?**
Not directly. ML verdicts create time-limited rules in a separate table that the fast path checks first; they expire on their own. A domain only enters the permanent blocklist when a person confirms the alert on the dashboard, or, if O1 is built, when its candidate list is approved. This protects the blocklist from model mistakes and from attackers trying to trigger false blocks.

**Q: What would you do with more time?**
Complete DNSSEC (including NSEC3), encrypted upstream where authoritative servers support it, active-active redundancy, and online learning for the ML models with human feedback from the dashboard.

---

## 16. Getting Started (Planned Interface)

*This section describes the intended interface; it will be updated as the implementation lands.*

### Build

```bash
git clone <repo-url> dnsentinel && cd dnsentinel
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

### Run

```bash
# Port 53 needs privileges; grant the capability instead of running as root
sudo setcap 'cap_net_bind_service=+ep' build/dnsentinel
certs/make_certs.sh                       # lab CA + server certificate for DoT/DoH (git-ignored)
./build/dnsentinel --config config/dnsentinel.yaml

# Test
dig @127.0.0.1 example.com A
dig @127.0.0.1 +tls +tls-ca=certs/ca.crt +tls-hostname=localhost example.com   # DoT
kdig @127.0.0.1 +https example.com        # DoH
```

### Example configuration

```yaml
listen:
  udp: "0.0.0.0:53"
  tcp: "0.0.0.0:53"
  dot: { addr: "0.0.0.0:853", cert: certs/server.crt, key: certs/server.key }
  doh: { addr: "0.0.0.0:443", path: "/dns-query", cert: certs/server.crt, key: certs/server.key }

access:
  allow: ["127.0.0.0/8", "192.168.0.0/16", "10.0.0.0/8"]

resolver:
  mode: recursive            # or: forward (baseline only)
  root_hints: config/named.root
  qname_minimisation: true
  edns_buffer: 1232
  use_0x20: true
  max_upstream_queries: 30

cache:
  max_memory_mb: 256
  max_ttl: 86400
  serve_stale: { enabled: true, stale_ttl: 30, max_stale_age: 86400 }
  prefetch: true

policy:
  blocklists: [lists/ads.txt, lists/trackers.txt, lists/malware.txt]
  allowlist: lists/allow.txt
  check_cname_chain: true
  rebinding_protection: { enabled: true, exempt: ["home", "lan"] }
  block_response: null_ip    # null_ip | nxdomain

rate_limit:
  per_client_qps: 100
  rrl: { responses_per_second: 10, slip: 2 }

ml:
  mode: monitor              # monitor | enforce
  dga: { model: models/dga_rf.cpp, threshold: 0.9, skip_top_n: 100000 }
  analyzer_socket: /run/dnsentinel/events.sock

telemetry:
  prometheus: "127.0.0.1:9153"
  query_log: { enabled: true, retention_days: 7, anonymise_clients: false }
```

---

## 17. Glossary

| Term | Meaning |
|---|---|
| **Authoritative server** | Server holding the actual records for a zone |
| **Bailiwick** | The zone a server is authoritative for; data outside it is not trusted |
| **CNAME cloaking** | Hiding a third-party tracker behind a first-party subdomain alias |
| **DGA** | Domain Generation Algorithm: malware technique generating many pseudo-random domains |
| **DoH / DoT** | DNS over HTTPS / DNS over TLS |
| **EDNS0** | Extension mechanism allowing larger UDP messages and extra flags |
| **eTLD+1** | Registrable domain: public suffix plus one label (`example.co.uk`) |
| **Glue record** | IP address of a name server, supplied in a referral |
| **Negative caching** | Caching "does not exist" answers |
| **NXDOMAIN** | Response code: name does not exist |
| **QNAME minimisation** | Sending each server only the part of the name it needs |
| **Referral** | Response pointing to the name servers of a child zone |
| **RRL** | Response Rate Limiting: anti-amplification measure |
| **Serve-stale** | Answering with expired data when upstream resolution fails |
| **SRTT** | Smoothed round-trip time estimate per server |
| **Stub resolver** | Simple client resolver in the OS |
| **TTL** | Time to live: how long a record may be cached |
| **Tunnelling (DNS)** | Encoding arbitrary data inside DNS queries/responses |
| **Zone cut** | Point in the tree where authority is delegated to a child zone |
| **0x20 encoding** | Randomising letter case in queries to add anti-spoofing entropy |

---

## 18. References

### Standards (RFCs)

- RFC 1034 — Domain Names: Concepts and Facilities
- RFC 1035 — Domain Names: Implementation and Specification
- RFC 2181 — Clarifications to the DNS Specification (trust ranking, §5.4.1)
- RFC 2308 — Negative Caching of DNS Queries
- RFC 4033, 4034, 4035 — DNS Security Extensions (DNSSEC)
- RFC 5452 — Measures for Making DNS More Resilient against Forged Answers
- RFC 6891 — Extension Mechanisms for DNS (EDNS(0))
- RFC 7766 — DNS Transport over TCP: Implementation Requirements
- RFC 7858 — DNS over TLS
- RFC 8484 — DNS Queries over HTTPS (DoH)
- RFC 8767 — Serving Stale Data to Improve DNS Resiliency
- RFC 9156 — DNS Query Name Minimisation to Improve Privacy

### Papers and technical material

- D. Kaminsky, "Black Ops 2008: It's the End of the Cache As We Know It", Black Hat USA 2008.
- D. Dagon et al., "Increased DNS Forgery Resistance Through 0x20-Bit Encoding", ACM CCS 2008.
- Y. Afek, A. Bremler-Barr, L. Shafir, "NXNSAttack: Recursive DNS Inefficiencies and Vulnerabilities", USENIX Security 2020.
- Y. Dimova et al., "The CNAME of the Game: Large-scale Analysis of DNS-based Tracking Evasion", PETS 2021.
- D. Plohmann et al., "A Comprehensive Measurement Study of Domain Generating Malware", USENIX Security 2016.
- J. Woodbridge et al., "Predicting Domain Generation Algorithms with Long Short-Term Memory Networks", arXiv 2016.
- V. Le Pochat et al., "Tranco: A Research-Oriented Top Sites Ranking Hardened Against Manipulation", NDSS 2019.
- G. Engelen, V. Rimmer, W. Joosen, "Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study", IEEE SPW 2021.
- X. Man et al., "DNS Cache Poisoning Attack Reloaded: Revolutions with Side Channels" (SAD DNS), ACM CCS 2020.
- J. Jung, E. Sit, H. Balakrishnan, R. Morris, "DNS Performance and the Effectiveness of Caching", ACM IMW 2001 / IEEE/ACM Transactions on Networking 2002.
- J. Jung, A. W. Berger, H. Balakrishnan, "Modeling TTL-based Internet Caches", IEEE INFOCOM 2003.
- L. Breslau et al., "Web Caching and Zipf-like Distributions: Evidence and Implications", IEEE INFOCOM 1999.
- D. Arp et al., "Dos and Don'ts of Machine Learning in Computer Security", USENIX Security 2022.
- *Optional extensions:* Arora et al., "Dns2Vec: Exploring Internet Domain Names through Deep Learning", USENIX ScAINet 2019 · U. Iqbal et al., "AdGraph: A Graph-Based Approach to Ad and Tracker Blocking", IEEE S&P 2020 · S. Siby et al., "WebGraph: Capturing Advertising and Tracking Information Flows for Robust Blocking", USENIX Security 2022 · DuckDuckGo Tracker Radar (open dataset) · Unicode Technical Standard #39, "Unicode Security Mechanisms" · RFC 3492, "Punycode" · Piredda et al., "Deepsquatting: Learning-Based Typosquatting Detection at Deeper Domain Levels", 2017.
- DNS Flag Day 2020 — recommendations on EDNS buffer size (dnsflagday.net).

### Tools

Unbound, BIND, NSD, Pi-hole (reference implementations and lab hierarchy) · dig/kdig · dnsperf/resperf (DNS-OARC) · Scapy · iodine · dnscat2 · Singularity of Origin · Playwright · dnstwist · Wireshark · libFuzzer/AFL++ · scikit-learn · PyTorch · ONNX Runtime · Prometheus · Grafana · ns-3 · Mininet · MATLAB / GNU Octave.

---

*DNSentinel — understand every byte, defend every query.*