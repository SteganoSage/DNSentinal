# DNSentinel — Complete Implementation Plan

> Everything you need to know to build every module, in every phase, without writing a single line of code here. This document explains **what** each component does, **how** it works internally, **why** each design decision exists, **what pitfalls** to avoid, and **how** everything connects.

---

## Table of Contents

1. [Project Overview & Architecture Recap](#1-project-overview--architecture-recap)
2. [Phase 1 — Foundation (Weeks 1–2)](#2-phase-1--foundation-weeks-12)
3. [Phase 2 — Working Resolver (Weeks 3–4)](#3-phase-2--working-resolver-weeks-34)
4. [Phase 3 — Robust Core (Weeks 5–6)](#4-phase-3--robust-core-weeks-56)
5. [Phase 4 — Security & Policy (Weeks 7–8)](#5-phase-4--security--policy-weeks-78)
6. [Phase 5 — Privacy & ML Integration (Weeks 9–10)](#6-phase-5--privacy--ml-integration-weeks-910)
7. [Phase 6 — Observability (Week 11)](#7-phase-6--observability-week-11)
8. [Phase 7 — Evaluation (Weeks 12–13)](#8-phase-7--evaluation-weeks-1213)
9. [Phase 8 — Final (Week 14)](#9-phase-8--final-week-14)
10. [Cross-Cutting Concerns](#10-cross-cutting-concerns)
11. [Risk Register & Contingencies](#11-risk-register--contingencies)

---

## 1. Project Overview & Architecture Recap

DNSentinel is a **recursive DNS resolver built from scratch in C++20** that sits between devices on a local network and the internet. It resolves names by walking the DNS delegation tree itself (not forwarding), and layers security, privacy, and machine learning on top.

### The Two-Path Architecture

Every query flows through two parallel paths:

**Fast path (synchronous, blocks the response):**
```
Client query → ACL check → Rate limit → Dynamic rules → Blocklist lookup
→ DGA classifier (cached per domain) → Cache lookup → [miss] → Resolver
→ Post-resolution checks (CNAME chain, rebinding) → Response
```
The fast path must add **< 1ms** of latency. Everything here is C++ and runs in the event-loop thread.

**Slow path (asynchronous, never blocks):**
```
Every query+response event → in-memory ring buffer → Unix socket
→ Python analyzer service → Tunnel detector (60s sliding windows)
                          → NXDOMAIN burst detector
                          → Score fusion → If high risk: push dynamic
                            block rule back to the fast-path policy engine
```
The slow path receives a **copy** of events and processes them out-of-band. Detection delay is seconds, not milliseconds, and that's acceptable because tunnelling can only be identified over time.

### Module Dependency Order

This is the order modules must be built. Each depends on the ones above it:

```
1. types.h (core data structures)
2. wire/parser + wire/builder (parse and build DNS packets)
3. net/event_loop + net/udp_listener (receive and send UDP packets)
4. resolver/recursive_resolver (walk the delegation tree)
5. cache/cache (store and retrieve answers)
6. security/* (harden upstream queries)
7. policy/* (filter queries and responses)
8. net/tcp_listener (TCP transport)
9. net/dot_listener + net/doh_listener (encrypted transports)
10. ml/dga_classifier (fast-path ML inference)
11. telemetry/event_bus (feed the slow path)
12. analyzer/* (Python slow-path detectors)
13. telemetry/metrics + query_log + dashboard
```

---

## 2. Phase 1 — Foundation (Weeks 1–2)

### 2.1 Module: Core Types (`types.h`)

**What it is:** The shared vocabulary of every module. Every other file includes this.

**What to implement:**

- **`Name`** — A DNS name is a sequence of labels. On the wire, each label is a length byte followed by that many characters, terminated by a zero-length label. Example: `www.example.com.` is `\x03www\x07example\x03com\x00`.

  The `Name` struct must store TWO representations:
  - `labels` — canonical (all lowercase) for comparison, hashing, and cache keys. DNS is case-insensitive per RFC 1035 §2.3.3, so `WWW.EXAMPLE.COM` and `www.example.com` are the same name.
  - `original_case` — preserves the exact case as received or as randomised. This is critical for 0x20 encoding (Phase 4): we send `wWw.ExAmPlE.cOm` and verify the response echoes that exact case. Without original_case, 0x20 cannot work.

  Methods needed:
  - `to_string()` → `"www.example.com."` (dot-joined, trailing dot)
  - `wire_length()` → sum of `(1 + label.size())` for each label, plus 1 for the trailing `\x00`
  - `operator==` compares canonical (lowercase) labels only
  - A hash function (for `std::unordered_map`) that hashes the canonical form

  **Pitfall:** Labels are limited to 63 bytes each, and a full name on the wire is limited to 255 bytes. These must be enforced at parse time, not in the Name constructor, because Name also gets built programmatically (e.g. when building a query).

- **`Header`** — Exactly 12 bytes on the wire. The struct should have named fields for every flag:
  - `id` (16 bits): transaction ID, used to match responses to queries
  - `qr` (1 bit): 0 = query, 1 = response
  - `opcode` (4 bits): 0 = standard query (the only one we handle)
  - `aa` (1 bit): authoritative answer — set by auth servers, not by us
  - `tc` (1 bit): truncated — response didn't fit in UDP, retry over TCP
  - `rd` (1 bit): recursion desired — stubs set this; we set it when talking to forwarders but NOT when doing iterative resolution (we set rd=0 to authoritative servers)
  - `ra` (1 bit): recursion available — we set this in responses to clients
  - `ad` (1 bit): authenticated data (DNSSEC) — stretch goal
  - `cd` (1 bit): checking disabled — client asks us not to validate DNSSEC
  - `rcode` (4 bits): response code
  - `qdcount`, `ancount`, `nscount`, `arcount` (16 bits each): counts of entries in each section

  **Pitfall:** The flags byte is packed in network byte order. Bits 5–8 of the second byte are `RA, Z, AD, CD`. Many implementations get the bit layout wrong. Draw the bit diagram from RFC 1035 §4.1.1 and implement from that directly.

- **`RR` (Resource Record)** — One record: a name, type, class, TTL, and type-specific data. The RDATA field is a variant over all supported record types.

  Supported RDATA types:
  - `RDataA` — 4 bytes, an IPv4 address stored as `uint32_t` in network byte order
  - `RDataAAAA` — 16 bytes, an IPv6 address as `uint8_t[16]`
  - `RDataNS` — a `Name` (the name server's domain name)
  - `RDataCNAME` — a `Name` (the canonical name this alias points to)
  - `RDataSOA` — two Names (MNAME, RNAME) plus 5 uint32_t fields (serial, refresh, retry, expire, minimum). The `minimum` field is used for negative caching TTL.
  - `RDataMX` — a 16-bit preference value plus a `Name`
  - `RDataTXT` — a vector of strings. On the wire, TXT RDATA is one or more `<length><chars>` segments.
  - `RDataPTR` — a `Name` (for reverse lookups)
  - `RDataRaw` — fallback for any type we don't parse specifically. Just store the raw bytes.

  Each RR also carries a `TrustRank` (from RFC 2181 §5.4.1):
  - `Answer` (highest) — from the answer section of an authoritative response
  - `Authority` — from the authority section
  - `Glue` — glue records in a referral (IP of a name server in the delegation)
  - `Additional` (lowest) — unsolicited data in the additional section

  **Why trust rank matters:** A poisoning attack can sneak fake records into the additional section of a legitimate response. If we blindly cache those and later serve them, the attacker wins. Trust ranking prevents lower-ranked data from overwriting higher-ranked data in the cache. This is implemented in the cache module (Phase 3) but the rank values must be defined here.

- **`Question`** — A query: qname (Name), qtype (uint16), qclass (uint16, almost always 1 = IN).

- **`EdnsInfo`** — Extracted from the OPT pseudo-record in the additional section:
  - `udp_payload_size` — the maximum UDP response size the sender can handle (default 512 without EDNS)
  - `extended_rcode` — upper 8 bits of the response code (combined with the 4-bit rcode in the header)
  - `version` — EDNS version (must be 0; reject if not)
  - `dnssec_ok` — the DO bit; client wants DNSSEC data

- **`Message`** — The complete DNS message: header, vectors of questions/answers/authority/additional, plus an optional EdnsInfo extracted from the OPT record.

### 2.2 Module: Wire Parser (`wire/parser.cpp`)

**What it is:** The most security-critical module in the entire project. It takes raw bytes from the network — which could be **anything** an attacker sends — and produces a structured `Message`, or rejects the input.

**What to implement, in detail:**

**Step 1: Parse the header (first 12 bytes).**
- Check that the buffer is at least 12 bytes. If not → `BufferTooShort`.
- Read the 16-bit ID (bytes 0–1, big-endian).
- Unpack the flags from bytes 2–3. This is bit manipulation:
  ```
  Byte 2: QR(1) | Opcode(4) | AA(1) | TC(1) | RD(1)
  Byte 3: RA(1) | Z(1) | AD(1) | CD(1) | RCODE(4)
  ```
- Read the four 16-bit counts (QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT) from bytes 4–11.
- **Sanity check the counts** against the remaining buffer size. If the header claims 65535 answer records but the buffer is only 40 bytes, reject immediately. A rough check: each record is at least ~11 bytes (1-byte name pointer + 10 bytes of type/class/TTL/rdlength), so `(ancount + nscount + arcount) * 11` must not exceed `buffer.size() - 12`. This is a **safety heuristic**, not an exact check.

**Step 2: Parse the question section.**
- For each of the `qdcount` questions (almost always 1):
  - Parse a name (see below)
  - Read 2 bytes for qtype, 2 bytes for qclass
- If qclass is not 1 (IN) and not 255 (ANY), it's unusual but valid. Log it.

**Step 3: Parse each section (answer, authority, additional).**
- For each record:
  - Parse the name
  - Read type (2 bytes), class (2 bytes), TTL (4 bytes), rdlength (2 bytes)
  - Read exactly `rdlength` bytes of RDATA
  - For known types (A, AAAA, NS, CNAME, SOA, MX, TXT, PTR), parse the RDATA into the typed struct. For A, rdlength must be exactly 4. For AAAA, exactly 16. For NS/CNAME/PTR, the RDATA contains a compressed name. For SOA, two names plus 5 uint32s. **If rdlength doesn't match what we parsed, that's `RDataLengthMismatch`.**
  - For unknown types, store as `RDataRaw`.
  - If the record type is OPT (41), extract EDNS info: the class field is actually the UDP payload size, the TTL field encodes extended-rcode/version/DO-bit, and RDATA contains EDNS options. Store this in `Message::edns` and do **not** add the OPT record to the `additional` vector.

**Step 4: Name parsing — the hard part.**

A DNS name on the wire is a sequence of labels, each preceded by a length byte. There are three cases for the length byte:
- **0**: end of name (the root label)
- **1–63** (top two bits are `00`): a label of that length follows
- **Top two bits are `11`**: this is a **compression pointer**. The remaining 14 bits are an offset from the start of the message where the rest of the name can be found.
- **Top two bits are `01` or `10`**: reserved/obsolete label types. **Reject immediately** (`InvalidLabelType`).

Compression pointers create a directed graph within the message. A malicious message can create loops:
```
Offset 12: C0 0C    (pointer to offset 12 — points to itself)
```
Or mutual pointers:
```
Offset 12: C0 14    (pointer to offset 20)
Offset 20: C0 0C    (pointer to offset 12)
```

**Safety rules for name parsing:**
1. **Pointers must point strictly backwards** (to a lower offset than the current position). This is not required by the RFC but is the safest implementation and is what Unbound does. Forward pointers are rare in legitimate traffic and are a common attack vector.
2. **Maximum 128 pointer jumps per name.** Even with the backwards-only rule, deeply nested (but non-looping) pointers could waste CPU. 128 is generous; real names have 0–3 pointers.
3. **Each label ≤ 63 bytes.** The length byte's top two bits are `00`, so the max is 63.
4. **Total name ≤ 255 bytes on the wire** (sum of all `1 + label_length` plus the trailing zero).
5. **All reads bounds-checked.** Before reading a length byte, a label's characters, or following a pointer, verify that the offset is within the buffer. Every. Single. Time.

When parsing a name, keep track of two things:
- The **current offset** in the buffer (where we're reading labels from)
- The **original offset** (where name parsing started) — needed to know where to resume after following a pointer. After the first pointer jump, the "return position" is right after that pointer (2 bytes). Subsequent pointer jumps don't change the return position.

Store labels in both canonical (lowercase) and original-case form as you parse them.

**Why this matters so much:** Buffer over-reads and infinite loops in DNS name parsing have been the source of CVEs in BIND, dnsmasq, and systemd-resolved. This module will be **fuzzed** — it must not crash, hang, or read out of bounds on any input.

### 2.3 Module: Wire Builder (`wire/builder.cpp`)

**What it is:** The reverse of the parser. Takes a `Message` struct and produces bytes ready to send on the wire.

**What to implement:**

**Name compression:**
- Maintain a map of `name_suffix → offset` during building. When writing a name, check if any suffix of the name has been written before. If so, write the new labels up to the suffix, then write a compression pointer.
- Example: After writing `www.example.com` at offset 12, the map contains:
  - `www.example.com` → 12
  - `example.com` → 16
  - `com` → 24
  
  When later writing `mail.example.com`, write `\x04mail` then a pointer to offset 16.
- **Pointer offsets must fit in 14 bits** (max offset 16383). If a suffix was written past that offset, don't compress it.

**Truncation (TC bit):**
- The builder is given a maximum size (512 bytes default, or the client's EDNS0 buffer size).
- Write the header, question, then records section by section. If at any point the next **complete record set** (all records with the same name and type) would exceed the limit:
  - Stop adding records
  - Set the `TC` bit in the header
  - Return what we have so far
- Truncation at a record-set boundary is important — a partial RRset is worse than no RRset.

**TCP framing:**
- For TCP/DoT, prepend a 2-byte big-endian length before the message bytes. No size limit (TCP can carry up to 65535-byte messages).

**Round-trip testing:** The parser and builder must satisfy `parse(build(msg)) == msg` for every well-formed message. Build a comprehensive test suite with captured real packets from Wireshark/tcpdump.

### 2.4 Module: EDNS0 Handling (`wire/edns.cpp`)

**What it is:** EDNS0 (RFC 6891) extends DNS with an OPT pseudo-record in the additional section. It's not a real record — it carries metadata about the sender's capabilities.

**What to implement:**
- **Parsing:** When the parser encounters a record with type 41 (OPT) in the additional section:
  - The "class" field is actually the sender's UDP payload size (how big a UDP response they can handle)
  - The "TTL" field encodes: extended-rcode (8 bits), version (8 bits), DO flag (1 bit), reserved (15 bits)
  - RDATA contains zero or more EDNS options (we can ignore these initially)
  - Extract all this into `EdnsInfo` on the Message, and **do not** add the OPT to the additional records vector (it's metadata, not data)

- **Building:** When building a response:
  - If the client sent an OPT, include our own OPT in the response (UDP payload size = 1232, version 0)
  - If the client did NOT send an OPT, cap our response at 512 bytes

- **Upstream queries:** Always include an OPT advertising a 1232-byte buffer. This is the DNS Flag Day 2020 recommendation — it avoids IP fragmentation on virtually all paths. Fragmented UDP responses are unreliable (firewalls drop fragments) and a known poisoning vector (later fragments don't carry the DNS ID or port).

### 2.5 Setup: Build System, CI, Lab

**CMake build:**
- The CMakeLists.txt is already created. It compiles the core library as a static lib, links OpenSSL and pthreads, and has toggles for DoT, DoH, ML, tests, fuzz, and sanitizers.
- Set up **clang-format** with a `.clang-format` file for consistent style.
- Set up **GitHub Actions CI**: build with GCC and Clang, run tests, run with ASan+UBSan.

**Lab namespaces:**
- Create a shell script (`lab/namespaces/setup_lab.sh`) that creates Linux network namespaces:
  - `ns-resolver` — runs DNSentinel
  - `ns-client1`, `ns-client2` — normal clients
  - `ns-infected` — will run DGA simulator and tunnel client
  - `ns-attacker` — will run Scapy poisoning scripts
  - `ns-fakeauth` — our own authoritative server for poisoning tests
- Connect them with virtual ethernet pairs (`veth`) and bridges
- Add `tc netem` rules to simulate realistic latency (e.g. 20ms to "upstream")

**DGA dataset collection (M4 starts in parallel):**
- Download the Tranco top-1M list (benign domains)
- Run open-source DGA family reimplementations to generate malicious domain names
- Document data provenance in `ml/data/README.md`

---

## 3. Phase 2 — Working Resolver (Weeks 3–4)

### 3.1 Module: Event Loop (`net/event_loop.cpp`)

**What it is:** The heart of the networking layer. An `epoll`-based event loop that multiplexes thousands of sockets without threads-per-connection.

**How it works:**

1. Create an epoll instance with `epoll_create1(0)`.
2. Register file descriptors (sockets) with `epoll_ctl(EPOLL_CTL_ADD, fd, events)`.
3. In the main loop, call `epoll_wait()` which blocks until one or more registered FDs are ready.
4. For each ready FD, call the associated callback (read handler, write handler, timer).

**Design decisions:**

- **One event loop per CPU core.** Use `SO_REUSEPORT` on the UDP listening socket so the kernel distributes incoming packets across multiple processes/threads, each with their own epoll loop. This avoids cross-thread coordination on the hot path.
  
  For the initial implementation (weeks 3–4), **start with a single thread**. Multi-core scaling is an optimisation for Phase 3 or later. Getting a single-threaded event loop correct first is essential.

- **Timer management.** Upstream DNS queries have timeouts (800ms initial, exponential backoff). Use `timerfd_create()` to get a timer FD that integrates with epoll, or maintain a sorted timer heap and compute the next `epoll_wait` timeout from the earliest pending timer.

- **Callback registration.** Each FD needs an associated handler. Use a map from FD → callback (a `std::function` or a virtual method on a handler interface). When epoll reports FD N is readable, look up and call its handler.

**What the event loop manages:**
- The UDP listening socket (read → parse query → process → send response)
- Upstream UDP sockets (one per outstanding query to an authoritative server)
- Later: TCP listening socket, connected TCP sessions, DoT/DoH sessions

**Pitfall:** `epoll_wait` can return `EINTR` if a signal is delivered. Always retry on `EINTR`. Also, a socket reported as readable might return `EAGAIN` / `EWOULDBLOCK` on `recvfrom` if another thread consumed the data (with `SO_REUSEPORT`). Handle this gracefully.

### 3.2 Module: UDP Listener (`net/udp_listener.cpp`)

**What it is:** Listens on UDP port 53, receives queries from clients, dispatches them through the processing pipeline, and sends responses.

**What to implement:**

1. **Create socket:** `socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0)`. Set `SO_REUSEADDR` and `SO_REUSEPORT`. Bind to `0.0.0.0:53`.

2. **Receive queries:** On readable event, call `recvfrom()` to get the packet bytes and the client's address (IP + port). Pass the bytes to `wire::parse()`. If parsing fails, drop the packet silently (do not respond to garbage — it could be an amplification vector).

3. **Process the query:** This is where the fast-path pipeline runs (ACL → rate limit → blocklist → DGA → cache → resolver → post-checks). In Phase 2, this is simplified: just cache lookup → resolver → cache insert → respond.

4. **Send response:** Call `wire::build()` with the client's EDNS buffer size (or 512), then `sendto()` the bytes to the client's address.

**Important detail: `recvmmsg` / `sendmmsg`.** These Linux-specific syscalls process multiple packets per syscall, reducing kernel crossing overhead. Use them for performance, but they're an optimisation — start with `recvfrom`/`sendto` and switch later if needed.

**Important detail: source address.** When the resolver host has multiple IP addresses, the response must be sent from the same IP the query arrived on. Use `IP_PKTINFO` with `recvmsg`/`sendmsg` to learn and control the local address. This is fiddly but necessary for correct behaviour.

### 3.3 Module: Iterative Recursive Resolver (`resolver/recursive_resolver.cpp`)

**What it is:** The core algorithm. Given a question not in cache, find the answer by walking the DNS delegation tree from the root servers down to the authoritative server.

**The algorithm, step by step:**

```
resolve(qname, qtype):
    // Find the closest zone cut we already know about
    zone_cut ← deepest ancestor of qname for which we have cached NS records
               (if nothing cached, use root from root hints)
    
    upstream_queries_used ← 0
    
    LOOP (guard: max 30 upstream queries, max depth 16 referrals):
        // Get the name server IPs for this zone
        servers ← IP addresses of NS records for zone_cut
                   (if we have names but not IPs, resolve the NS names
                    as sub-queries — carefully, see below)
        
        // Pick the best server to ask
        server ← pick_best(servers)   // lowest SRTT, with exploration
        
        // Send the query
        query ← build_query(qname, qtype)  // with random ID, from random port
        send query to server
        upstream_queries_used++
        
        // Wait for response (with timeout)
        response ← wait(timeout = 800ms initially, exponential backoff)
        
        IF timeout or network error:
            penalise server SRTT (add large penalty, e.g. 2000ms)
            try next server in the list
            IF all servers failed → return SERVFAIL
        
        IF response received:
            // Validate the response (critical for security)
            IF response.id ≠ query.id → discard, keep waiting
            IF response came from wrong IP → discard
            IF response.question ≠ query.question → discard
            IF 0x20 enabled AND case doesn't match → discard
            
            // Classify the response
            CASE: ANSWER (ancount > 0, response has answer records):
                // Bailiwick check: ensure answer records are within zone_cut
                apply_bailiwick_filter(response, zone_cut)
                cache all records with appropriate trust ranks
                
                IF answer is a CNAME and qtype ≠ CNAME:
                    // Follow the CNAME chain
                    new_qname ← CNAME target
                    cname_hops++
                    IF cname_hops > 8 → return SERVFAIL
                    restart resolve(new_qname, qtype)
                ELSE:
                    return the answer
            
            CASE: REFERRAL (ancount = 0, nscount > 0 with NS records):
                referred_zone ← the zone the NS records are for
                
                // Sanity: referral must go DEEPER toward qname
                IF referred_zone is not a proper suffix of qname
                   OR referred_zone is not below zone_cut → discard, try next server
                
                // Cache the NS records (trust rank = Authority)
                // Cache any glue IPs (trust rank = Glue, only for in-bailiwick names)
                
                zone_cut ← referred_zone
                continue LOOP
            
            CASE: NXDOMAIN (rcode = 3):
                cache negatively (using SOA in authority section)
                return NXDOMAIN to client
            
            CASE: NODATA (rcode = 0, ancount = 0, no NS referral):
                cache negatively
                return empty answer with NOERROR
            
            CASE: SERVFAIL / REFUSED:
                mark this server as bad for this zone
                try next server
```

**Critical details:**

**Root priming.** On startup, load the root hints file (`config/named.root`) which contains the 13 root server names and their IP addresses. Then send a query for `. NS` to one of them to get the **current** root NS set and cache it. This is called "priming the cache" and is done once.

**Sub-queries for NS resolution.** When a referral says "the NS for example.com is ns1.example.com" and provides glue (ns1's IP), we use the glue. But when the NS name is **out of bailiwick** (e.g. "the NS for example.com is ns1.otherdns.net"), there's no glue, and we must resolve `ns1.otherdns.net` as a separate sub-query. 

This is dangerous — an attacker can exploit this:
- **NXNSAttack (2020):** A malicious auth server returns a referral listing 1000 NS names without glue, all pointing at a victim. The resolver tries to resolve all 1000, flooding the victim with queries.
- **Mitigation:** Cap the number of glue-less NS names we resolve per referral (e.g. max 5). Log when this cap is hit.

Also, sub-queries can create cycles: resolving ns1.example.com requires asking example.com's NS, which is ns1.example.com... The resolver must detect this (track query ancestry) and break cycles with SERVFAIL.

**Server selection (SRTT).** Maintain a smoothed round-trip time per upstream server IP:
```
srtt = 0.875 * srtt + 0.125 * sample
```
This is the same exponential moving average used for TCP RTT estimation. Pick the server with the lowest SRTT, but occasionally (1 in N) try a random server to detect if a previously slow server has improved. Timeouts add a large penalty (e.g. 2000ms) to the SRTT so the resolver quickly avoids dead servers.

**Timeouts and deadlines.** Two limits:
- Per-upstream-query timeout: starts at 800ms, doubles on retry (exponential backoff), capped at ~3s
- Overall per-client-query deadline: 5 seconds. If we haven't found an answer by then, return SERVFAIL. This prevents a malicious zone from holding our resources forever.

### 3.4 Module: Basic Cache (`cache/cache.cpp`)

**What it is:** Stores resolved answers so repeated queries are answered instantly without hitting upstream servers again.

**Data structure:**

- **Key:** `(canonical_qname, qtype, qclass)` — the same question might be asked as `A` or `AAAA`, and those are separate cache entries.
- **Value:** A `CacheEntry` containing the record set, trust rank, absolute expiry time (`now + ttl`), insertion time, and hit count.
- **Organisation:** A hash map (`std::unordered_map`) per shard, plus a doubly-linked list per shard for LRU ordering.
- **Sharding:** `N` shards (e.g. 16), determined by hashing the cache key. Each shard has its own mutex and its own LRU list. This means threads operating on different shards never contend. For the single-threaded Phase 2, sharding is still worthwhile to keep the LRU lists short.

**Operations:**

- **Lookup:** Hash the key → pick shard → lock shard → find in hash map. If found and `now < expires_at`, it's a hit: move to front of LRU, increment hit count, return the entry with `ttl_remaining = expires_at - now`. If found but expired, it's a miss (but the entry stays for serve-stale, Phase 6).

- **Insert:** Hash → shard → lock → insert or update. When updating, **respect trust ranking**: if the existing entry has a higher trust rank than the new data, do NOT overwrite. This prevents a poisoning attack where an attacker sneaks records into the additional section of a legitimate response, and those records have lower trust than what we already cached.

  Apply TTL clamping: `effective_ttl = clamp(ttl, config.min_ttl, config.max_ttl)`. A max_ttl of 86400 (1 day) prevents absurdly long TTLs. A min_ttl of 0 means we respect very short TTLs (some CDNs use TTL=0 for load balancing).

- **Eviction:** When inserting would exceed the memory limit, evict the least-recently-used entry from the shard. Walk the LRU list from the tail.

- **Memory accounting:** Track approximate memory usage. Each entry costs roughly: key size (name wire length × 2 for canonical + hash + type/class) + value size (record data + metadata). Don't need to be byte-exact — an estimate is fine for eviction decisions.

---

## 4. Phase 3 — Robust Core (Weeks 5–6)

### 4.1 Module: TCP Listener (`net/tcp_listener.cpp`)

**What it is:** DNS over TCP on port 53. Used when a UDP response is truncated (TC bit), and also as a security mechanism against spoofing.

**How TCP DNS framing works:**
- Each DNS message on a TCP connection is preceded by a **2-byte big-endian length**, then the message bytes. The length does NOT include the 2-byte length field itself.
- Multiple queries can be sent on a single TCP connection (pipelining).
- Server should support an idle timeout (e.g. 10 seconds) to reclaim resources from abandoned connections.

**What to implement:**
1. **Listening socket:** `socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0)`. Bind to port 53, listen.
2. **Accept connections:** When the listening FD is readable, call `accept4()` (with `SOCK_NONBLOCK`). Register the new connection FD with epoll.
3. **Read state machine:** Each TCP connection needs a per-connection read buffer and state:
   - State 1: reading the 2-byte length prefix
   - State 2: reading `length` bytes of message data
   - When complete → parse, process, respond (same pipeline as UDP)
   - Then back to State 1 (for pipelining)
4. **Write:** Prepend the 2-byte length, write the response. Handle partial writes (`EAGAIN`): buffer the remainder and register for `EPOLLOUT`.
5. **Connection limits:** Cap the total number of TCP connections (e.g. 200) and per-client connections (e.g. 10) to prevent resource exhaustion.

**TC → TCP fallback (upstream):**
When we receive an upstream UDP response with the TC bit set, re-send the same query over TCP to the same server. This is the normal DNS fallback mechanism.

### 4.2 Module: Negative Cache (`cache/negative_cache.cpp`)

**What it is:** Caching "this name doesn't exist" (NXDOMAIN) and "this name exists but has no records of this type" (NODATA).

**How it works:**
- When an upstream server responds with NXDOMAIN or NODATA, the authority section should contain a SOA record for the zone.
- The negative cache TTL is `min(SOA record's TTL, SOA MINIMUM field)` per RFC 2308.
- Store this in the regular cache with a special `is_negative = true` flag.
- On lookup, if we find a negative entry and it hasn't expired, return NXDOMAIN or empty answer without querying upstream.

**Why it matters:**
1. **Performance:** Typos, ad-blocked domains, and broken links generate repeated NXDOMAINs. Without negative caching, each retry hits upstream.
2. **ML signal:** DGA-infected hosts generate bursts of NXDOMAINs (most generated domains are unregistered). Negative caching limits the upstream load, and the NXDOMAIN count feeds the ML detector.
3. **Not sufficient for anti-poisoning:** Kaminsky's attack works by querying random subdomains (`abc123.bank.com`) to generate fresh, uncached queries. Even with negative caching, the attacker can use subdomains the resolver hasn't seen. This is why the randomisation defences in Phase 4 are needed.

### 4.3 Module: SRTT Server Selection (`resolver/server_selection.cpp`)

**What it is:** Tracks the response time of every upstream server and picks the fastest one for each query.

**Algorithm:**
- Maintain a `std::unordered_map<IPAddress, SRTTInfo>` where `SRTTInfo` contains:
  - `srtt_us` — smoothed RTT in microseconds
  - `rttvar_us` — RTT variance (for timeout calculation, like TCP)
  - `last_success` — timestamp of last successful query
  - `failure_count` — consecutive failures

- On a successful response with measured RTT `sample`:
  ```
  rttvar = 0.75 * rttvar + 0.25 * |srtt - sample|
  srtt = 0.875 * srtt + 0.125 * sample
  ```

- On timeout: `srtt += 2000000` (2 second penalty) and increment failure count.

- **Selection:** Given a list of candidate server IPs for a zone, sort by SRTT. Pick the lowest, but with probability 1/20, pick a random one (exploration). If a server has failed 5+ times consecutively, deprioritise it heavily.

- **New servers** (no SRTT data yet) get an initial estimate of 400ms — optimistic enough that they'll be tried, but not so low that they always win over proven-fast servers.

### 4.4 Module: In-Flight Deduplication

**What it is:** If 20 clients simultaneously ask for `www.example.com A` and it's not cached, we send **one** upstream query and fan the answer out to all 20 clients.

**How to implement:**
- Maintain a map of `(qname, qtype) → PendingQuery` where `PendingQuery` contains a list of waiting clients.
- On cache miss, check the pending map. If a query for this name+type is already in flight, just add this client to the waiting list. When the response arrives, iterate the list and send the response to all.
- After the response is sent (or the query fails), remove the entry from the pending map.

**Why it matters for security:** The birthday paradox means that if we have many outstanding identical queries to the same server, an attacker has a higher chance of guessing the right ID/port combination. By coalescing, we keep at most one outstanding query per name, reducing the attack surface.

### 4.5 Experiment: E1 — Correctness

**What:** Resolve the top 10,000 domains from the Tranco list using DNSentinel and using Unbound. Compare the answer sets.

**Method:**
1. Set up Unbound as a reference resolver on the same machine
2. Script that calls `dig @dnsentinel <domain> A` and `dig @unbound <domain> A` for each domain
3. Compare: do they return the same IP addresses (or at least overlapping sets, because CDNs return different IPs based on server selection)?
4. Count: how many match, how many differ, how many SERVFAIL

**Expected outcome:** ≥98% match rate. Differences should be explainable (CDN variance, timing). Any SERVFAIL from our resolver that Unbound answers correctly is a bug to investigate.

---

## 5. Phase 4 — Security & Policy (Weeks 7–8)

### 5.1 Module: Random Source Port (`security/randomisation.cpp`)

**What it is:** For every upstream query, use a random source UDP port from the ephemeral range (1024–65535) instead of a fixed port.

**Why:** An attacker trying to spoof a response must guess the right destination port. With a fixed port, they know it. With a random port from ~32,000 possible values, they must guess, multiplying the search space by ~2^15.

**Implementation:**
- For each upstream query, create a new UDP socket, bind it to a random port (let the OS choose with `bind(0)` or explicitly pick from a randomised pool), send the query, register the socket with epoll for the response, and close it after receiving the response or timing out.
- Use `getrandom()` (Linux) or `/dev/urandom` for randomness. **Never** use `rand()`, `random()`, or any PRNG seeded with `time(NULL)` — these are predictable.
- The transaction ID (16 bits) is also generated with `getrandom()` for every query.

**Combined entropy:** Random ID (16 bits) × Random port (~15 bits) = ~2^31 combinations. An attacker must send ~2 billion forged packets to have a 50% chance, compared to ~32,000 with a fixed port.

### 5.2 Module: 0x20 Encoding (`security/zero_x20.cpp`)

**What it is:** A clever anti-spoofing trick from Dagon et al. (2008). DNS names are case-insensitive, but most servers **echo the question section exactly as received**. We randomise the case of each letter in the query name and reject responses that don't match.

**How to implement:**

1. **Encoding (outgoing query):** For each letter in the query name, flip bit 0x20 randomly:
   ```
   "www.example.com" → "wWw.ExAmPlE.cOm"
   ```
   Store the randomised name in `Name::original_case`.

2. **Verification (incoming response):** Compare the question section of the response against our stored original_case. If any character's case doesn't match, discard the response (it's likely forged — the attacker guessed the name but not the case pattern).

3. **Fallback:** A small fraction of servers or middleboxes normalise the case before echoing (they return everything lowercase). When we detect this (a mismatch that doesn't look like an attack — the response is otherwise valid), add the server to a "no-0x20" list and resend without case randomisation. Log this event.

**Entropy added:** Each letter in the name adds 1 bit. A 15-letter name like `www.example.com` adds 15 bits, bringing the total to 2^(16+15+15) ≈ 2^46 for an attacker to guess.

**Pitfall:** Only ASCII letters (A-Z/a-z) can be case-randomised. Digits, hyphens, and non-ASCII bytes are unchanged. Count only letters when computing entropy.

### 5.3 Module: Bailiwick Checking (`security/bailiwick.cpp`)

**What it is:** Ensures that an authoritative server only provides records for the zone it's authoritative for.

**The rule:** When we ask `ns1.example.com` about `www.example.com`, the server may only provide records that are **within** `example.com` (or below). If the response contains `google.com A 6.6.6.6` in the additional section, we **discard that record** — the server for `example.com` has no authority to tell us about `google.com`.

**Implementation:**
- Track the current `zone_cut` during resolution (the zone the current server is authoritative for).
- After receiving a response, filter every record in every section:
  - Answer records must have names that are `zone_cut` itself or subdomains of it
  - Authority records (NS, SOA) must be for `zone_cut` or subdomains
  - Additional records (glue): only accept if the name is within `zone_cut` (in-bailiwick glue)
- Records that fail the check are silently dropped from the response before caching.

**This defeats:** The classic attack of injecting `bank.com → attacker_ip` into the additional section of a response from `attacker.com`'s authoritative server.

### 5.4 Module: Spoof Detection → TCP Fallback

**What it is:** If we notice many responses with wrong IDs or ports arriving for an outstanding query, someone is actively trying to spoof. Switch to TCP where spoofing is impossible.

**Implementation:**
- Count mismatched responses per outstanding query (wrong ID, wrong port, wrong source IP, wrong question, wrong 0x20 case).
- If the mismatch count exceeds a threshold (e.g. 5 mismatches for one query), flag it as a spoofing attempt.
- Re-send the query over TCP to the same server. TCP has a 3-way handshake, so an off-path attacker cannot inject a response.
- Log a security alert with the query name, server, and mismatch count.

### 5.5 Module: Access Control (`policy/acl.cpp`)

**What it is:** Only answer queries from clients on configured subnets.

**Implementation:**
- Parse CIDR subnets from config (e.g. `192.168.0.0/16`, `10.0.0.0/8`, `127.0.0.0/8`).
- For each incoming query, check the client's IP against all allowed subnets.
- If not allowed: respond with REFUSED, or silently drop (configurable).
- **Why:** An open resolver (one that answers anyone) is the primary tool of DNS amplification DDoS attacks. An attacker sends queries with a spoofed source IP (the victim's IP). The resolver sends large responses to the victim. Restricting to LAN clients prevents this entirely.

### 5.6 Module: Blocklist Trie (`policy/blocklist_trie.cpp`)

**What it is:** A trie (prefix tree) built on **reversed** domain labels for fast domain matching. A rule for `example.com` matches all subdomains.

**Data structure:**
```
Root
├── "com"
│   ├── "example"           ← blocks *.example.com
│   │   ├── "ads"           ← blocks *.ads.example.com (more specific)
│   │   └── [ALLOW]"cdn"    ← allowlists *.cdn.example.com
│   └── "adtracker"         ← blocks *.adtracker.com
└── "net"
    └── "doubleclick"       ← blocks *.doubleclick.net
```

**Why reversed labels?** A domain like `ads.example.com` is stored as `["com", "example", "ads"]`. Walking the trie from root matches TLD → SLD → subdomain, so a rule at any level automatically covers all subdomains below it.

**Operations:**
- **Insert:** Split the domain into labels, reverse them, walk/create trie nodes, mark the terminal node with the action (block/allow).
- **Lookup:** Split the query domain into labels, reverse them, walk the trie. At each level, check if the current node is marked. The deepest match wins. An allow marking overrides a block marking at the same or deeper level.
- **Complexity:** O(number of labels in the query) — typically 3–4. Independent of the number of rules in the list (could be 500k+).

**Loading lists:**
- Support hosts-format (`0.0.0.0 ads.example.com`) and plain domain-list format (one domain per line).
- Lines starting with `#` are comments.
- Load multiple files and merge into one trie.

**Hot reload:** Build a new trie from the (possibly updated) files, then atomically swap the pointer. Old trie is destroyed when no queries are using it (use `std::shared_ptr` or a read-copy-update pattern). This allows blocklist updates without restarting the resolver.

### 5.7 Module: CNAME Cloaking Check (`policy/cname_check.cpp`)

**What it is:** After resolution, check every name in the CNAME chain against the blocklist. If any hop is blocked, block the whole answer.

**Why it exists:** Ad-tech companies use CNAME cloaking to bypass blocklists. `metrics.newsite.com` has a CNAME to `tracker.adcompany.net`. A blocklist check on `metrics.newsite.com` passes (it's a first-party domain), but `adcompany.net` is on the blocklist. Without checking the chain, the tracker slips through.

**Implementation:**
1. After resolution produces an answer with CNAME records, extract the CNAME chain:
   `query_name → CNAME target₁ → CNAME target₂ → ... → final A/AAAA`
2. Look up each name and each name's **registrable domain** (eTLD+1) in the blocklist trie.
3. If any hop matches a block rule, replace the entire response with a blocked response (0.0.0.0 or NXDOMAIN) and log which CNAME hop triggered the block.

**Cost:** One trie lookup per CNAME hop. A typical chain is 1–3 hops. Negligible.

### 5.8 Module: DNS Rebinding Protection (`policy/rebinding.cpp`)

**What it is:** Prevents a public domain from resolving to a private/local IP address.

**The attack:** An attacker registers `evil.com`, sets its A record to their server initially, serves JavaScript that makes requests to `evil.com`, then changes the DNS to `192.168.1.1` (the victim's router). The browser's same-origin policy allows the JavaScript to access `evil.com`, which now resolves to the router. The attacker can now scan the local network or access the router admin panel.

**Implementation:**
- After resolution, for every A and AAAA record in the answer:
  - Check if the domain is "public" (not in a configured exempt list like `.home`, `.lan`, `.local`)
  - Check if the IP is in a private/special range:
    - `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (RFC 1918)
    - `127.0.0.0/8` (loopback)
    - `169.254.0.0/16` (link-local)
    - `0.0.0.0/8` (unspecified)
    - `100.64.0.0/10` (CGN / shared address space)
    - IPv6: `::1`, `fc00::/7` (ULA), `fe80::/10` (link-local), IPv4-mapped forms
  - If public domain AND private IP → **strip that record** from the answer. If all records are stripped, return NXDOMAIN.

### 5.9 Module: Response Rate Limiting (`security/rrl.cpp`)

**What it is:** Limits the rate of identical responses sent to the same client network. Defeats DNS amplification attacks.

**How the attack works:** An attacker sends queries to our resolver with a **spoofed source IP** (the victim's IP). Our resolver sends (potentially large) responses to the victim. The amplification factor is `response_size / query_size`, which can be 50x+ for TXT queries.

**Implementation (two mechanisms):**

**Per-client query rate limiting (token bucket):**
- One token bucket per client IP.
- Configured rate: e.g. 100 queries/second, burst capacity 200.
- If the bucket is empty, drop or respond with REFUSED.
- Use a hash map with periodic cleanup of expired buckets.

**Response Rate Limiting (RRL) per RFC-like semantics:**
- Track response fingerprints: `(client_network, qname, qtype, rcode)` where client_network is the client IP masked to /24 (IPv4) or /56 (IPv6).
- Each fingerprint has a counter. If the counter exceeds `responses_per_second`:
  - Most excess responses are **dropped** (the victim never receives them).
  - Every Nth excess response (the "slip" rate, e.g. every 2nd) is sent with the **TC bit set** and the answer section empty. This tells a legitimate client "retry over TCP." A legitimate client whose IP happens to be the attacker's spoofed source can recover. A DDoS attacker gets nothing useful.
- Counters reset every window (e.g. 1 second).

### 5.10 Attack Lab: Kaminsky Poisoning

**What to build:**

A Scapy-based attack script (`lab/attacks/kaminsky.py`) that demonstrates the Kaminsky attack against our resolver at different defence levels:

1. **Weak mode** (for demo): sequential transaction IDs, fixed source port, no 0x20, no bailiwick check.
   - The attacker script queries `random123.target.com`, then floods forged responses with guessed IDs, all containing a referral for `target.com` pointing to the attacker's server.
   - Expected: succeeds within a few thousand packets.

2. **Random ID only**: random 16-bit TXID, fixed port.
   - Expected: needs ~65k packets per attempt, may succeed within a budget.

3. **Random ID + random port**: both randomised.
   - Expected: needs ~2 billion packets, practically infeasible.

4. **Full hardening**: random ID + port + 0x20 + bailiwick.
   - Expected: attack fails entirely within any practical budget.

**Metric:** Number of forged packets sent until successful poisoning (or failure after N million packets).

> [!WARNING]
> All poisoning attacks are run ONLY inside isolated network namespaces against our own resolver and our own fake authoritative server. Never against real resolvers or domains.

---

## 6. Phase 5 — Privacy & ML Integration (Weeks 9–10)

### 6.1 Module: QNAME Minimisation (`resolver/qname_minimisation.cpp`)

**What it is:** Instead of sending the full query name to every server in the chain, send only as much as each server needs to route us.

**Without minimisation:**
```
To root:  "www.private-clinic.example.in A?"   ← root learns the full name
To .in:   "www.private-clinic.example.in A?"   ← TLD learns the full name
To auth:  "www.private-clinic.example.in A?"   ← only this server needs the full name
```

**With minimisation (RFC 9156):**
```
To root:  "in NS?"                              ← root learns only the TLD
To .in:   "example.in NS?"                      ← TLD learns only the SLD
To auth:  "www.private-clinic.example.in A?"     ← auth gets the full name (it needs it)
```

**Implementation:**
- At each step of iterative resolution, instead of asking for the full `qname`, ask for `zone_cut_plus_one_label NS?`.
- Example: zone_cut is `in.`, qname is `www.private-clinic.example.in.`. The next label below `in.` is `example`, so we ask `example.in. NS?`.
- At the final authoritative server, send the full query.

**Edge cases (RFC 9156 §5):**
- **Empty non-terminals:** A name like `example.in` might exist only as a delegation point, not as a name with records. Some broken servers return NXDOMAIN for such intermediate queries. If we get NXDOMAIN for a minimised query, try the next longer name. If that also fails, fall back to the full name for this zone.
- **Extra round trips:** Minimisation adds one query per delegation step on a cold cache. But once zone cuts are cached (the normal case), the cost disappears because we already know where to go. We measure this cost in experiment E6.

### 6.2 Module: DoT Listener (`net/dot_listener.cpp`)

**What it is:** DNS-over-TLS on port 853 (RFC 7858). Wraps the TCP DNS framing inside a TLS connection.

**Implementation:**
1. Create a TLS context with OpenSSL (`SSL_CTX_new`), load the server certificate and key.
2. Listen on TCP port 853.
3. On accept, wrap the socket in an SSL object (`SSL_new`, `SSL_set_fd`).
4. Perform TLS handshake (`SSL_accept`). This is asynchronous — it may require multiple reads/writes that epoll must handle.
5. After handshake completes, read/write using `SSL_read`/`SSL_write` instead of `read`/`write`. The framing is the same as TCP DNS (2-byte length prefix + message).

**Certificate management:**
- For lab testing: generate a self-signed CA and server certificate with a script.
- For real deployment: Let's Encrypt with a domain name.
- Android's "Private DNS" setting can be pointed at any DoT server. This is how we demo DoT with a real phone.

### 6.3 Module: DoH Listener (`net/doh_listener.cpp`)

**What it is:** DNS-over-HTTPS on port 443 (RFC 8484). DNS messages are carried inside HTTP requests.

**The protocol:**
- **POST** to `/dns-query` with `Content-Type: application/dns-message` and the raw DNS message bytes as the body.
- **GET** to `/dns-query?dns=<base64url-encoded-message>` — the DNS message is base64url-encoded in the query string.
- Response: `Content-Type: application/dns-message`, body is the raw DNS response bytes.
- RFC 8484 recommends HTTP/2, but HTTP/1.1 is acceptable for a prototype.

**Implementation options:**
- **Simple (HTTP/1.1):** Handle the HTTP framing manually — parse `POST /dns-query`, read Content-Length bytes, process, respond with HTTP 200 and the DNS response. This is achievable with OpenSSL for TLS.
- **Proper (HTTP/2):** Use the `nghttp2` library for HTTP/2 framing. More complex but protocol-correct. HTTP/2 multiplexes multiple queries over one connection, which is important for performance.

**For Phase 5, start with HTTP/1.1 over TLS.** Upgrade to HTTP/2 with nghttp2 if time permits.

**How to test:** Firefox and Chrome can be configured with a custom DoH URL (`https://your-resolver-ip/dns-query`). This is the demo for DoH.

### 6.4 Module: DGA Classifier — Fast Path (`core/ml/dga_classifier.cpp`)

**What it is:** A machine learning model that runs **inline on every uncached query** to detect Domain Generation Algorithm domains.

**What it classifies:** The **registrable domain** (eTLD+1), not the full query name. This is critical:
- A DGA generates registrable domains like `x7kq2mzpfa.com`.
- Legitimate subdomains can look random (`d1a2b3c4.cloudfront.net`), but the registrable domain (`cloudfront.net`) is benign.
- Use the Public Suffix List to extract the eTLD+1.

**Model options (trained in Python, exported for C++ inference):**

**Option A — Feature-based Random Forest (recommended for v1):**
- Features computed from the registrable label string:
  - Length of the registrable label
  - Shannon entropy (how random the characters are)
  - Ratio of digits / vowels / consonants
  - Longest consonant run (humans make pronounceable names)
  - 2-gram and 3-gram log-likelihood under a model trained on benign domains (measures how "English-like" or "brand-like" the name looks)
  - Fraction of hex digits (many DGAs output hex)
  - Number of distinct characters
- Export the trained Random Forest to C++ code using `m2cgen` or Treelite. This generates a single `.cpp` file with if/else trees — no runtime dependency, microsecond inference.

**Option B — Character-level 1D CNN (for comparison):**
- Embed each character (dim ~32) → 1D convolutions → global pooling → dense → sigmoid.
- Export to ONNX, run with ONNX Runtime in C++.
- Measures: does deep learning add accuracy over hand-crafted features? At what latency cost?

**Deployment in the resolver:**
- On every cache miss, extract the registrable domain from the query name.
- Check against a **popular-domain allowlist** (top 100k Tranco). If on the list → skip scoring entirely (no false-positive risk, no latency).
- If not on the list → compute features, run the model, get a score (0.0 = benign, 1.0 = DGA).
- **Cache the verdict** per registrable domain. The domain `x7kq2mzpfa.com` is scored once; all subsequent queries for any subdomain of it reuse the cached score.
- If score > threshold (e.g. 0.9) and mode is "enforce" → block. If mode is "monitor" → log alert, allow.

### 6.5 Module: Event Bus (`telemetry/event_bus.cpp`)

**What it is:** An in-memory ring buffer that publishes a copy of every query and response event to the slow-path analyzer and the logging subsystem.

**Structure of an event:**
- Timestamp
- Client IP and port
- Transport type (UDP, TCP, DoT, DoH)
- Query name, type, class
- Response code, answer count
- Cache hit/miss
- Latency (microseconds)
- Policy action (allow, block) and rule name
- DGA score (if scored)

**Implementation:**
- A lock-free single-producer, single-consumer ring buffer (SPSC queue) from the event loop thread to a writer thread.
- The writer thread serialises events and sends them over a Unix domain socket to the Python analyzer process.
- If the analyzer is not connected or falls behind, events are dropped (the ring buffer overwrites old entries). The fast path must **never** block waiting for the slow path.

### 6.6 Module: Python Analyzer Service (`analyzer/main.py`)

**What it is:** A Python process that receives query/response events over a Unix socket and runs the slow-path detectors.

**Architecture:**
1. Connect to the Unix socket that the event bus writes to.
2. Read events as JSON lines (or MessagePack for efficiency).
3. Feed each event to the detector pipeline:
   - **Tunnel detector** — maintains per-(client_ip, registrable_domain) sliding windows
   - **NXDOMAIN burst detector** — maintains per-client_ip counters
4. When a detector fires, push a dynamic rule back to the resolver (over a separate control socket or a shared file).

### 6.7 Module: Tunnel Detector (`analyzer/detectors/tunnel_detector.py`)

**What it is:** Detects DNS tunnelling (iodine, dnscat2, etc.) by analysing behavioural patterns over time.

**Unit of analysis:** `(client_ip, registrable_domain)` over a 60-second sliding window, stepped every 10 seconds.

**Features computed per window:**

| Feature | Why it separates tunnels from normal |
|---|---|
| Query count | Tunnels send many queries/minute to one domain |
| Unique subdomain count | Each tunnel query carries new encoded data, so subdomains never repeat |
| Mean and max subdomain length | Data is packed to the 63-byte label limit |
| Mean character entropy of subdomains | Base32/64 encoded data has high entropy (~4.5–5.0 bits/char) vs normal names (~3.0) |
| Fraction of TXT / NULL / CNAME / MX queries | Tunnels prefer record types that carry more data in responses |
| Mean response size | Downstream data comes back in large responses |
| Mean inter-query time and its standard deviation | Tunnels poll at regular intervals |
| Ratio of NXDOMAIN responses | Some tunnel setups generate NXDOMAINs |

**Model:** Random Forest or Gradient Boosting on these tabular features. Also evaluate an Isolation Forest (unsupervised) trained only on benign traffic.

**Detection latency:** The detector can only fire after one full 60-second window, so the minimum detection delay is ~60 seconds. This is reported as a metric.

**Known false-positive sources:**
- Anti-virus reputation services (many unique subdomains, high entropy)
- DNS-based blocklists (e.g. `*.zen.spamhaus.org`)
- CDN probe checks
- These are handled by the popular-domain allowlist and measured explicitly.

### 6.8 Module: NXDOMAIN Burst Detector (`analyzer/detectors/nxdomain_burst.py`)

**What it is:** Detects DGA-infected hosts by monitoring per-client NXDOMAIN rates.

**How it works:**
- Track per-client: NXDOMAIN count over the last 60 seconds, and total query count.
- If NXDOMAIN ratio > threshold (e.g. 70%) AND NXDOMAIN count > minimum (e.g. 50 in 60s), flag the client.
- Cross-reference with DGA scores: "This client got 150 NXDOMAINs in a minute, and 90% of those names scored > 0.7 on the DGA classifier." This combined signal is much stronger than either alone.

**Why it's a separate detector:** Alone, NXDOMAIN bursts are noisy — typos, broken apps, and expired CDN entries cause them. But combined with DGA scores, the signal is very strong and false positives drop dramatically.

### 6.9 Module: Score Fusion & Dynamic Rules (`analyzer/fusion/risk_scorer.py`)

**What it is:** Combines signals from all detectors into a single risk score per (client, domain) and decides what action to take.

**Fusion formula:**
```
risk = w1 * dga_score + w2 * tunnel_score + w3 * nxdomain_burst_score + w4 * blocklist_hit
```

Start with hand-tuned weights and thresholds. Optionally train a logistic regression on top if labelled examples are available.

**Actions by risk level:**

| Risk Level | Score Range | Action |
|---|---|---|
| Low | 0.0 – 0.3 | Log only |
| Medium | 0.3 – 0.6 | Dashboard alert with full explanation |
| High | 0.6 – 1.0 | Block domain for that client (time-limited), push dynamic rule to policy engine |

**Dynamic rules:** A high-risk verdict creates a rule like "block `*.suspicious-domain.net` for client `192.168.1.23` for 1 hour." This rule is pushed to the resolver's policy engine (via a control socket or shared state), where the fast path enforces it on all subsequent queries. The rule has:
- An expiry time (auto-unblock after duration)
- A reason string (for the dashboard)
- The contributing scores and features (for explainability)

---

## 7. Phase 6 — Observability (Week 11)

### 7.1 Module: Serve-Stale (`cache/serve_stale.cpp`)

**What it is:** When upstream resolution fails and we have an expired cache entry, return the stale data with a short TTL instead of SERVFAIL.

**Why:** A slightly old IP address almost always still works. No answer never works. This keeps the network functioning during upstream outages.

**Implementation:**
- When a cache lookup finds an expired entry, mark it as `is_stale = true` in the result but keep the entry available.
- When the resolver fails to refresh (timeout/SERVFAIL from all servers), check if a stale entry exists:
  - If yes: return it with TTL = 30 seconds (per RFC 8767)
  - If no: return SERVFAIL
- Stale entries are kept for `max_stale_age` (e.g. 1 day) beyond their original TTL, then truly evicted.
- When a stale entry is served, launch a **background refresh** — the next query for this name should get fresh data if upstream has recovered.

### 7.2 Module: Prefetch

**What it is:** When a popular cache entry is requested and it's near expiry (last 10% of TTL), answer from cache AND start a background refresh.

**Implementation:**
- On cache hit, compute `remaining_pct = (expires_at - now) / (expires_at - inserted_at) * 100`.
- If `remaining_pct < 10` (configurable threshold) AND the entry has been hit multiple times (it's popular), set `needs_prefetch = true` in the lookup result.
- The caller triggers a background resolution for this name. The result updates the cache entry with a new TTL.
- From the user's perspective, popular names never expire — they always get a fast cache answer, and the cache is silently kept fresh.

### 7.3 Module: Query Log (`telemetry/query_log.cpp`)

**What it is:** A structured JSON log of every query, suitable for analysis and the dashboard.

**Event format (one JSON object per line):**
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

**Implementation:**
- Events come from the event bus ring buffer.
- A writer thread serialises to JSON lines and appends to a log file.
- **Retention:** rotate logs daily, delete logs older than `retention_days`.
- **Anonymisation option:** if `anonymise_clients` is enabled, hash client IPs with a daily-rotating salt.
- **Performance:** the writer thread batches writes and uses buffered I/O. Never block the event loop.

### 7.4 Module: Prometheus Metrics (`telemetry/metrics.cpp`)

**What it is:** An HTTP endpoint (`/metrics`) that Prometheus scrapes to collect time-series data.

**Metrics to expose:**
- `queries_total{transport, qtype, rcode}` — counter
- `cache_hits_total` / `cache_misses_total` — counters
- `cache_entries` — gauge (current count)
- `resolution_latency_seconds` — histogram (p50, p95, p99)
- `upstream_queries_total` — counter
- `upstream_timeouts_total` — counter
- `blocked_total{list, reason}` — counter (by blocklist name, by reason like "cname_cloaking")
- `ml_alerts_total{detector}` — counter (by detector type)
- `spoof_attempts_total` — counter
- `rrl_dropped_total` — counter

**Implementation:**
- A small HTTP server on a configurable port (e.g. 9153) that responds to `GET /metrics` with text in Prometheus exposition format:
  ```
  # HELP queries_total Total DNS queries received
  # TYPE queries_total counter
  queries_total{transport="udp",qtype="A",rcode="NOERROR"} 123456
  ```
- Use atomic counters updated from the event loop thread. The HTTP server reads them on demand.

### 7.5 Module: Dashboard

**What it is:** Visual interface for the network owner to understand what's happening.

**Components:**
1. **Grafana dashboards** (provisioned via JSON):
   - Overview: queries/s, cache hit ratio, p50/p99 latency, % blocked
   - Per-client view: top domains, blocked counts, activity timeline
   - Security: spoofing attempts, RRL activity, rebinding blocks

2. **Custom alert UI** (simple web page):
   - List of ML alerts with timestamp, client, domain, risk score, and contributing features
   - Feature explanation: "unique subdomains: 412/min, mean entropy: 4.8 bits/char, tunnel_score: 0.92"
   - One-click buttons: "Add to allowlist" / "Permanently block" / "Dismiss"
   - These actions update the resolver's policy via the control socket

---

## 8. Phase 7 — Evaluation (Weeks 12–13)

### All 12 Experiments

| # | Question | Detailed Method | Key Metrics |
|---|---|---|---|
| E1 | Is resolution correct? | Resolve top 10k Tranco with DNSentinel and Unbound; compare answer IP sets | % matching, SERVFAIL rate |
| E2 | How fast is it? | `dnsperf` with cold cache (first run) and warm cache (second run); compare latency distributions with Unbound | p50/p95/p99 latency (ms), max sustained QPS before >1% loss |
| E3 | Cache effectiveness? | Replay a multi-hour query trace captured from our own devices; measure hit ratio over time | Cache hit ratio (%), upstream queries saved (%) |
| E4 | Serve-stale impact? | During a replayed trace, cut the upstream link for 5 minutes; measure how many queries are answered | % queries answered during outage, with vs without serve-stale |
| E5 | Poisoning resistance? | Kaminsky attack at 4 defence levels; count forged packets to success | Packets to success (or "failed after N million"), per defence level |
| E6 | Privacy cost? | Latency with/without QNAME minimisation; latency over DoT/DoH vs plain UDP | Added latency per query (ms), extra upstream queries (%) |
| E7 | DGA detection? | Random split AND leave-family-out cross-validation | Per-family P/R/F1, ROC AUC, PR AUC, false positives per day of real browsing |
| E8 | Tunnel detection? | Run iodine/dnscat2 at 5 different throughput rates (10 kbps to 500 kbps); run 24h of benign traffic | Recall per rate, FP per day, detection delay (seconds from tunnel start to alert) |
| E9 | ML latency cost? | Benchmark queries with and without fast-path DGA scoring enabled | Microseconds added per query (histogram); effect of verdict caching |
| E10 | Abuse resistance? | Send spoofed-source queries from attacker namespace while legitimate clients query; measure amplification | Amplification factor with RRL off vs on; legitimate client success rate |
| E11 | Parser robustness? | Run libFuzzer and/or AFL++ for 48+ hours; report crashes and code coverage | Crashes found/fixed, line/branch coverage (%) |
| E12 | Blocking in practice? | Browse top 50 websites with blocking enabled; compare network requests against unblocked baseline | % tracker requests blocked, CNAME-cloaked trackers caught, pages visually broken |

**Every experiment is:**
- Scripted (reproducible from `bench/scripts/`)
- Run ≥5 times
- Reported with median and 95% confidence intervals
- Plotted (`bench/plots/plot_results.py`)

---

## 9. Phase 8 — Final (Week 14)

### Report Structure
Each team member writes the sections they own:
- M1: Wire format, resolver algorithm, QNAME minimisation, E1/E11 results
- M2: Event loop, cache, serve-stale, prefetch, E2/E3/E4/E9 results
- M3: Security defences, policy engine, DoT/DoH, attack lab, E5/E6/E10/E12 results
- M4: ML models, analyzer, dashboard, E7/E8 results

### Demo Script (10 minutes)
1. Show a phone (DoT) and laptop (DoH) browsing with DNSentinel — pages load, ads disappear
2. Show a CNAME-cloaked tracker caught, with its chain on the dashboard
3. Run the poisoning attack: weak mode (succeeds), hardened (fails), show spoof counter
4. Start an iodine tunnel → alert appears on dashboard with feature explanation → auto-blocked
5. Run DGA simulator → NXDOMAIN burst + DGA scores → client flagged
6. Cut the upstream link → serve-stale keeps recent sites working
7. Show key evaluation graphs

### Viva Prep
Everyone must be able to explain every module, not just their own. Drill the Q&A from §15 of the README.

---

## 10. Cross-Cutting Concerns

### Error Handling Strategy
- **Network errors** (timeouts, connection refused): retry with next server, bounded by deadline. Return SERVFAIL only after all options exhausted.
- **Parse errors** on incoming queries: drop silently (don't amplify garbage).
- **Parse errors** on upstream responses: treat as SERVFAIL-worthy, try next server.
- **Configuration errors**: fail loudly at startup with clear messages. Don't silently use defaults for security-critical settings.

### Memory Safety
- All buffer accesses bounds-checked (parser, builder, EDNS).
- Run with **AddressSanitizer (ASan)** and **UndefinedBehaviorSanitizer (UBSan)** in CI and during all testing.
- Fuzz the parser with libFuzzer or AFL++ from week 2 onward.
- Use `std::span` instead of raw pointer + length.
- Use `std::expected` for error returns instead of exceptions (no unwinding cost, explicit error handling).

### Configuration Loading
- Parse `config/dnsentinel.yaml` at startup using a YAML library (e.g. `yaml-cpp`).
- Validate all values at startup (e.g. `edns_buffer` must be ≥ 512 and ≤ 4096).
- Some settings support hot-reload (blocklists, ML thresholds). Security settings (ACL, TLS certs) require restart.

### Logging
- Use a lightweight structured logger (or even `spdlog`).
- Log levels: ERROR (things that need attention), WARN (unusual but handled), INFO (startup, shutdown, config changes), DEBUG (per-query details, off by default).
- Performance: logging must never block the event loop. Use an async logger that writes from a background thread.

---

## 11. Risk Register & Contingencies

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Parser bugs cause crashes on real traffic | Medium | High | Fuzz from week 2, ASan in CI, conservative parsing (reject on doubt) |
| Iterative resolution too slow vs Unbound | High | Medium | Expected — we're not trying to match Unbound. Measure and explain the gap honestly. Focus on correctness first. |
| DoH HTTP/2 implementation too complex | Medium | Medium | Fall back to HTTP/1.1. Still functional, just less efficient. |
| ML false positives on legitimate traffic | Medium | High | Popular-domain allowlist, monitor-only mode as default, time-limited blocks, one-click override on dashboard |
| Broken servers reject minimised queries | Low | Low | RFC 9156 fallback logic: retry with full name for that zone |
| DNSSEC stretch goal too large | High | Low | It's explicitly a stretch goal. Core project is complete without it. |
| Team member unavailable for their phase | Medium | High | Everyone reviews every PR and can explain every module. Overlap in expertise. |

---

> [!IMPORTANT]
> **The #1 rule across all phases:** If something is too hard to finish in time, **cut scope and document what's missing**, don't silently leave it broken. A working resolver without DoH is better than a crashing resolver with DoH. The README already lists limitations honestly — the implementation should match that standard.
