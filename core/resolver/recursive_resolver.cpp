/// @file resolver/recursive_resolver.cpp
/// Iterative resolution (plan §3.3) as an event-driven state machine.
///
/// A Task is one resolution: a client's question, or a sub-query for a name
/// server's address. It moves through
///   step()             answer from the cache, or find the closest zone cut
///   next_server()      pick the fastest untried server (SRTT); if none, resolve a glueless NS
///   send_query()       ask it and return to the loop
///   handle_response()  answer / CNAME / NXDOMAIN / referral / NODATA
/// and never blocks: every wait is a return to the event loop.
///
/// Convention: finish() runs the task's callback, which may start new work
/// or destroy the resolver, so every call to finish() (and to functions
/// that may call it) is the last thing its caller does.

#include "dnsentinel/resolver/recursive_resolver.h"

#include "dnsentinel/net/event_loop.h"
#include "dnsentinel/resolver/server_selection.h"
#include "dnsentinel/resolver/upstream.h"
#include "dnsentinel/security/bailiwick.h"

#include <netinet/in.h>

#include <algorithm>
#include <chrono>
#include <climits>
#include <optional>
#include <unordered_map>
#include <utility>

namespace dnsentinel::resolver {

namespace {

using std::chrono::microseconds;
using std::chrono::milliseconds;
using Clock = std::chrono::steady_clock;

constexpr uint16_t kClassIN   = 1;
constexpr uint16_t kTypeA     = static_cast<uint16_t>(RRType::A);
constexpr uint16_t kTypeNS    = static_cast<uint16_t>(RRType::NS);
constexpr uint16_t kTypeCNAME = static_cast<uint16_t>(RRType::CNAME);

/// Cache slot for NXDOMAIN. A name that doesn't exist has no records of any
/// type (RFC 2308 §5), so the entry is keyed by name alone, under the
/// reserved type 0.
constexpr uint16_t kNxdomainType = 0;

/// How deep sub-queries may nest (an NS name whose zone needs another NS
/// name resolved, ...). Cycles are caught separately; this bounds depth.
constexpr size_t kMaxSubqueryDepth = 4;

std::vector<RR> collect(const std::vector<RR>& section, const Name& name, uint16_t type) {
    std::vector<RR> out;
    for (const auto& rr : section) {
        if (rr.cls == kClassIN && static_cast<uint16_t>(rr.type) == type && rr.name == name) {
            out.push_back(rr);
        }
    }
    return out;
}

uint32_t min_ttl(const std::vector<RR>& rrs) {
    uint32_t ttl = UINT32_MAX;
    for (const auto& rr : rrs) ttl = std::min(ttl, rr.ttl);
    return rrs.empty() ? 0 : ttl;
}

/// The SOA proving a negative answer: owned by an ancestor of `qname`.
const RR* find_soa(const std::vector<RR>& authority, const Name& qname) {
    for (const auto& rr : authority) {
        if (std::holds_alternative<RDataSOA>(rr.rdata) && qname.is_subdomain_of(rr.name)) return &rr;
    }
    return nullptr;
}

/// RFC 2308 §5: a negative answer lives for min(SOA TTL, SOA MINIMUM).
uint32_t negative_ttl(const RR& soa) {
    return std::min(soa.ttl, std::get<RDataSOA>(soa.rdata).minimum);
}

/// The NS records of a referral: all NS records sharing the first one's owner.
std::vector<RR> referral_ns(const std::vector<RR>& authority) {
    std::vector<RR> ns;
    for (const auto& rr : authority) {
        if (rr.cls != kClassIN || !std::holds_alternative<RDataNS>(rr.rdata)) continue;
        if (!ns.empty() && !(rr.name == ns.front().name)) continue;
        ns.push_back(rr);
    }
    return ns;
}

std::vector<in_addr_t> ipv4_addresses(const std::vector<RR>& rrs) {
    std::vector<in_addr_t> out;
    for (const auto& rr : rrs) {
        if (const auto* a = std::get_if<RDataA>(&rr.rdata)) out.push_back(a->addr);
    }
    return out;
}

}  // namespace

std::string resolve_error_to_string(ResolveError e) {
    switch (e) {
        case ResolveError::Timeout:               return "timed out";
        case ResolveError::ServFail:              return "server failure";
        case ResolveError::MaxQueriesExceeded:    return "too many upstream queries";
        case ResolveError::MaxDepthExceeded:      return "too many referrals";
        case ResolveError::MaxCnameChainExceeded: return "CNAME chain too long";
        case ResolveError::AllServersFailed:      return "no name server answered";
        case ResolveError::NetworkError:          return "network error";
    }
    return "unknown resolve error";
}

// ─── Impl ───────────────────────────────────────────────────────────────────

struct RecursiveResolver::Impl {
    using Outcome = std::expected<ResolveResult, ResolveError>;

    /// Shared by a client query and all of its sub-queries.
    struct Budget {
        uint32_t queries = 0;
    };

    struct Task {
        Question              question;    // as asked
        Name                  qname;       // current target, after CNAMEs
        std::vector<RR>       chain;       // CNAMEs followed so far
        uint8_t               cname_hops = 0;
        std::vector<Question> ancestry;    // enclosing tasks' questions: cycle detection

        Name                   zone;        // current zone cut
        std::vector<in_addr_t> servers;     // known addresses of its name servers
        std::vector<Name>      unresolved;  // its name servers with no known address
        std::vector<in_addr_t> tried;
        in_addr_t              asked    = 0;      // the server asked last
        bool                   over_tcp = false;  // ... and whether over TCP
        uint8_t                glueless_lookups = 0;
        uint16_t               referrals        = 0;
        uint32_t               timeouts         = 0;  // in this zone: each doubles the next wait
        Clock::time_point      sent_at;

        std::shared_ptr<Budget> budget;
        Clock::time_point       started;
        UpstreamClient::QueryId upstream    = 0;  // query in flight
        uint64_t                child       = 0;  // sub-query in flight
        net::EventLoop::TimerId start_timer = 0;
        net::EventLoop::TimerId deadline    = 0;  // client queries only
        ResolveCallback         done;
    };

    Impl(const ResolverConfig& cfg, RootHints root_hints, net::EventLoop& event_loop,
         cache::Cache& answer_cache)
        : config(cfg), hints(std::move(root_hints)), loop(event_loop), cache(answer_cache),
          upstream(event_loop), selection(cfg.explore_one_in) {
        for (const auto& stub : config.stub_zones) {
            auto& servers = stubs[stub.zone];
            servers.insert(servers.end(), stub.servers.begin(), stub.servers.end());
        }
    }

    ~Impl() {
        // Callbacks are dropped. The upstream client closes its own sockets.
        for (auto& [id, t] : tasks) {
            if (t->start_timer) loop.cancel_timer(t->start_timer);
            if (t->deadline) loop.cancel_timer(t->deadline);
        }
    }

    ResolverConfig                                     config;
    RootHints                                          hints;
    net::EventLoop&                                    loop;
    cache::Cache&                                      cache;
    UpstreamClient                                     upstream;
    ServerSelection                                    selection;
    std::unordered_map<Name, std::vector<in_addr_t>>   stubs;  // zone → its servers
    uint64_t                                           next_task_id = 1;
    std::unordered_map<uint64_t, std::unique_ptr<Task>> tasks;

    // ─── Task lifecycle ─────────────────────────────────────────────────────

    Task* find(uint64_t id) {
        auto it = tasks.find(id);
        return it == tasks.end() ? nullptr : it->second.get();
    }

    /// Create a task; it starts on the next loop iteration, so its callback
    /// can never run inside the call that created it.
    uint64_t spawn(const Question& q, std::shared_ptr<Budget> budget,
                   std::vector<Question> ancestry, ResolveCallback done) {
        const uint64_t id = next_task_id++;
        auto t      = std::make_unique<Task>();
        t->question = q;
        t->qname    = q.qname;
        t->ancestry = std::move(ancestry);
        t->budget   = std::move(budget);
        t->started  = Clock::now();
        t->done     = std::move(done);
        t->start_timer = loop.add_timer(milliseconds(0), [this, id] {
            if (Task* task = find(id)) {
                task->start_timer = 0;
                step(id);
            }
        });
        tasks.emplace(id, std::move(t));
        return id;
    }

    void resolve_client(const Question& q, ResolveCallback done) {
        const uint64_t id = spawn(q, std::make_shared<Budget>(), {}, std::move(done));
        tasks.at(id)->deadline = loop.add_timer(milliseconds(config.overall_deadline_ms), [this, id] {
            if (Task* t = find(id)) {
                t->deadline = 0;
                finish(id, std::unexpected(ResolveError::Timeout));
            }
        });
    }

    void release(Task& t) {
        if (t.upstream) upstream.cancel(t.upstream);
        if (t.child) cancel(t.child);
        if (t.start_timer) loop.cancel_timer(t.start_timer);
        if (t.deadline) loop.cancel_timer(t.deadline);
    }

    /// Remove a task and everything it has in flight, without calling back.
    void cancel(uint64_t id) {
        auto it = tasks.find(id);
        if (it == tasks.end()) return;
        std::unique_ptr<Task> t = std::move(it->second);
        tasks.erase(it);
        release(*t);
    }

    void finish(uint64_t id, Outcome result) {
        auto it = tasks.find(id);
        if (it == tasks.end()) return;
        std::unique_ptr<Task> t = std::move(it->second);
        tasks.erase(it);
        release(*t);
        if (result) {
            result->upstream_queries_used = t->budget->queries;
            result->latency_us            = static_cast<uint32_t>(
                std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - t->started).count());
        }
        ResolveCallback done = std::move(t->done);
        t.reset();
        done(std::move(result));
    }

    static Outcome outcome(const Task& t, RCode rcode, const std::vector<RR>& answers,
                           const std::vector<RR>& authority) {
        ResolveResult r;
        r.response.header.qr    = true;
        r.response.header.rcode = static_cast<uint8_t>(rcode);
        r.response.questions    = {t.question};
        r.response.answers      = t.chain;
        r.response.answers.insert(r.response.answers.end(), answers.begin(), answers.end());
        r.response.authority = authority;
        return r;
    }

    // ─── Resolution steps ───────────────────────────────────────────────────

    bool follow_cname(Task& t, const RR& cname) {
        const auto* data = std::get_if<RDataCNAME>(&cname.rdata);
        if (!data || ++t.cname_hops > config.max_cname_chain) return false;
        t.chain.push_back(cname);
        t.qname = data->target;
        return true;
    }

    /// (Re)start resolving t.qname: from the cache if possible, else from the
    /// closest zone cut we know servers for.
    void step(uint64_t id) {
        Task* t = find(id);
        if (!t) return;
        if (t->question.qclass != kClassIN) {  // only the Internet class is resolved
            finish(id, std::unexpected(ResolveError::ServFail));
            return;
        }
        const uint16_t qtype = t->question.qtype;

        // Only authoritative answer data is served from the cache. Glue and
        // referral data (lower trust ranks) find servers; they never answer.
        while (true) {
            if (auto nx = cache.lookup({t->qname, kNxdomainType, kClassIN}); nx.entry) {
                finish(id, outcome(*t, RCode::NXDomain, {}, nx.entry->records));
                return;
            }
            auto hit = cache.lookup({t->qname, qtype, kClassIN});
            if (hit.entry && hit.entry->is_negative) {
                finish(id, outcome(*t, RCode::NoError, {}, hit.entry->records));
                return;
            }
            if (hit.entry && hit.entry->trust == TrustRank::Answer) {
                finish(id, outcome(*t, RCode::NoError, hit.entry->records, {}));
                return;
            }
            if (qtype == kTypeCNAME) break;
            auto cname = cache.lookup({t->qname, kTypeCNAME, kClassIN});
            if (!cname.entry || cname.entry->is_negative || cname.entry->trust != TrustRank::Answer ||
                cname.entry->records.empty()) {
                break;
            }
            if (!follow_cname(*t, cname.entry->records.front())) {
                finish(id, std::unexpected(ResolveError::MaxCnameChainExceeded));
                return;
            }
        }

        start_at_closest_zone(*t);
        next_server(id);
    }

    /// The deepest ancestor of t.qname that is a stub zone or has cached NS
    /// records, else the root. A stub zone beats cached NS records for the
    /// same zone, but delegations cached below it (which its servers handed
    /// out) are still used.
    void start_at_closest_zone(Task& t) {
        for (Name z = t.qname;; z = z.parent()) {
            if (auto stub = stubs.find(z); stub != stubs.end()) {
                reset_zone(t, z);
                for (in_addr_t a : stub->second) add_server(t, a);
                return;
            }
            auto ns = cache.lookup({z, kTypeNS, kClassIN});
            if (ns.entry && !ns.entry->is_negative && !ns.entry->records.empty()) {
                enter_zone(t, z, ns.entry->records);
                return;
            }
            if (z.label_count() == 0) break;
        }
        enter_zone(t, Name{}, hints.ns);
    }

    void add_server(Task& t, in_addr_t address) {
        if (std::find(t.servers.begin(), t.servers.end(), address) == t.servers.end()) {
            t.servers.push_back(address);
        }
    }

    /// Make `zone` the current zone cut, with no servers known yet.
    void reset_zone(Task& t, Name zone) {
        t.zone = std::move(zone);
        t.servers.clear();
        t.unresolved.clear();
        t.tried.clear();
        t.glueless_lookups = 0;
        t.timeouts         = 0;
    }

    /// Make `zone`, served by `ns_records`, the current zone cut. Server
    /// addresses come from `glue` (fresh from a referral) or the cache.
    void enter_zone(Task& t, Name zone, const std::vector<RR>& ns_records,
                    const std::vector<RR>& glue = {}) {
        reset_zone(t, std::move(zone));

        for (const auto& rr : ns_records) {
            const auto* ns = std::get_if<RDataNS>(&rr.rdata);
            if (!ns) continue;
            std::vector<in_addr_t> addresses = ipv4_addresses(collect(glue, ns->nsdname, kTypeA));
            if (addresses.empty()) {
                auto cached = cache.lookup({ns->nsdname, kTypeA, kClassIN});
                if (cached.entry && !cached.entry->is_negative) addresses = ipv4_addresses(cached.entry->records);
            }
            if (addresses.empty()) t.unresolved.push_back(ns->nsdname);
            for (in_addr_t a : addresses) add_server(t, a);
        }
        if (t.zone.label_count() == 0) {
            for (in_addr_t a : ipv4_addresses(hints.addresses)) add_server(t, a);
        }
    }

    bool would_cycle(const Task& t, const Question& q) const {
        if (q.qname == t.qname && q.qtype == t.question.qtype) return true;
        return std::find(t.ancestry.begin(), t.ancestry.end(), q) != t.ancestry.end();
    }

    void next_server(uint64_t id) {
        Task* t = find(id);
        if (!t) return;

        std::vector<in_addr_t> untried;
        for (in_addr_t s : t->servers) {
            if (std::find(t->tried.begin(), t->tried.end(), s) == t->tried.end()) untried.push_back(s);
        }
        if (!untried.empty()) {
            send_query(id, selection.pick(untried));
            return;
        }

        // Out of addresses: look up a name server that came without glue.
        // Capped per zone, so a referral listing hundreds of glueless names
        // can't turn us into a flood against a victim (NXNSAttack).
        while (!t->unresolved.empty() && t->glueless_lookups < config.max_glueless_ns) {
            Question q{t->unresolved.front(), kTypeA, kClassIN};
            t->unresolved.erase(t->unresolved.begin());
            if (would_cycle(*t, q) || t->ancestry.size() >= kMaxSubqueryDepth) continue;

            ++t->glueless_lookups;
            std::vector<Question> ancestry = t->ancestry;
            ancestry.push_back(Question{t->qname, t->question.qtype, kClassIN});
            t->child = spawn(q, t->budget, std::move(ancestry),
                             [this, id](Outcome o) { on_child_done(id, std::move(o)); });
            return;
        }
        finish(id, std::unexpected(ResolveError::AllServersFailed));
    }

    void on_child_done(uint64_t parent_id, Outcome child) {
        Task* t = find(parent_id);
        if (!t) return;
        t->child = 0;
        if (child) {
            for (in_addr_t a : ipv4_addresses(child->response.answers)) add_server(*t, a);
        }
        next_server(parent_id);
    }

    void send_query(uint64_t id, in_addr_t address, UpstreamTransport transport = UpstreamTransport::Udp) {
        Task& t = *find(id);
        if (t.budget->queries >= config.max_upstream_queries) {
            finish(id, std::unexpected(ResolveError::MaxQueriesExceeded));
            return;
        }
        ++t.budget->queries;
        if (transport == UpstreamTransport::Udp) t.tried.push_back(address);  // a TCP retry is the same try
        t.asked    = address;
        t.over_tcp = transport == UpstreamTransport::Tcp;

        Message query;
        query.header.rd = false;  // iterative: we do the recursion ourselves
        query.questions.push_back(Question{t.qname, t.question.qtype, kClassIN});
        query.edns = EdnsInfo{.udp_payload_size = config.edns_buffer};

        // As long as this server usually takes, doubled for each timeout in this zone.
        const milliseconds most    = milliseconds(config.max_query_timeout_ms);
        milliseconds       timeout = selection.timeout(address, milliseconds(config.query_timeout_ms));
        for (uint32_t i = 0; i < t.timeouts && timeout < most; ++i) timeout *= 2;
        timeout = std::min(timeout, most);

        sockaddr_in server{};
        server.sin_family      = AF_INET;
        server.sin_port        = htons(config.upstream_port);
        server.sin_addr.s_addr = address;
        t.sent_at  = Clock::now();
        t.upstream = upstream.send(
            server, std::move(query), timeout,
            [this, id](std::expected<Message, UpstreamError> r) { on_response(id, std::move(r)); }, transport);
    }

    void on_response(uint64_t id, std::expected<Message, UpstreamError> response) {
        Task* t = find(id);
        if (!t) return;
        t->upstream    = 0;
        const auto rtt = std::chrono::duration_cast<microseconds>(Clock::now() - t->sent_at);
        if (!response) {
            selection.record_failure(t->asked);
            if (response.error() == UpstreamError::Timeout) ++t->timeouts;
            next_server(id);
            return;
        }
        handle_response(id, *response, rtt);
    }

    /// Tell server selection how the server just asked did. Only UDP round
    /// trips are samples: over TCP the handshake doubles them.
    void rate(const Task& t, bool usable, microseconds rtt) {
        if (usable) {
            selection.record_answer(t.asked, t.over_tcp ? std::nullopt : std::optional(rtt));
        } else {
            selection.record_unusable(t.asked);
        }
    }

    /// Cache the addresses a response gave for these name servers (already
    /// bailiwick-filtered) at glue rank: they find servers, never answer.
    void cache_glue(const std::vector<RR>& additional, const std::vector<RR>& ns_records) {
        for (const auto& ns : ns_records) {
            const auto* data = std::get_if<RDataNS>(&ns.rdata);
            if (!data) continue;
            std::vector<RR> glue = collect(additional, data->nsdname, kTypeA);
            if (!glue.empty()) {
                cache.insert({data->nsdname, kTypeA, kClassIN}, glue, TrustRank::Glue, min_ttl(glue));
            }
        }
    }

    void handle_response(uint64_t id, Message& response, microseconds rtt) {
        Task& t = *find(id);
        const auto rcode = static_cast<RCode>(response.header.rcode);

        // TC: the answer didn't fit in UDP. Ask the same server again over
        // TCP (plan §4.1); if even that comes back truncated, give up on it.
        if (response.header.tc) {
            rate(t, !t.over_tcp, rtt);
            if (t.over_tcp) {
                next_server(id);
            } else {
                send_query(id, t.asked, UpstreamTransport::Tcp);
            }
            return;
        }
        // Any error rcode: this server can't help.
        if (rcode != RCode::NoError && rcode != RCode::NXDomain) {
            rate(t, false, rtt);
            next_server(id);
            return;
        }

        // Only records inside the zone we asked about are believed.
        security::filter_to_bailiwick(response, t.zone);
        const uint16_t  qtype       = t.question.qtype;
        const TrustRank answer_rank = response.header.aa ? TrustRank::Answer : TrustRank::Authority;

        // What the response says, worked out before acting on it: acting can
        // finish the task, and the server must be rated first.
        const bool answered = !collect(response.answers, t.qname, qtype).empty() ||
                              (qtype != kTypeCNAME && !collect(response.answers, t.qname, kTypeCNAME).empty());
        const RR*       soa   = find_soa(response.authority, t.qname);
        std::vector<RR> proof = soa ? std::vector<RR>{*soa} : std::vector<RR>{};
        // Referral: a non-authoritative response delegating a zone. Only
        // delegations downward, toward the name, are followed; upward or
        // sideways ones are a classic poisoning trick.
        const std::vector<RR> ns = response.header.aa ? std::vector<RR>{} : referral_ns(response.authority);
        const bool downward = !ns.empty() && ns.front().name.label_count() > t.zone.label_count() &&
                              t.qname.is_subdomain_of(ns.front().name);
        // Useless: a bad referral, or nothing at all (a lame server).
        rate(t, answered || rcode == RCode::NXDomain || (ns.empty() ? response.header.aa || soa : downward), rtt);

        // Answer section: follow CNAMEs as far as this response goes.
        bool followed = false;
        while (true) {
            std::vector<RR> rrset = collect(response.answers, t.qname, qtype);
            if (!rrset.empty()) {
                cache.insert({t.qname, qtype, kClassIN}, rrset, answer_rank, min_ttl(rrset));
                if (qtype == kTypeNS) cache_glue(response.additional, rrset);  // e.g. priming
                finish(id, outcome(t, RCode::NoError, rrset, {}));
                return;
            }
            if (qtype == kTypeCNAME) break;
            std::vector<RR> cname = collect(response.answers, t.qname, kTypeCNAME);
            if (cname.empty()) break;
            cname.resize(1);  // a name has at most one CNAME
            cache.insert({t.qname, kTypeCNAME, kClassIN}, cname, answer_rank, cname[0].ttl);
            if (!follow_cname(t, cname[0])) {
                finish(id, std::unexpected(ResolveError::MaxCnameChainExceeded));
                return;
            }
            followed = true;
        }
        if (followed) {
            // The rest of the chain isn't in this response (or wasn't
            // believable, e.g. out of bailiwick): resolve the target afresh.
            step(id);
            return;
        }

        if (rcode == RCode::NXDomain) {
            if (soa) {
                cache.insert({t.qname, kNxdomainType, kClassIN}, proof, TrustRank::Authority,
                             negative_ttl(*soa), /*negative=*/true);
            }
            finish(id, outcome(t, RCode::NXDomain, {}, proof));
            return;
        }

        if (!ns.empty()) {
            if (!downward) {
                next_server(id);
                return;
            }
            if (++t.referrals > config.max_referral_depth) {
                finish(id, std::unexpected(ResolveError::MaxDepthExceeded));
                return;
            }
            const Name child = ns.front().name;
            cache.insert({child, kTypeNS, kClassIN}, ns, TrustRank::Authority, min_ttl(ns));
            cache_glue(response.additional, ns);
            enter_zone(t, child, ns, response.additional);
            next_server(id);
            return;
        }

        // NODATA: the name exists but has no records of this type.
        if (response.header.aa || soa) {
            if (soa) {
                cache.insert({t.qname, qtype, kClassIN}, proof, TrustRank::Authority, negative_ttl(*soa),
                             /*negative=*/true);
            }
            finish(id, outcome(t, RCode::NoError, {}, proof));
            return;
        }
        next_server(id);  // nothing usable: a lame server
    }

    void prime(PrimeCallback done) {
        resolve_client(Question{Name{}, kTypeNS, kClassIN}, [done = std::move(done)](Outcome o) {
            if (!o) {
                done(std::unexpected(o.error()));
            } else if (o->response.answers.empty()) {
                done(std::unexpected(ResolveError::ServFail));
            } else {
                done({});
            }
        });
    }
};

// ─── RecursiveResolver ──────────────────────────────────────────────────────

RecursiveResolver::RecursiveResolver(const ResolverConfig& config, RootHints hints,
                                     net::EventLoop& loop, cache::Cache& cache)
    : impl_(std::make_unique<Impl>(config, std::move(hints), loop, cache)) {}

RecursiveResolver::~RecursiveResolver() = default;

void RecursiveResolver::resolve(const Question& question, ResolveCallback done) {
    impl_->resolve_client(question, std::move(done));
}

void RecursiveResolver::prime_root(PrimeCallback done) { impl_->prime(std::move(done)); }

}  // namespace dnsentinel::resolver
