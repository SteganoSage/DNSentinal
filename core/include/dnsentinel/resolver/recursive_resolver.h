#pragma once
/// @file resolver/recursive_resolver.h
/// Iterative recursive DNS resolver — walks the delegation tree from root hints.
///
/// Asynchronous: the resolver runs on the EventLoop, sending upstream
/// queries from its own sockets and using the loop's timers for timeouts,
/// so a slow or dead zone never blocks other clients. Each resolution is a
/// state machine: where the algorithm in §7.3 of the design doc says "send
/// and wait", the implementation sends, returns to the loop, and resumes
/// from the socket or timer callback.

#include "dnsentinel/cache/cache.h"
#include "dnsentinel/resolver/root_hints.h"
#include "dnsentinel/types.h"

#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace dnsentinel::net {
class EventLoop;
}

namespace dnsentinel::resolver {

enum class ResolveError {
    Timeout,
    ServFail,
    MaxQueriesExceeded,
    MaxDepthExceeded,
    MaxCnameChainExceeded,
    AllServersFailed,
    NetworkError,
};

[[nodiscard]] std::string resolve_error_to_string(ResolveError e);

/// A zone whose names are resolved by asking `servers` directly instead of
/// starting at the root (Unbound's stub-zone). Lets one resolver browse the
/// real internet and serve the lab's `lab.` zone at the same time. The
/// servers must be authoritative for the zone; delegations they hand out
/// below it are followed as usual.
struct StubZone {
    Name                  zone;
    std::vector<uint32_t> servers;  // IPv4, network byte order (as in RDataA)
};

struct ResolverConfig {
    std::string root_hints_path = "config/named.root";  // loaded by the caller: see RootHints
    bool     qname_minimisation   = true;   // not implemented yet (plan §6.1)
    bool     use_0x20             = true;   // random letter case in upstream queries (plan §5.2)
    uint16_t edns_buffer          = 1232;
    uint32_t max_upstream_queries = 30;     // per client query, sub-queries included
    uint16_t max_referral_depth   = 16;
    uint8_t  max_cname_chain      = 8;
    uint8_t  max_glueless_ns      = 5;      // NXNSAttack cap: NS names resolved per zone
    uint32_t query_timeout_ms     = 800;    // for a server not yet measured (less for fast ones, see
                                            // ServerSelection); doubles after each timeout
    uint32_t max_query_timeout_ms = 3000;
    uint32_t overall_deadline_ms  = 5000;
    uint32_t explore_one_in       = 20;     // ask a random server once in this many picks; 0: never
    uint32_t spoof_tcp_threshold  = 5;      // forged-looking replies to one query before asking
                                            // again over TCP (plan §5.4); 0: never
    uint16_t upstream_port        = 53;     // tests and the lab only
    std::vector<StubZone> stub_zones;
};

/// Result of a resolution that reached a definite outcome. That includes
/// "the name does not exist" (response.header.rcode == NXDOMAIN) and "no
/// records of this type" (NOERROR with no answers); the SOA that proves it
/// is in response.authority. The answers start with any CNAMEs followed.
/// A ResolveError means no outcome could be reached (answer SERVFAIL).
struct ResolveResult {
    Message  response;
    uint32_t upstream_queries_used = 0;      // caused by this query: 0 when coalesced
    uint32_t latency_us            = 0;      // from this query's resolve() call
    bool     coalesced             = false;  // joined an identical resolution in flight (plan §4.4)
};

using ResolveCallback = std::function<void(std::expected<ResolveResult, ResolveError>)>;
using PrimeCallback   = std::function<void(std::expected<void, ResolveError>)>;

/// Raised when one upstream query draws so many forged-looking replies that
/// someone is probably trying to poison the cache (plan §5.4). The resolver
/// has already switched that query to TCP, which an off-path attacker can't
/// spoof; the alert is for logging and the dashboard.
struct SpoofAlert {
    Question question;  // what was asked, as sent upstream
    uint32_t server  = 0;  // the server being impersonated: IPv4, network byte order
    uint32_t replies = 0;  // forged-looking replies to that one query
};
using SpoofAlertFn = std::function<void(const SpoofAlert&)>;

/// The recursive resolver engine. Use it only from the loop's thread.
class RecursiveResolver {
public:
    /// `loop` and `cache` must outlive the resolver. `hints` come from
    /// load_root_hints(config.root_hints_path), loaded by the caller so a
    /// bad file fails at startup.
    RecursiveResolver(const ResolverConfig& config, RootHints hints, net::EventLoop& loop,
                      cache::Cache& cache);

    /// Abandons resolutions still in progress: their callbacks are never
    /// called. Callers that may outlive the resolver must not rely on them.
    ~RecursiveResolver();

    RecursiveResolver(const RecursiveResolver&)            = delete;
    RecursiveResolver& operator=(const RecursiveResolver&) = delete;

    /// Start resolving `question` by iteratively walking the delegation tree
    /// (§7.3 of the design doc).
    ///
    /// `done` is called exactly once, on the loop's thread, and never before
    /// resolve() returns, even when the answer is already known. Callers
    /// therefore never see their callback re-entered from inside resolve().
    /// config.overall_deadline_ms bounds how long that can take.
    ///
    /// A question identical to one already being resolved (same name,
    /// compared case-insensitively, type and class) joins that resolution
    /// instead of starting another (in-flight deduplication, plan §4.4).
    /// Every caller gets the outcome, with its own question in the response.
    /// Besides saving upstream traffic, this keeps at most one upstream query
    /// outstanding per question, which blunts birthday-style spoofing: with
    /// n identical queries in flight, a forged answer has n chances to match.
    void resolve(const Question& question, ResolveCallback done);

    /// Prime the cache with the root NS set (done once at startup). Same
    /// callback guarantees as resolve().
    void prime_root(PrimeCallback done);

    /// Call `alert` for every suspected spoofing attempt. It runs on the
    /// loop's thread and must not destroy the resolver.
    void on_spoof_alert(SpoofAlertFn alert);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace dnsentinel::resolver
