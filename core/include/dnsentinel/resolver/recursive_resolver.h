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
#include "dnsentinel/types.h"

#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <string>

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

struct ResolverConfig {
    std::string root_hints_path = "config/named.root";
    bool     qname_minimisation   = true;
    bool     use_0x20             = true;
    uint16_t edns_buffer          = 1232;
    uint32_t max_upstream_queries = 30;
    uint16_t max_referral_depth   = 16;
    uint8_t  max_cname_chain      = 8;
    uint32_t query_timeout_ms     = 800;
    uint32_t overall_deadline_ms  = 5000;
};

/// Result of a successful resolution
struct ResolveResult {
    Message  response;
    uint32_t upstream_queries_used = 0;
    uint32_t latency_us            = 0;
};

using ResolveCallback = std::function<void(std::expected<ResolveResult, ResolveError>)>;
using PrimeCallback   = std::function<void(std::expected<void, ResolveError>)>;

/// The recursive resolver engine. Use it only from the loop's thread.
class RecursiveResolver {
public:
    /// `loop` and `cache` must outlive the resolver.
    RecursiveResolver(const ResolverConfig& config, net::EventLoop& loop, cache::Cache& cache);

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
    void resolve(const Question& question, ResolveCallback done);

    /// Prime the cache with the root NS set (done once at startup). Same
    /// callback guarantees as resolve().
    void prime_root(PrimeCallback done);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace dnsentinel::resolver
