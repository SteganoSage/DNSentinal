#pragma once
/// @file resolver/recursive_resolver.h
/// Iterative recursive DNS resolver — walks the delegation tree from root hints.

#include "dnsentinel/cache/cache.h"
#include "dnsentinel/types.h"

#include <cstdint>
#include <expected>
#include <functional>
#include <string>

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

/// The recursive resolver engine.
class RecursiveResolver {
public:
    RecursiveResolver(const ResolverConfig& config, cache::Cache& cache);
    ~RecursiveResolver();

    /// Resolve a question by iteratively walking the delegation tree.
    /// This is the core algorithm (§7.3 of the design doc).
    [[nodiscard]]
    std::expected<ResolveResult, ResolveError>
    resolve(const Question& question);

    /// Prime the cache with the root NS set (done once at startup).
    void prime_root();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace dnsentinel::resolver
