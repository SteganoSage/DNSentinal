#pragma once
/// @file cache/cache.h
/// Sharded LRU DNS cache with TTL, negative caching, serve-stale, and prefetch.

#include "dnsentinel/types.h"

#include <chrono>
#include <cstddef>
#include <functional>
#include <mutex>
#include <optional>
#include <vector>

namespace dnsentinel::cache {

using Clock = std::chrono::steady_clock;
using TimePoint = Clock::time_point;

struct CacheEntry {
    std::vector<RR> records;
    TrustRank       trust      = TrustRank::Additional;
    TimePoint       expires_at;
    TimePoint       inserted_at;
    uint64_t        hit_count  = 0;
    bool            is_negative = false;  // NXDOMAIN or NODATA
};

struct CacheConfig {
    size_t   max_memory_bytes   = 256 * 1024 * 1024;
    size_t   num_shards         = 16;
    uint32_t min_ttl            = 0;
    uint32_t max_ttl            = 86400;
    bool     serve_stale        = true;
    uint32_t stale_ttl          = 30;
    uint32_t max_stale_age      = 86400;
    bool     prefetch           = true;
    uint8_t  prefetch_threshold = 10;  // percent of TTL remaining
};

struct CacheKey {
    Name     name;
    uint16_t qtype;
    uint16_t qclass = 1;
};

/// Result of a cache lookup
struct LookupResult {
    std::optional<CacheEntry> entry;
    bool is_stale     = false;   // entry is expired but within stale window
    bool needs_prefetch = false; // entry is near expiry, trigger background refresh
};

/// Thread-safe sharded LRU DNS cache.
class Cache {
public:
    explicit Cache(const CacheConfig& config);
    ~Cache();

    /// Look up a cache entry. Returns nullopt on miss.
    [[nodiscard]] LookupResult lookup(const CacheKey& key);

    /// Insert or update a cache entry. Respects trust ranking —
    /// lower-ranked data never overwrites higher-ranked data.
    void insert(const CacheKey& key, std::vector<RR> records,
                TrustRank trust, uint32_t ttl, bool negative = false);

    /// Remove a specific entry.
    void evict(const CacheKey& key);

    /// Flush the entire cache.
    void flush();

    /// Stats
    [[nodiscard]] uint64_t hits() const;
    [[nodiscard]] uint64_t misses() const;
    [[nodiscard]] size_t   size() const;       // number of entries
    [[nodiscard]] size_t   memory_used() const;

private:
    struct Shard;
    std::vector<std::unique_ptr<Shard>> shards_;
    CacheConfig config_;

    [[nodiscard]] size_t shard_for(const CacheKey& key) const;
};

}  // namespace dnsentinel::cache
