#pragma once
/// @file cache/cache.h
/// Sharded LRU DNS cache with TTL, negative caching, serve-stale, and prefetch.

#include "dnsentinel/types.h"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <functional>
#include <memory>
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
    // Serve-stale (plan §7.1, RFC 8767): expired answers kept and used when
    // the upstream can't be reached.
    bool     serve_stale        = true;
    uint32_t stale_ttl          = 30;     // TTL of records served stale
    uint32_t max_stale_age      = 86400;  // seconds past expiry an entry may still be served
    uint32_t stale_answer_after_ms = 1800;  // RFC 8767 client-response timer: if resolving takes
                                            // longer, answer stale meanwhile; 0: only on failure
    // Prefetch (plan §7.2): refresh popular entries before they expire.
    bool     prefetch           = true;
    uint8_t  prefetch_threshold = 10;  // percent of TTL remaining
};

struct CacheKey {
    Name     name;
    uint16_t qtype  = 0;
    uint16_t qclass = 1;

    bool operator==(const CacheKey&) const = default;  // name compares case-insensitively
};

/// Result of a cache lookup
struct LookupResult {
    std::optional<CacheEntry> entry;
    bool is_stale     = false;   // entry is expired but within stale window
    bool needs_prefetch = false; // popular entry near expiry: refresh it in the background
};

/// Thread-safe sharded LRU DNS cache.
class Cache {
public:
    using ClockFn = std::function<TimePoint()>;

    /// `clock` exists so tests can control time; production uses the default.
    explicit Cache(const CacheConfig& config, ClockFn clock = Clock::now);
    ~Cache();

    /// Look up a cache entry. Returns nullopt on miss. On a hit, each
    /// record's TTL is the time remaining, in whole seconds, and
    /// needs_prefetch says the entry has been asked for more than once and
    /// is in its last prefetch_threshold percent of TTL.
    ///
    /// With `allow_stale` (and serve_stale on), an entry that expired less
    /// than max_stale_age ago is returned too, with is_stale set and every
    /// TTL stale_ttl. An entry past that window is dropped for good.
    [[nodiscard]] LookupResult lookup(const CacheKey& key, bool allow_stale = false);

    /// Insert or update a cache entry. Respects trust ranking —
    /// lower-ranked data never overwrites higher-ranked data.
    void insert(const CacheKey& key, std::vector<RR> records,
                TrustRank trust, uint32_t ttl, bool negative = false);

    /// Remove a specific entry.
    void evict(const CacheKey& key);

    /// Flush the entire cache.
    void flush();

    [[nodiscard]] const CacheConfig& config() const { return config_; }

    /// Stats
    [[nodiscard]] uint64_t hits() const;
    [[nodiscard]] uint64_t misses() const;
    [[nodiscard]] uint64_t stale_hits() const;  // expired entries handed out (serve-stale)
    [[nodiscard]] size_t   size() const;       // number of entries
    [[nodiscard]] size_t   memory_used() const;

private:
    struct Shard;
    std::vector<std::unique_ptr<Shard>> shards_;
    CacheConfig config_;
    ClockFn     clock_;
    size_t      shard_budget_;  // max_memory_bytes split evenly across shards
    std::atomic<uint64_t> hits_{0};
    std::atomic<uint64_t> misses_{0};
    std::atomic<uint64_t> stale_hits_{0};

    [[nodiscard]] size_t shard_for(const CacheKey& key) const;
};

}  // namespace dnsentinel::cache
