/// @file cache/cache.cpp
/// Sharded LRU cache: per-shard hash index + recency list, TTL expiry,
/// trust ranking, and approximate memory accounting.

#include "dnsentinel/cache/cache.h"

#include <algorithm>
#include <functional>
#include <iterator>
#include <list>
#include <string>
#include <unordered_map>
#include <variant>

namespace dnsentinel::cache {

namespace {

struct KeyHash {
    size_t operator()(const CacheKey& k) const noexcept {
        size_t h = k.name.hash();
        h ^= ((size_t{k.qtype} << 16) | k.qclass) + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
        return h;
    }
};

// ─── Approximate memory accounting ──────────────────────────────────────────
// Close enough for eviction decisions; not byte-exact.

constexpr size_t kNodeOverhead = 64;  // list node links + hash node + bucket slot

size_t name_bytes(const Name& n) {
    // Two vectors of labels (canonical + original case).
    return 2 * (n.labels.size() * sizeof(std::string) + n.wire_length());
}

size_t rdata_bytes(const RData& rdata) {
    struct Visitor {
        size_t operator()(const RDataA&) const { return 0; }
        size_t operator()(const RDataAAAA&) const { return 0; }
        size_t operator()(const RDataNS& d) const { return name_bytes(d.nsdname); }
        size_t operator()(const RDataCNAME& d) const { return name_bytes(d.target); }
        size_t operator()(const RDataPTR& d) const { return name_bytes(d.ptrdname); }
        size_t operator()(const RDataMX& d) const { return name_bytes(d.exchange); }
        size_t operator()(const RDataSOA& d) const { return name_bytes(d.mname) + name_bytes(d.rname); }
        size_t operator()(const RDataTXT& d) const {
            size_t bytes = d.strings.size() * sizeof(std::string);
            for (const auto& s : d.strings) bytes += s.size();
            return bytes;
        }
        size_t operator()(const RDataRaw& d) const { return d.data.size(); }
    };
    return std::visit(Visitor{}, rdata);
}

size_t entry_bytes(const CacheKey& key, const CacheEntry& entry) {
    size_t bytes = kNodeOverhead + sizeof(CacheKey) + sizeof(CacheEntry) + name_bytes(key.name);
    for (const auto& rr : entry.records) {
        bytes += sizeof(RR) + name_bytes(rr.name) + rdata_bytes(rr.rdata);
    }
    return bytes;
}

}  // namespace

// ─── Shard ──────────────────────────────────────────────────────────────────

struct Cache::Shard {
    struct Node {
        CacheKey   key;
        CacheEntry entry;
        size_t     bytes = 0;
    };
    using NodeIter = std::list<Node>::iterator;

    std::mutex      mutex;
    std::list<Node> lru;  // front = most recently used
    // The index refers to the key stored in the list node (list nodes never
    // move), so each key is stored once.
    std::unordered_map<std::reference_wrapper<const CacheKey>, NodeIter, KeyHash,
                       std::equal_to<CacheKey>>
           index;
    size_t bytes = 0;

    void erase(NodeIter node) {
        bytes -= node->bytes;
        index.erase(node->key);
        lru.erase(node);
    }
};

// ─── Cache ──────────────────────────────────────────────────────────────────

Cache::Cache(const CacheConfig& config, ClockFn clock)
    : config_(config), clock_(std::move(clock)) {
    const size_t n = std::max<size_t>(config_.num_shards, 1);
    shard_budget_  = config_.max_memory_bytes / n;
    shards_.reserve(n);
    for (size_t i = 0; i < n; ++i) shards_.push_back(std::make_unique<Shard>());
}

Cache::~Cache() = default;

size_t Cache::shard_for(const CacheKey& key) const {
    // High bits pick the shard; the shard's own index uses the full hash.
    return (KeyHash{}(key) >> 32) % shards_.size();
}

LookupResult Cache::lookup(const CacheKey& key) {
    Shard&          shard = *shards_[shard_for(key)];
    const TimePoint now   = clock_();

    LookupResult result;
    {
        std::lock_guard lock(shard.mutex);
        auto it = shard.index.find(key);
        // Expired entries stay until evicted: serve-stale will want them.
        if (it == shard.index.end() || it->second->entry.expires_at <= now) {
            misses_.fetch_add(1, std::memory_order_relaxed);
            return result;
        }
        Shard::NodeIter node = it->second;
        shard.lru.splice(shard.lru.begin(), shard.lru, node);
        ++node->entry.hit_count;
        result.entry = node->entry;
    }
    hits_.fetch_add(1, std::memory_order_relaxed);

    const auto remaining =
        std::chrono::duration_cast<std::chrono::seconds>(result.entry->expires_at - now).count();
    for (auto& rr : result.entry->records) rr.ttl = static_cast<uint32_t>(remaining);
    return result;
}

void Cache::insert(const CacheKey& key, std::vector<RR> records, TrustRank trust,
                   uint32_t ttl, bool negative) {
    // min/max rather than std::clamp: a misconfigured min > max must not be UB.
    const uint32_t effective = std::min(std::max(ttl, config_.min_ttl), config_.max_ttl);
    if (effective == 0) return;  // TTL 0 means "do not cache"

    const TimePoint now = clock_();
    CacheEntry entry;
    entry.records     = std::move(records);
    entry.trust       = trust;
    entry.expires_at  = now + std::chrono::seconds(effective);
    entry.inserted_at = now;
    entry.is_negative = negative;
    const size_t bytes = entry_bytes(key, entry);

    Shard& shard = *shards_[shard_for(key)];
    std::lock_guard lock(shard.mutex);

    if (auto it = shard.index.find(key); it != shard.index.end()) {
        Shard::NodeIter node = it->second;
        // RFC 2181 §5.4.1: live data is never replaced by less trusted data.
        if (node->entry.expires_at > now && node->entry.trust > trust) return;
        if (bytes > shard_budget_) {
            shard.erase(node);  // the old data is superseded either way
            return;
        }
        shard.bytes = shard.bytes - node->bytes + bytes;
        node->entry = std::move(entry);
        node->bytes = bytes;
        shard.lru.splice(shard.lru.begin(), shard.lru, node);
    } else {
        if (bytes > shard_budget_) return;  // could never fit
        shard.lru.push_front(Shard::Node{key, std::move(entry), bytes});
        shard.index.emplace(shard.lru.front().key, shard.lru.begin());
        shard.bytes += bytes;
    }

    // Evict least recently used entries; the one just written is at the front.
    while (shard.bytes > shard_budget_ && shard.lru.size() > 1) {
        shard.erase(std::prev(shard.lru.end()));
    }
}

void Cache::evict(const CacheKey& key) {
    Shard& shard = *shards_[shard_for(key)];
    std::lock_guard lock(shard.mutex);
    if (auto it = shard.index.find(key); it != shard.index.end()) shard.erase(it->second);
}

void Cache::flush() {
    for (auto& shard : shards_) {
        std::lock_guard lock(shard->mutex);
        shard->index.clear();
        shard->lru.clear();
        shard->bytes = 0;
    }
}

uint64_t Cache::hits() const { return hits_.load(std::memory_order_relaxed); }

uint64_t Cache::misses() const { return misses_.load(std::memory_order_relaxed); }

size_t Cache::size() const {
    size_t total = 0;
    for (const auto& shard : shards_) {
        std::lock_guard lock(shard->mutex);
        total += shard->lru.size();
    }
    return total;
}

size_t Cache::memory_used() const {
    size_t total = 0;
    for (const auto& shard : shards_) {
        std::lock_guard lock(shard->mutex);
        total += shard->bytes;
    }
    return total;
}

}  // namespace dnsentinel::cache
