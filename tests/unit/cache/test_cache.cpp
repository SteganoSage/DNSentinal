#include "dnsentinel/cache/cache.h"

#include "../wire/wire_test_util.h"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <random>
#include <string>
#include <thread>
#include <vector>

using namespace dnsentinel;
using namespace dnsentinel::cache;
using namespace dnsentinel::test;
using namespace std::chrono_literals;

namespace {

class CacheTest : public ::testing::Test {
protected:
    TimePoint now = TimePoint{} + 1000h;  // fake clock, advanced by tests

    Cache make_cache(CacheConfig config = {}) {
        return Cache(config, [this] { return now; });
    }

    static CacheKey key(std::string_view name_text, RRType type = RRType::A) {
        return {name(name_text), static_cast<uint16_t>(type), 1};
    }

    static std::vector<RR> a_records(std::string_view owner, int count = 1, uint32_t first = 1) {
        std::vector<RR> records;
        for (int i = 0; i < count; ++i) {
            records.push_back(make_rr(owner, RRType::A, RDataA{first + static_cast<uint32_t>(i)}));
        }
        return records;
    }

    static uint32_t first_addr(const LookupResult& r) {
        return std::get<RDataA>(r.entry->records.at(0).rdata).addr;
    }
};

}  // namespace

// ─── Basics ─────────────────────────────────────────────────────────────────

TEST_F(CacheTest, MissThenHit) {
    Cache cache = make_cache();
    EXPECT_FALSE(cache.lookup(key("example.com")).entry.has_value());

    cache.insert(key("example.com"), a_records("example.com", 2), TrustRank::Answer, 300);
    auto hit = cache.lookup(key("example.com"));
    ASSERT_TRUE(hit.entry.has_value());
    EXPECT_EQ(hit.entry->records, a_records("example.com", 2));  // RR == ignores trust
    EXPECT_EQ(hit.entry->trust, TrustRank::Answer);
    EXPECT_EQ(hit.entry->hit_count, 1u);
    EXPECT_FALSE(hit.is_stale);
    EXPECT_EQ(cache.hits(), 1u);
    EXPECT_EQ(cache.misses(), 1u);
    EXPECT_EQ(cache.size(), 1u);
}

TEST_F(CacheTest, KeyIsCaseInsensitiveAndTypeSpecific) {
    Cache cache = make_cache();
    cache.insert(key("Example.COM"), a_records("example.com"), TrustRank::Answer, 300);
    EXPECT_TRUE(cache.lookup(key("example.com")).entry.has_value());
    EXPECT_FALSE(cache.lookup(key("example.com", RRType::AAAA)).entry.has_value());
    EXPECT_FALSE(cache.lookup(CacheKey{name("example.com"), 1, 3}).entry.has_value());  // class CH
}

TEST_F(CacheTest, NegativeFlagIsKept) {
    Cache cache = make_cache();
    cache.insert(key("nope.example.com"), {}, TrustRank::Authority, 60, /*negative=*/true);
    auto hit = cache.lookup(key("nope.example.com"));
    ASSERT_TRUE(hit.entry.has_value());
    EXPECT_TRUE(hit.entry->is_negative);
    EXPECT_TRUE(hit.entry->records.empty());
}

// ─── TTL ────────────────────────────────────────────────────────────────────

TEST_F(CacheTest, TtlCountsDownThenExpires) {
    Cache cache = make_cache();
    cache.insert(key("example.com"), a_records("example.com"), TrustRank::Answer, 300);

    now += 100s;
    EXPECT_EQ(cache.lookup(key("example.com")).entry->records[0].ttl, 200u);

    now += 199s + 500ms;
    EXPECT_EQ(cache.lookup(key("example.com")).entry->records[0].ttl, 0u);

    now += 500ms;  // exactly 300s after insertion
    EXPECT_FALSE(cache.lookup(key("example.com")).entry.has_value());
}

TEST_F(CacheTest, TtlIsClamped) {
    Cache cache = make_cache({.min_ttl = 30, .max_ttl = 100});
    cache.insert(key("long.example"), a_records("long.example"), TrustRank::Answer, 1'000'000);
    cache.insert(key("short.example"), a_records("short.example"), TrustRank::Answer, 5);

    EXPECT_EQ(cache.lookup(key("long.example")).entry->records[0].ttl, 100u);
    now += 20s;
    EXPECT_TRUE(cache.lookup(key("short.example")).entry.has_value());  // lives 30s, not 5s
    now += 81s;
    EXPECT_FALSE(cache.lookup(key("long.example")).entry.has_value());
}

TEST_F(CacheTest, ZeroTtlIsNotCached) {
    Cache cache = make_cache();
    cache.insert(key("cdn.example"), a_records("cdn.example"), TrustRank::Answer, 0);
    EXPECT_EQ(cache.size(), 0u);
}

// ─── Trust ranking ──────────────────────────────────────────────────────────

TEST_F(CacheTest, LessTrustedDataNeverReplacesLiveData) {
    // The poisoning scenario: a forged record smuggled into an additional
    // section must not overwrite the authoritative answer.
    Cache cache = make_cache();
    cache.insert(key("bank.example"), a_records("bank.example", 1, 111), TrustRank::Answer, 300);
    cache.insert(key("bank.example"), a_records("bank.example", 1, 666), TrustRank::Additional, 300);
    EXPECT_EQ(first_addr(cache.lookup(key("bank.example"))), 111u);
}

TEST_F(CacheTest, EqualOrMoreTrustedDataReplaces) {
    Cache cache = make_cache();
    cache.insert(key("a.example"), a_records("a.example", 1, 1), TrustRank::Glue, 300);
    cache.insert(key("a.example"), a_records("a.example", 1, 2), TrustRank::Answer, 300);
    EXPECT_EQ(first_addr(cache.lookup(key("a.example"))), 2u);

    cache.insert(key("a.example"), a_records("a.example", 1, 3), TrustRank::Answer, 300);
    EXPECT_EQ(first_addr(cache.lookup(key("a.example"))), 3u);
    EXPECT_EQ(cache.size(), 1u);
}

TEST_F(CacheTest, ExpiredDataCanBeReplacedByLessTrustedData) {
    Cache cache = make_cache();
    cache.insert(key("a.example"), a_records("a.example", 1, 1), TrustRank::Answer, 10);
    now += 11s;
    cache.insert(key("a.example"), a_records("a.example", 1, 2), TrustRank::Glue, 300);
    EXPECT_EQ(first_addr(cache.lookup(key("a.example"))), 2u);
}

// ─── Memory and eviction ────────────────────────────────────────────────────

TEST_F(CacheTest, StaysWithinMemoryBudget) {
    Cache cache = make_cache({.max_memory_bytes = 8 * 1024, .num_shards = 1});
    for (int i = 0; i < 200; ++i) {
        std::string n = "host" + std::to_string(i) + ".example";
        cache.insert(key(n), a_records(n), TrustRank::Answer, 300);
        EXPECT_LE(cache.memory_used(), 8u * 1024);
    }
    EXPECT_LT(cache.size(), 200u);
    EXPECT_TRUE(cache.lookup(key("host199.example")).entry.has_value());  // newest kept
    EXPECT_FALSE(cache.lookup(key("host0.example")).entry.has_value());   // oldest evicted
}

TEST_F(CacheTest, EvictsLeastRecentlyUsed) {
    Cache cache = make_cache({.max_memory_bytes = 8 * 1024, .num_shards = 1});
    cache.insert(key("hot.example"), a_records("hot.example"), TrustRank::Answer, 300);
    cache.insert(key("cold.example"), a_records("cold.example"), TrustRank::Answer, 300);
    for (int i = 0; i < 200; ++i) {
        ASSERT_TRUE(cache.lookup(key("hot.example")).entry.has_value()) << "evicted at " << i;
        std::string n = "filler" + std::to_string(i) + ".example";
        cache.insert(key(n), a_records(n), TrustRank::Answer, 300);
    }
    EXPECT_FALSE(cache.lookup(key("cold.example")).entry.has_value());
}

TEST_F(CacheTest, OversizedEntryIsNotCached) {
    Cache cache = make_cache({.max_memory_bytes = 2048, .num_shards = 1});
    cache.insert(key("small.example"), a_records("small.example"), TrustRank::Answer, 300);
    cache.insert(key("huge.example"), a_records("huge.example", 100), TrustRank::Answer, 300);
    EXPECT_FALSE(cache.lookup(key("huge.example")).entry.has_value());
    EXPECT_TRUE(cache.lookup(key("small.example")).entry.has_value());  // not evicted for nothing
}

TEST_F(CacheTest, EvictAndFlush) {
    Cache cache = make_cache();
    cache.insert(key("a.example"), a_records("a.example"), TrustRank::Answer, 300);
    cache.insert(key("b.example"), a_records("b.example"), TrustRank::Answer, 300);
    cache.evict(key("a.example"));
    EXPECT_FALSE(cache.lookup(key("a.example")).entry.has_value());
    EXPECT_EQ(cache.size(), 1u);

    cache.flush();
    EXPECT_EQ(cache.size(), 0u);
    EXPECT_EQ(cache.memory_used(), 0u);
}

// ─── Concurrency ────────────────────────────────────────────────────────────

TEST(CacheConcurrency, ParallelInsertAndLookup) {
    Cache cache({.max_memory_bytes = 64 * 1024});
    constexpr int kThreads = 8, kOps = 5000;
    std::atomic<uint64_t> lookups{0};
    std::vector<std::thread> threads;
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&, t] {
            std::mt19937 rng(static_cast<uint32_t>(t));
            for (int i = 0; i < kOps; ++i) {
                std::string n = "h" + std::to_string(rng() % 500) + ".example";
                if (rng() % 2) {
                    cache.insert({name(n), 1, 1}, {make_rr(n, RRType::A, RDataA{1})}, TrustRank::Answer, 300);
                } else {
                    (void)cache.lookup({name(n), 1, 1});
                    lookups.fetch_add(1);
                }
            }
        });
    }
    for (auto& th : threads) th.join();
    EXPECT_EQ(cache.hits() + cache.misses(), lookups.load());
    EXPECT_LE(cache.memory_used(), 64u * 1024);
}
