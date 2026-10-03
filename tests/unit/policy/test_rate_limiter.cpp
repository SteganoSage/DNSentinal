#include "dnsentinel/policy/rate_limiter.h"

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <chrono>
#include <string>

using namespace dnsentinel::policy;
using namespace std::chrono_literals;

namespace {

using Clock = RateLimiter::Clock;
const Clock::time_point t0 = Clock::time_point{} + 1h;  // any fixed moment

sockaddr_storage client(const char* ip) {
    sockaddr_storage addr{};
    auto* v4 = reinterpret_cast<sockaddr_in*>(&addr);
    auto* v6 = reinterpret_cast<sockaddr_in6*>(&addr);
    if (inet_pton(AF_INET, ip, &v4->sin_addr) == 1) {
        v4->sin_family = AF_INET;
    } else {
        addr = {};
        EXPECT_EQ(inet_pton(AF_INET6, ip, &v6->sin6_addr), 1) << ip;
        v6->sin6_family = AF_INET6;
    }
    return addr;
}

/// How many of `count` queries from `ip` at `when` are let through.
int allowed(RateLimiter& limiter, const char* ip, int count, Clock::time_point when) {
    int ok = 0;
    for (int i = 0; i < count; ++i) ok += limiter.allow(client(ip), when);
    return ok;
}

}  // namespace

TEST(RateLimiter, AQuietClientMaySendItsBurst) {
    RateLimiter limiter({.qps = 10, .burst = 5});
    EXPECT_EQ(allowed(limiter, "192.168.1.5", 8, t0), 5);
    EXPECT_EQ(limiter.limited(), 3u);
}

TEST(RateLimiter, RefillsAtTheConfiguredRate) {
    RateLimiter limiter({.qps = 10, .burst = 5});
    ASSERT_EQ(allowed(limiter, "192.168.1.5", 5, t0), 5);
    EXPECT_EQ(allowed(limiter, "192.168.1.5", 3, t0 + 100ms), 1);  // 10/s: one token per 100 ms
    EXPECT_EQ(allowed(limiter, "192.168.1.5", 3, t0 + 350ms), 2);
    EXPECT_EQ(allowed(limiter, "192.168.1.5", 20, t0 + 1h), 5);  // a long rest refills only up to the burst
}

TEST(RateLimiter, SustainedRateIsTheLimit) {
    // A client sending 50 queries/s for 10 s against a 20/s limit (burst 20).
    RateLimiter limiter({.qps = 20, .burst = 20});
    int ok = 0;
    for (int i = 0; i < 500; ++i) ok += limiter.allow(client("10.0.0.7"), t0 + i * 20ms);
    EXPECT_NEAR(ok, 20 + 20 * 10, 2);  // the burst, then 20 per second
}

TEST(RateLimiter, ClientsHaveTheirOwnBuckets) {
    RateLimiter limiter({.qps = 1, .burst = 2});
    ASSERT_EQ(allowed(limiter, "192.168.1.5", 2, t0), 2);
    EXPECT_EQ(allowed(limiter, "192.168.1.5", 1, t0), 0);
    EXPECT_EQ(allowed(limiter, "192.168.1.6", 2, t0), 2);
    EXPECT_EQ(allowed(limiter, "::ffff:192.168.1.5", 1, t0), 0);  // the same client, IPv4-mapped
    EXPECT_EQ(allowed(limiter, "fd00::5", 2, t0), 2);
    EXPECT_EQ(limiter.tracked(), 3u);
}

TEST(RateLimiter, ZeroQpsMeansNoLimit) {
    RateLimiter limiter({.qps = 0});
    EXPECT_FALSE(limiter.enabled());
    EXPECT_EQ(allowed(limiter, "192.168.1.5", 10000, t0), 10000);
    EXPECT_EQ(limiter.tracked(), 0u);
}

TEST(RateLimiter, ExemptClientsAreNeverLimited) {
    RateLimiter limiter({.qps = 1, .burst = 1, .exempt = {*parse_subnet("192.168.1.1")}});
    EXPECT_EQ(allowed(limiter, "192.168.1.1", 100, t0), 100);  // e.g. a router forwarding for a LAN
    EXPECT_EQ(allowed(limiter, "192.168.1.2", 100, t0), 1);
}

TEST(RateLimiter, NonIpClientsAreLetThrough) {
    RateLimiter limiter({.qps = 1, .burst = 1});
    sockaddr_storage unknown{};
    for (int i = 0; i < 5; ++i) EXPECT_TRUE(limiter.allow(unknown, t0));
}

TEST(RateLimiter, AFullTableForgetsIdleClientsThenSharesOneBucket) {
    RateLimiter limiter({.qps = 1, .burst = 2, .max_clients = 3});
    for (const char* ip : {"10.0.0.1", "10.0.0.2", "10.0.0.3"}) ASSERT_EQ(allowed(limiter, ip, 1, t0), 1);
    ASSERT_EQ(limiter.tracked(), 3u);

    // None of them is idle yet, so newcomers share one bucket (burst 2 between them).
    EXPECT_EQ(allowed(limiter, "10.0.0.4", 1, t0) + allowed(limiter, "10.0.0.5", 1, t0) +
                  allowed(limiter, "10.0.0.6", 1, t0),
              2);
    EXPECT_EQ(limiter.tracked(), 3u);  // a flood of new addresses doesn't grow the table

    // Once the first three have refilled, they are forgotten and newcomers get their own buckets.
    EXPECT_EQ(allowed(limiter, "10.0.0.7", 2, t0 + 10s), 2);
    EXPECT_EQ(limiter.tracked(), 1u);
}
