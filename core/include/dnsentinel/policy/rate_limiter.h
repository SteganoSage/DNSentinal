#pragma once
/// @file policy/rate_limiter.h
/// Per-client query rate limiting (plan §5.9, README §7.6.5): a token
/// bucket per client IP, so one misbehaving or infected device can't use up
/// the resolver for everyone else. The same algorithm traffic shapers use.

#include "dnsentinel/policy/acl.h"

#include <chrono>
#include <cstdint>
#include <unordered_map>
#include <vector>

namespace dnsentinel::policy {

struct RateLimitConfig {
    uint32_t   qps    = 100;  // sustained queries per second per client; 0 = no limit
    uint32_t   burst  = 200;  // queries a quiet client may send at once
    DenyAction action = DenyAction::Drop;  // for queries over the limit
    /// Never limited: e.g. a router that forwards a whole network's queries
    /// and so looks like one very busy client.
    std::vector<Subnet> exempt{};
    /// Clients tracked at once. When the table is full, idle clients are
    /// forgotten (at most once a second); if it is still full, new clients
    /// share one bucket, so a flood from many spoofed addresses can't grow
    /// the table or escape the limit.
    size_t max_clients = 65536;
};

class RateLimiter {
public:
    using Clock = std::chrono::steady_clock;

    explicit RateLimiter(RateLimitConfig config);

    /// Take a token for one query from `client` at `now` (which never goes
    /// backwards: a steady clock): true if it may go ahead. Always true when
    /// there is no limit, for exempt clients, and for anything that isn't an
    /// IP address.
    bool allow(const sockaddr_storage& client, Clock::time_point now);

    [[nodiscard]] bool     enabled() const { return config_.qps > 0; }
    [[nodiscard]] uint64_t limited() const { return limited_; }   // queries refused or dropped so far
    [[nodiscard]] size_t   tracked() const { return buckets_.size(); }
    [[nodiscard]] const RateLimitConfig& config() const { return config_; }

private:
    struct Bucket {
        double            tokens = 0;
        Clock::time_point last;  // when `tokens` was last brought up to date
    };
    bool take(Bucket& bucket, Clock::time_point now);
    void forget_idle(Clock::time_point now);

    RateLimitConfig                                       config_;
    std::unordered_map<IpAddress, Bucket, IpAddressHash> buckets_;
    Bucket                                                overflow_;  // shared once the table is full
    bool                                                  overflow_used_ = false;
    Clock::time_point                                     last_sweep_{};
    uint64_t                                              limited_ = 0;
};

}  // namespace dnsentinel::policy
