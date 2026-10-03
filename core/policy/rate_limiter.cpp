/// @file policy/rate_limiter.cpp
/// Token buckets per client.

#include "dnsentinel/policy/rate_limiter.h"

#include <algorithm>
#include <utility>

namespace dnsentinel::policy {

RateLimiter::RateLimiter(RateLimitConfig config) : config_(std::move(config)) {
    config_.burst = std::max<uint32_t>(config_.burst, 1);  // a bucket must hold at least one query
}

bool RateLimiter::take(Bucket& bucket, Clock::time_point now) {
    const double elapsed = std::chrono::duration<double>(now - bucket.last).count();
    bucket.tokens        = std::min<double>(config_.burst, bucket.tokens + elapsed * config_.qps);
    bucket.last          = now;
    if (bucket.tokens < 1) {
        ++limited_;
        return false;
    }
    bucket.tokens -= 1;
    return true;
}

void RateLimiter::forget_idle(Clock::time_point now) {
    // A bucket that has refilled completely is no different from a new one.
    std::erase_if(buckets_, [&](const auto& entry) {
        const Bucket& b = entry.second;
        return b.tokens + std::chrono::duration<double>(now - b.last).count() * config_.qps >= config_.burst;
    });
    last_sweep_ = now;
}

bool RateLimiter::allow(const sockaddr_storage& client, Clock::time_point now) {
    if (!enabled()) return true;
    auto ip = ip_address(client);
    if (!ip) return true;
    if (std::any_of(config_.exempt.begin(), config_.exempt.end(), [&](const Subnet& s) { return s.contains(client); })) {
        return true;
    }

    if (auto it = buckets_.find(*ip); it != buckets_.end()) return take(it->second, now);
    if (buckets_.size() >= config_.max_clients && now - last_sweep_ >= std::chrono::seconds(1)) forget_idle(now);
    if (buckets_.size() >= config_.max_clients) {
        if (!overflow_used_) overflow_ = Bucket{static_cast<double>(config_.burst), now};
        overflow_used_ = true;
        return take(overflow_, now);
    }
    return take(buckets_.emplace(*ip, Bucket{static_cast<double>(config_.burst), now}).first->second, now);
}

}  // namespace dnsentinel::policy
