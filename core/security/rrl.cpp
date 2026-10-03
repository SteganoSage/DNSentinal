/// @file security/rrl.cpp
/// Response fingerprints and per-window counts.

#include "dnsentinel/security/rrl.h"

#include <algorithm>
#include <utility>

namespace dnsentinel::security {

namespace {

/// The name a response is counted under: the zone for negative answers.
std::string counted_name(const Message& response) {
    const bool negative = response.header.rcode == static_cast<uint8_t>(RCode::NXDomain) ||
                          (response.header.rcode == static_cast<uint8_t>(RCode::NoError) && response.answers.empty());
    if (negative) {
        for (const auto& rr : response.authority) {
            if (rr.type == RRType::SOA) return rr.name.to_string();
        }
    }
    return response.questions.empty() ? std::string() : response.questions.front().qname.to_string();
}

}  // namespace

ResponseRateLimiter::ResponseRateLimiter(RrlConfig config)
    : config_(std::move(config)), window_(std::chrono::seconds(std::max<uint32_t>(config_.window_seconds, 1))) {}

RrlVerdict ResponseRateLimiter::count(Entry& entry, Clock::time_point now) {
    if (now - entry.window_start >= window_) entry = Entry{now, 0, 0};
    const uint64_t cap = uint64_t{config_.responses_per_second} * (window_ / std::chrono::seconds(1));
    if (++entry.sent <= cap) return RrlVerdict::Send;
    ++entry.excess;
    if (config_.slip > 0 && entry.excess % config_.slip == 0) {
        ++slipped_;
        return RrlVerdict::Slip;
    }
    ++dropped_;
    return RrlVerdict::Drop;
}

void ResponseRateLimiter::forget_expired(Clock::time_point now) {
    std::erase_if(entries_, [&](const auto& entry) { return now - entry.second.window_start >= window_; });
    last_sweep_ = now;
}

RrlVerdict ResponseRateLimiter::check(const sockaddr_storage& client, const Message& response, Clock::time_point now) {
    if (!enabled()) return RrlVerdict::Send;
    auto ip = policy::ip_address(client);
    if (!ip) return RrlVerdict::Send;
    if (std::any_of(config_.exempt.begin(), config_.exempt.end(),
                    [&](const policy::Subnet& s) { return s.contains(client); })) {
        return RrlVerdict::Send;
    }

    const policy::IpAddress network = ip->network(ip->family == AF_INET ? config_.ipv4_prefix : config_.ipv6_prefix);
    const uint16_t          qtype   = response.questions.empty() ? 0 : response.questions.front().qtype;
    std::string             key;
    key.reserve(24 + 64);
    key += static_cast<char>(network.family);
    key.append(reinterpret_cast<const char*>(network.bytes.data()), network.bytes.size());
    key += static_cast<char>(response.header.rcode);
    key += static_cast<char>(qtype >> 8);
    key += static_cast<char>(qtype & 0xFF);
    key += counted_name(response);

    if (auto it = entries_.find(key); it != entries_.end()) return count(it->second, now);
    if (entries_.size() >= config_.max_entries && now - last_sweep_ >= std::chrono::seconds(1)) forget_expired(now);
    if (entries_.size() >= config_.max_entries) {
        if (!overflow_used_) overflow_ = Entry{now, 0, 0};
        overflow_used_ = true;
        return count(overflow_, now);
    }
    return count(entries_.emplace(std::move(key), Entry{now, 0, 0}).first->second, now);
}

Message truncated(const Message& response) {
    Message slip;
    slip.header    = response.header;
    slip.header.tc = true;
    slip.questions = response.questions;
    slip.edns      = response.edns;
    return slip;
}

}  // namespace dnsentinel::security
