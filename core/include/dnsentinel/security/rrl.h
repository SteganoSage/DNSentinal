#pragma once
/// @file security/rrl.h
/// Response Rate Limiting (plan §5.9, README §7.6.5). A query with a forged
/// source address makes us send the answer to the victim whose address was
/// forged, and a small query for a big answer makes us an amplifier. RRL
/// caps how many identical responses go to one client network per second.
/// Most responses over the cap are dropped; every `slip`-th goes out
/// truncated (TC set, no records), so a real client whose address is being
/// forged can still get its answer over TCP, which can't be spoofed.
///
/// UDP only: a TCP client has completed a handshake from its address.

#include "dnsentinel/policy/acl.h"
#include "dnsentinel/types.h"

#include <chrono>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace dnsentinel::security {

struct RrlConfig {
    uint32_t responses_per_second = 0;  // identical responses per client network; 0 = off
    uint32_t window_seconds       = 1;  // counts reset this often
    uint32_t slip                 = 2;  // every Nth response over the cap is sent truncated; 0 = none, 1 = all
    uint8_t  ipv4_prefix          = 24;  // what counts as one client network
    uint8_t  ipv6_prefix          = 56;
    std::vector<policy::Subnet> exempt{};  // never limited
    /// Fingerprints tracked at once; past this, as in RateLimiter, expired
    /// ones are forgotten (at most once a second) and then new ones share one
    /// counter.
    size_t max_entries = 65536;
};

enum class RrlVerdict {
    Send,  // under the cap
    Drop,  // over it: send nothing
    Slip,  // over it: send truncated()
};

class ResponseRateLimiter {
public:
    using Clock = std::chrono::steady_clock;

    explicit ResponseRateLimiter(RrlConfig config);

    /// Count one UDP response to `client` at `now` and decide its fate.
    /// Identical means the same client network, name, type and rcode. For
    /// NXDOMAIN and empty answers the name is the zone (the SOA owner in the
    /// authority section), as in BIND's RRL: otherwise a flood of random
    /// names would make every response look different.
    RrlVerdict check(const sockaddr_storage& client, const Message& response, Clock::time_point now);

    [[nodiscard]] bool     enabled() const { return config_.responses_per_second > 0; }
    [[nodiscard]] uint64_t dropped() const { return dropped_; }
    [[nodiscard]] uint64_t slipped() const { return slipped_; }
    [[nodiscard]] size_t   tracked() const { return entries_.size(); }
    [[nodiscard]] const RrlConfig& config() const { return config_; }

private:
    struct Entry {
        Clock::time_point window_start;
        uint32_t          sent   = 0;  // responses counted in this window
        uint32_t          excess = 0;  // how many of them were over the cap
    };
    RrlVerdict count(Entry& entry, Clock::time_point now);
    void       forget_expired(Clock::time_point now);

    RrlConfig                              config_;
    Clock::duration                        window_;
    std::unordered_map<std::string, Entry> entries_;  // fingerprint → counts
    Entry                                  overflow_;
    bool                                   overflow_used_ = false;
    Clock::time_point                      last_sweep_{};
    uint64_t                               dropped_ = 0;
    uint64_t                               slipped_ = 0;
};

/// What a slip sends instead of `response`: the same header and question,
/// TC set, and no records, so the client asks again over TCP.
[[nodiscard]] Message truncated(const Message& response);

}  // namespace dnsentinel::security
