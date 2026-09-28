#pragma once
/// @file resolver/server_selection.h
/// Which upstream server to ask, and how long to wait for it (plan §4.3).
///
/// Keeps a smoothed round-trip time (SRTT) and its variance per server,
/// as TCP does for retransmission timeouts. The resolver asks the fastest
/// known server for a zone, now and then a random one in case it has
/// improved, and soon stops waiting on dead ones: a timeout adds a large
/// penalty, and five failures in a row push a server behind all others.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <unordered_map>

namespace dnsentinel::resolver {

class ServerSelection {
public:
    using Address  = uint32_t;  // IPv4, network byte order (as in RDataA)
    using Clock    = std::chrono::steady_clock;
    using ClockFn  = std::function<Clock::time_point()>;
    using RandomFn = std::function<uint32_t(uint32_t)>;  // uniform in [0, n)

    /// Assumed for a server never measured: optimistic enough that it gets
    /// tried, not so low that it beats servers proven to be fast.
    static constexpr std::chrono::microseconds kUnmeasured{400'000};
    static constexpr std::chrono::microseconds kTimeoutPenalty{2'000'000};
    static constexpr std::chrono::microseconds kMaxSrtt{5'000'000};  // penalties stop adding up, so a revived server can recover
    static constexpr uint32_t                  kMaxFailures = 5;  // in a row, then deprioritised
    static constexpr std::chrono::milliseconds kMinTimeout{100};
    static constexpr std::chrono::minutes      kForgetAfter{15};  // untouched this long: unmeasured again

    struct Info {
        bool                      measured = false;  // srtt holds real samples (and penalties)
        std::chrono::microseconds srtt{};
        std::chrono::microseconds rttvar{};
        uint32_t                  failures = 0;  // in a row
        Clock::time_point         updated;
    };

    /// Pick a random candidate once in `explore_one_in` picks (0: never).
    /// `clock` and `random` exist so tests can control them.
    explicit ServerSelection(uint32_t explore_one_in = 20, ClockFn clock = Clock::now, RandomFn random = default_random);

    /// The candidate to ask next: the lowest SRTT among those not
    /// deprioritised, ties broken at random. `candidates` must not be empty.
    [[nodiscard]] Address pick(std::span<const Address> candidates);

    /// How long to wait for `server`: SRTT plus four deviations (TCP's
    /// RTO), at least kMinTimeout and at most `ceiling`. A server with no
    /// measurements gets `ceiling`.
    [[nodiscard]] std::chrono::milliseconds timeout(Address server, std::chrono::milliseconds ceiling) const;

    /// A usable response. `rtt` is its round trip when that is a clean
    /// sample (UDP); nullopt over TCP, where the handshake doubles it.
    void record_answer(Address server, std::optional<std::chrono::microseconds> rtt);

    /// A response we couldn't use: REFUSED, SERVFAIL, a lame or upward referral.
    void record_unusable(Address server);

    /// No response: timed out or unreachable.
    void record_failure(Address server);

    /// What is known about `server`, if anything (not yet forgotten).
    [[nodiscard]] std::optional<Info> info(Address server) const;

    [[nodiscard]] size_t size() const { return servers_.size(); }

    static uint32_t default_random(uint32_t n);

private:
    [[nodiscard]] const Info* fresh(Address server) const;
    Info& entry(Address server);  // creates an unmeasured one if needed
    void  touched(Info& info);

    uint32_t                          explore_one_in_;
    ClockFn                           clock_;
    RandomFn                          random_;
    std::unordered_map<Address, Info> servers_;
    uint32_t                          updates_ = 0;  // prune forgotten servers every so often
};

}  // namespace dnsentinel::resolver
