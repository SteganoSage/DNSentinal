/// @file resolver/server_selection.cpp
/// SRTT bookkeeping and server choice.

#include "dnsentinel/resolver/server_selection.h"

#include <algorithm>
#include <cstdlib>
#include <utility>
#include <vector>

namespace dnsentinel::resolver {

using std::chrono::microseconds;
using std::chrono::milliseconds;

namespace {

constexpr uint32_t kPruneEvery = 1024;  // updates between sweeps for forgotten servers

}  // namespace

uint32_t ServerSelection::default_random(uint32_t n) { return arc4random_uniform(n); }

ServerSelection::ServerSelection(uint32_t explore_one_in, ClockFn clock, RandomFn random)
    : explore_one_in_(explore_one_in), clock_(std::move(clock)), random_(std::move(random)) {}

const ServerSelection::Info* ServerSelection::fresh(Address server) const {
    auto it = servers_.find(server);
    if (it == servers_.end() || clock_() - it->second.updated > kForgetAfter) return nullptr;
    return &it->second;
}

ServerSelection::Info& ServerSelection::entry(Address server) {
    Info& info = servers_[server];
    if (info.updated != Clock::time_point{} && clock_() - info.updated > kForgetAfter) info = Info{};
    return info;
}

void ServerSelection::touched(Info& info) {
    info.updated = clock_();
    if (++updates_ % kPruneEvery == 0) {
        const auto now = clock_();
        std::erase_if(servers_, [&](const auto& kv) { return now - kv.second.updated > kForgetAfter; });
    }
}

ServerSelection::Address ServerSelection::pick(std::span<const Address> candidates) {
    const auto n = static_cast<uint32_t>(candidates.size());
    if (n > 1 && explore_one_in_ != 0 && random_(explore_one_in_) == 0) return candidates[random_(n)];

    // Deprioritised servers last, then by SRTT.
    using Rank = std::pair<bool, microseconds>;
    auto rank  = [this](Address a) {
        const Info* info = fresh(a);
        if (!info) return Rank{false, kUnmeasured};
        return Rank{info->failures >= kMaxFailures, info->measured ? info->srtt : kUnmeasured};
    };
    std::vector<Address> best;
    Rank                 best_rank{};
    for (Address a : candidates) {
        const Rank r = rank(a);
        if (best.empty() || r < best_rank) {
            best      = {a};
            best_rank = r;
        } else if (r == best_rank) {
            best.push_back(a);
        }
    }
    // Ties, such as several servers never measured, spread the load.
    return best.size() == 1 ? best.front() : best[random_(static_cast<uint32_t>(best.size()))];
}

milliseconds ServerSelection::timeout(Address server, milliseconds ceiling) const {
    const Info* info = fresh(server);
    if (!info || !info->measured) return ceiling;
    const auto rto = std::chrono::ceil<milliseconds>(info->srtt + 4 * info->rttvar);
    return std::clamp(rto, std::min(kMinTimeout, ceiling), ceiling);
}

void ServerSelection::record_answer(Address server, std::optional<microseconds> rtt) {
    Info& info    = entry(server);
    info.failures = 0;
    if (rtt) {
        const microseconds sample = std::max(*rtt, microseconds(0));
        if (!info.measured) {  // first sample (RFC 6298 §2.2)
            info.srtt     = sample;
            info.rttvar   = sample / 2;
            info.measured = true;
        } else {
            const microseconds error = info.srtt > sample ? info.srtt - sample : sample - info.srtt;
            info.rttvar = (3 * info.rttvar + error) / 4;
            info.srtt   = (7 * info.srtt + sample) / 8;
        }
    }
    touched(info);
}

void ServerSelection::record_unusable(Address server) {
    Info& info = entry(server);
    ++info.failures;
    touched(info);
}

void ServerSelection::record_failure(Address server) {
    Info& info = entry(server);
    if (!info.measured) {  // a timeout is a measurement too: a bad one
        info.srtt     = kUnmeasured;
        info.measured = true;
    }
    info.srtt = std::min(info.srtt + kTimeoutPenalty, kMaxSrtt);
    ++info.failures;
    touched(info);
}

std::optional<ServerSelection::Info> ServerSelection::info(Address server) const {
    const Info* info = fresh(server);
    return info ? std::optional(*info) : std::nullopt;
}

}  // namespace dnsentinel::resolver
