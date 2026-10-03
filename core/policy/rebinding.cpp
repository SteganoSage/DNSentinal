/// @file policy/rebinding.cpp
/// Private-address ranges and stripping them from answers.

#include "dnsentinel/policy/rebinding.h"

#include "dnsentinel/policy/acl.h"

#include <netinet/in.h>
#include <sys/socket.h>

#include <algorithm>
#include <cstring>

namespace dnsentinel::policy {

namespace {

/// The ranges, as subnets. Subnet::contains also matches IPv4-mapped IPv6
/// addresses against the IPv4 ones.
const std::vector<Subnet>& private_ranges() {
    static const std::vector<Subnet> ranges = [] {
        std::vector<Subnet> out;
        for (const char* text : {"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
                                 "172.16.0.0/12", "192.168.0.0/16", "::/128", "::1/128", "fc00::/7", "fe80::/10"}) {
            out.push_back(parse_subnet(text).value());
        }
        return out;
    }();
    return ranges;
}

bool in_private_range(const sockaddr_storage& address) {
    const auto& ranges = private_ranges();
    return std::any_of(ranges.begin(), ranges.end(), [&](const Subnet& s) { return s.contains(address); });
}

}  // namespace

std::vector<Name> RebindingConfig::default_exempt() {
    std::vector<Name> names;
    for (const char* text : {"home.arpa", "internal", "localhost", "local", "lan", "home"}) {
        names.push_back(*Name::from_string(text));
    }
    return names;
}

bool is_private_address(const RData& rdata) {
    sockaddr_storage address{};
    if (const auto* a = std::get_if<RDataA>(&rdata)) {
        auto* v4       = reinterpret_cast<sockaddr_in*>(&address);
        v4->sin_family = AF_INET;
        std::memcpy(&v4->sin_addr, &a->addr, 4);
    } else if (const auto* aaaa = std::get_if<RDataAAAA>(&rdata)) {
        auto* v6        = reinterpret_cast<sockaddr_in6*>(&address);
        v6->sin6_family = AF_INET6;
        std::memcpy(&v6->sin6_addr, aaaa->addr, 16);
    } else {
        return false;
    }
    return in_private_range(address);
}

RebindingFilter::RebindingFilter(RebindingConfig config) : config_(std::move(config)) {}

bool RebindingFilter::exempt(const Name& qname) const {
    return std::any_of(config_.exempt.begin(), config_.exempt.end(),
                       [&](const Name& zone) { return qname.is_subdomain_of(zone); });
}

std::vector<RR> RebindingFilter::strip(const Name& qname, std::vector<RR>& answers) const {
    std::vector<RR> removed;
    if (!config_.enabled || exempt(qname)) return removed;
    auto kept = std::stable_partition(answers.begin(), answers.end(),
                                      [](const RR& rr) { return !is_private_address(rr.rdata); });
    removed.assign(std::make_move_iterator(kept), std::make_move_iterator(answers.end()));
    answers.erase(kept, answers.end());
    return removed;
}

}  // namespace dnsentinel::policy
