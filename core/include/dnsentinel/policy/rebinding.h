#pragma once
/// @file policy/rebinding.h
/// DNS rebinding protection (plan §5.8, README §7.6.4). A web page from
/// evil.com may talk to evil.com; if evil.com then resolves to 192.168.1.1,
/// the page's JavaScript reaches the victim's router. So addresses in
/// private and special ranges are removed from answers for public names.

#include "dnsentinel/types.h"

#include <vector>

namespace dnsentinel::policy {

struct RebindingConfig {
    bool enabled = true;
    /// Names at or below these may resolve to private addresses: local
    /// domains, split-horizon zones, services like plex.direct. The config
    /// loader adds the resolver's stub zones.
    std::vector<Name> exempt = default_exempt();

    /// home.arpa (RFC 8375), internal (reserved for private use), localhost,
    /// and the common home-router domains local, lan and home.
    static std::vector<Name> default_exempt();
};

/// Whether an A or AAAA record's address is in a private or special range:
/// 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16,
/// 172.16.0.0/12, 192.168.0.0/16, ::/128, ::1/128, fc00::/7, fe80::/10, and
/// IPv4-mapped IPv6 forms of the IPv4 ones. False for any other record.
[[nodiscard]] bool is_private_address(const RData& rdata);

class RebindingFilter {
public:
    explicit RebindingFilter(RebindingConfig config);

    /// Remove every A and AAAA record with a private address from `answers`
    /// and return them, unless the filter is off or `qname` is exempt.
    /// Only the query name decides: it is the name the browser trusts, so an
    /// exempt name further down the CNAME chain (evil.com → router.home)
    /// doesn't exempt it.
    std::vector<RR> strip(const Name& qname, std::vector<RR>& answers) const;

    [[nodiscard]] bool                   exempt(const Name& qname) const;
    [[nodiscard]] const RebindingConfig& config() const { return config_; }

private:
    RebindingConfig config_;
};

}  // namespace dnsentinel::policy
