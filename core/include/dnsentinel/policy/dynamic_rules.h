#pragma once
/// @file policy/dynamic_rules.h
/// Time-limited rules from the ML slow path (README §7.6.6): "block
/// `*.attacker.example` for client 192.168.1.23 for an hour".
///
/// Kept apart from the block lists on purpose. ML can be wrong, and a rule
/// that expires undoes itself where a list entry would not; an attacker who
/// could trigger false verdicts must not get names blocked for good; tunnel
/// verdicts are per client, the lists are for everyone; and the lists are
/// rebuilt from files and swapped in whole (§7.6.2). The only ways into the
/// permanent lists stay the feeds and the custom file a person edits.
///
/// Checked before the lists on every query, on the event-loop thread (as are
/// adding and removing rules), so there is no locking.

#include "dnsentinel/policy/acl.h"
#include "dnsentinel/policy/blocklists.h"
#include "dnsentinel/types.h"

#include <sys/socket.h>

#include <chrono>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace dnsentinel::policy {

struct DynamicRulesConfig {
    bool          enabled   = true;
    size_t        max_rules = 10000;  // more are refused: a flood of verdicts can't grow memory without bound
    uint32_t      max_ttl   = 86400;  // seconds; a rule asked for longer gets this
    BlockResponse response  = BlockResponse::NxDomain;  // README §7.6.2: NXDOMAIN for malware verdicts
};

struct DynamicRule {
    uint64_t              id = 0;
    Name                  domain;  // the name and every name below it
    std::optional<Subnet> client;  // whose queries it applies to; none: everyone's
    std::chrono::steady_clock::time_point expires;
    std::chrono::system_clock::time_point added;  // for the log and the dashboard
    std::string           reason;  // why, e.g. "tunnel"
    double                score = 0;  // the model's score behind it
    std::string           source;  // who asked, e.g. "analyzer"
    uint64_t              hits = 0;  // queries answered under it
};

class DynamicRules {
public:
    using Clock = std::chrono::steady_clock;

    explicit DynamicRules(DynamicRulesConfig config = {}) : config_(config) {}

    /// Add a rule, or renew the one for the same domain and client: its
    /// expiry, reason, score and source become these. An error if the table
    /// is full or `ttl_seconds` is 0; a longer TTL than max_ttl is cut.
    std::expected<const DynamicRule*, std::string> add(Name domain, std::optional<Subnet> client, uint32_t ttl_seconds,
                                                       std::string reason, double score, std::string source,
                                                       Clock::time_point now);

    /// Remove a rule before it expires. False if there is none with this id.
    bool remove(uint64_t id);

    /// The rule covering `qname` for this client, if any, counting the hit.
    /// An expired rule never matches, even before expire() removes it.
    const DynamicRule* match(const Name& qname, const sockaddr_storage& client, Clock::time_point now);

    /// Remove the rules that have expired, and return them (for the log).
    std::vector<DynamicRule> expire(Clock::time_point now);

    /// The rules still in force.
    [[nodiscard]] std::vector<DynamicRule> active(Clock::time_point now) const;

    [[nodiscard]] size_t                    size() const { return count_; }
    [[nodiscard]] const DynamicRulesConfig& config() const { return config_; }
    [[nodiscard]] uint64_t                  blocked() const { return blocked_; }  // queries answered under a rule
    [[nodiscard]] uint64_t                  added() const { return added_; }      // rules added (renewals not counted)

private:
    DynamicRulesConfig                                config_;
    std::unordered_map<Name, std::vector<DynamicRule>> by_domain_;
    size_t                                            count_   = 0;
    uint64_t                                          next_id_ = 1;
    uint64_t                                          blocked_ = 0;
    uint64_t                                          added_   = 0;
};

}  // namespace dnsentinel::policy
