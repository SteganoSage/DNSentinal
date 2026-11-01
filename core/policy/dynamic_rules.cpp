/// @file policy/dynamic_rules.cpp
/// Rules are found by walking the query name up to the root, one hash
/// lookup per label: the cost is the name's length, not the table's size.

#include "dnsentinel/policy/dynamic_rules.h"

#include <algorithm>
#include <utility>

namespace dnsentinel::policy {

namespace {

bool same_client(const std::optional<Subnet>& a, const std::optional<Subnet>& b) {
    return a.has_value() == b.has_value() && (!a || *a == *b);
}

}  // namespace

std::expected<const DynamicRule*, std::string> DynamicRules::add(Name domain, std::optional<Subnet> client,
                                                                 uint32_t ttl_seconds, std::string reason, double score,
                                                                 std::string source, Clock::time_point now) {
    if (ttl_seconds == 0) return std::unexpected("a rule needs a TTL of at least 1 second");
    if (domain.label_count() == 0) return std::unexpected("a rule can't cover the whole namespace");
    const auto ttl     = std::chrono::seconds(std::min(ttl_seconds, config_.max_ttl));
    auto&      entries = by_domain_[domain];
    for (auto& rule : entries) {
        if (same_client(rule.client, client)) {  // renew it
            rule.expires = now + ttl;
            rule.reason  = std::move(reason);
            rule.score   = score;
            rule.source  = std::move(source);
            return &rule;
        }
    }
    if (count_ >= config_.max_rules) {
        if (entries.empty()) by_domain_.erase(domain);
        return std::unexpected("the table is full (" + std::to_string(config_.max_rules) +
                               " rules, policy.dynamic_rules.max_rules)");
    }
    DynamicRule rule;
    rule.id      = next_id_++;
    rule.domain  = std::move(domain);
    rule.client  = std::move(client);
    rule.expires = now + ttl;
    rule.added   = std::chrono::system_clock::now();
    rule.reason  = std::move(reason);
    rule.score   = score;
    rule.source  = std::move(source);
    entries.push_back(std::move(rule));
    ++count_;
    ++added_;
    return &entries.back();
}

bool DynamicRules::remove(uint64_t id) {
    for (auto it = by_domain_.begin(); it != by_domain_.end(); ++it) {
        auto& entries = it->second;
        auto  found   = std::find_if(entries.begin(), entries.end(), [id](const DynamicRule& r) { return r.id == id; });
        if (found == entries.end()) continue;
        entries.erase(found);
        --count_;
        if (entries.empty()) by_domain_.erase(it);
        return true;
    }
    return false;
}

const DynamicRule* DynamicRules::match(const Name& qname, const sockaddr_storage& client, Clock::time_point now) {
    if (by_domain_.empty()) return nullptr;
    Name suffix = qname;
    while (suffix.label_count() > 0) {
        if (auto it = by_domain_.find(suffix); it != by_domain_.end()) {
            for (auto& rule : it->second) {
                if (rule.expires > now && (!rule.client || rule.client->contains(client))) {
                    ++rule.hits;
                    ++blocked_;
                    return &rule;
                }
            }
        }
        suffix = suffix.parent();
    }
    return nullptr;
}

std::vector<DynamicRule> DynamicRules::expire(Clock::time_point now) {
    std::vector<DynamicRule> gone;
    for (auto it = by_domain_.begin(); it != by_domain_.end();) {
        auto& entries = it->second;
        auto  keep    = std::stable_partition(entries.begin(), entries.end(),
                                              [now](const DynamicRule& r) { return r.expires > now; });
        for (auto e = keep; e != entries.end(); ++e) gone.push_back(std::move(*e));
        count_ -= static_cast<size_t>(entries.end() - keep);
        entries.erase(keep, entries.end());
        it = entries.empty() ? by_domain_.erase(it) : std::next(it);
    }
    return gone;
}

std::vector<DynamicRule> DynamicRules::active(Clock::time_point now) const {
    std::vector<DynamicRule> out;
    for (const auto& [domain, entries] : by_domain_) {
        for (const auto& rule : entries) {
            if (rule.expires > now) out.push_back(rule);
        }
    }
    std::sort(out.begin(), out.end(), [](const DynamicRule& a, const DynamicRule& b) { return a.id < b.id; });
    return out;
}

}  // namespace dnsentinel::policy
