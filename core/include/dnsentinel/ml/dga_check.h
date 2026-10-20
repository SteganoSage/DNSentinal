#pragma once
/// @file ml/dga_check.h
/// The DGA classifier in the query path (README §7.8.2): which query names
/// are worth scoring, the verdict cache, and what it all counted.
///
/// Not scored: special-use names (.arpa, .local, .test, ... nothing a DGA
/// registers), single labels (search-list noise), names no host has, and
/// popular sites (the allowlist). Verdicts are kept per registrable domain,
/// so mail.x7kq2.biz and www.x7kq2.biz cost one scoring.
///
/// Used from the event-loop thread only: no locking.

#include "dnsentinel/ml/dga_classifier.h"
#include "dnsentinel/ml/dga_config.h"
#include "dnsentinel/types.h"

#include <cstdint>
#include <expected>
#include <list>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace dnsentinel::ml {

struct DgaStats {
    uint64_t queries     = 0;  // query names looked at
    uint64_t skipped     = 0;  // special-use, single-label or not a host name
    uint64_t allowlisted = 0;  // a popular site
    uint64_t scored      = 0;  // new registrable domains the model scored
    uint64_t cache_hits  = 0;  // verdicts reused
    uint64_t flagged     = 0;  // queries for a name the model judged generated
    uint64_t flagged_new = 0;  // ...of them, the first query for that registrable domain
};

struct DgaResult {
    DgaVerdict verdict;
    bool       cached = false;  // reused: this registrable domain was scored before
};

class DgaCheck {
public:
    /// Load the model and the allowlist the config names.
    [[nodiscard]] static std::expected<DgaCheck, std::string> load(const DgaConfig& config);
    /// From parts already loaded (tests).
    DgaCheck(DgaClassifier model, StringSet allowlist, const DgaConfig& config);
    // The cache's index views strings inside its own list: a copy would point
    // into the original. A move keeps the list's nodes, so it is safe.
    DgaCheck(const DgaCheck&)            = delete;
    DgaCheck& operator=(const DgaCheck&) = delete;
    DgaCheck(DgaCheck&&)                 = default;
    DgaCheck& operator=(DgaCheck&&)      = default;

    /// The verdict on a query name's registrable domain, from the cache or
    /// scored now; nullopt if the name isn't scored (see the file comment).
    [[nodiscard]] std::optional<DgaResult> check(const Name& qname);

    [[nodiscard]] DgaMode              mode() const { return mode_; }
    [[nodiscard]] const DgaStats&      stats() const { return stats_; }
    [[nodiscard]] const DgaClassifier& classifier() const { return model_; }
    [[nodiscard]] size_t               allowlist_size() const { return allowlist_.size(); }
    [[nodiscard]] size_t               cached() const { return order_.size(); }

    /// True for names under a special-use or local top-level domain.
    [[nodiscard]] static bool special_use(std::string_view tld);
    /// Read an allowlist file ("rank,domain" or "domain" lines, "#" comments).
    [[nodiscard]] static std::expected<StringSet, std::string> read_allowlist(const std::string& path);

private:
    void remember(const DgaVerdict& verdict);

    DgaClassifier model_;
    StringSet     allowlist_;
    DgaMode       mode_;
    size_t        capacity_;
    DgaStats      stats_;
    // Least recently used first; the map's keys view the verdicts' strings.
    std::list<DgaVerdict>                                                    order_;
    std::unordered_map<std::string_view, std::list<DgaVerdict>::iterator> index_;
};

}  // namespace dnsentinel::ml
