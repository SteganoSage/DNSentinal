#pragma once
/// @file ml/dga_check.h
/// The DGA classifier in the query path (README §7.8.2): which query names
/// are worth scoring, the verdict cache, and what it all counted.
///
/// Not scored: special-use names (.arpa, .local, .test, ... nothing a DGA
/// registers), single labels (search-list noise), names no host has, and
/// popular sites (the allowlist). Verdicts are kept per registrable domain,
/// so mail.x7kq2.biz and www.x7kq2.biz cost one scoring; and each query
/// name's outcome (verdict, popular or not scored) is kept too, so asking
/// for a name again costs one hash lookup, not a Public Suffix List split
/// (experiment E9: a resolver mostly answers names it has seen, most of
/// them popular).
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

/// A least-recently-used map from strings. The index's keys view the keys
/// stored in the list's nodes, which never move.
template <typename Value>
class Lru {
public:
    explicit Lru(size_t capacity) : capacity_(capacity) {}
    Lru(const Lru&)            = delete;  // a copy's index would view the original's nodes
    Lru& operator=(const Lru&) = delete;
    Lru(Lru&&)                 = default;  // a moved list keeps its nodes
    Lru& operator=(Lru&&)      = default;

    /// The value for `key`, now the most recently used; nullptr if absent.
    Value* find(std::string_view key) {
        const auto it = index_.find(key);
        if (it == index_.end()) return nullptr;
        order_.splice(order_.end(), order_, it->second);
        return &it->second->second;
    }
    void insert(std::string key, Value value) {
        if (capacity_ == 0) return;
        if (order_.size() >= capacity_) {  // forget the least recently used
            index_.erase(order_.front().first);
            order_.pop_front();
        }
        order_.emplace_back(std::move(key), std::move(value));
        index_.emplace(order_.back().first, std::prev(order_.end()));
    }
    void clear() {
        index_.clear();
        order_.clear();
    }
    [[nodiscard]] size_t size() const { return order_.size(); }

private:
    using Entry = std::pair<std::string, Value>;
    size_t                                                                         capacity_;
    std::list<Entry>                                                               order_;  // least recent first
    std::unordered_map<std::string_view, typename std::list<Entry>::iterator> index_;
};

class DgaCheck {
public:
    /// Load the model and the allowlist the config names.
    [[nodiscard]] static std::expected<DgaCheck, std::string> load(const DgaConfig& config);
    /// From parts already loaded (tests).
    DgaCheck(DgaClassifier model, StringSet allowlist, const DgaConfig& config);
    // The caches can't be copied (Lru): neither can this. Moving is safe.
    DgaCheck(const DgaCheck&)            = delete;
    DgaCheck& operator=(const DgaCheck&) = delete;
    DgaCheck(DgaCheck&&)                 = default;
    DgaCheck& operator=(DgaCheck&&)      = default;

    /// The verdict on a query name's registrable domain, from the cache or
    /// scored now; nullopt if the name isn't scored (see the file comment).
    [[nodiscard]] std::optional<DgaResult> check(const Name& qname);

    /// Forget every verdict and outcome (the counters stay).
    void clear() {
        verdicts_.clear();
        names_.clear();
    }

    [[nodiscard]] DgaMode              mode() const { return mode_; }
    [[nodiscard]] const DgaStats&      stats() const { return stats_; }
    [[nodiscard]] const DgaClassifier& classifier() const { return model_; }
    [[nodiscard]] size_t               allowlist_size() const { return allowlist_.size(); }
    [[nodiscard]] size_t               cached() const { return verdicts_.size(); }  // registrable domains

    /// True for names under a special-use or local top-level domain.
    [[nodiscard]] static bool special_use(std::string_view tld);
    /// Read an allowlist file ("rank,domain" or "domain" lines, "#" comments).
    [[nodiscard]] static std::expected<StringSet, std::string> read_allowlist(const std::string& path);

private:
    /// What became of a query name, kept so asking again is one lookup.
    struct Outcome {
        enum class Kind : uint8_t { Skipped, Popular, Judged } kind = Kind::Skipped;
        DgaVerdict verdict;  // Judged only
    };
    std::optional<DgaResult> recall(Outcome& outcome);

    DgaClassifier    model_;
    StringSet        allowlist_;
    DgaMode          mode_;
    DgaStats         stats_;
    Lru<DgaVerdict>  verdicts_;  // by registrable domain
    Lru<Outcome>     names_;     // by query name (lower case, no trailing dot)
};

}  // namespace dnsentinel::ml
