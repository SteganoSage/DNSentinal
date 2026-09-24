#pragma once
/// @file policy/blocklist_trie.h
/// Reversed-label trie for fast domain blocklist/allowlist lookups.
/// A rule for "example.com" can match all subdomains with one trie walk.

#include "dnsentinel/types.h"

#include <memory>
#include <string>
#include <vector>

namespace dnsentinel::policy {

enum class ListAction {
    Block,
    Allow,
};

/// Result of a trie lookup
struct TrieLookupResult {
    bool       matched   = false;
    ListAction action    = ListAction::Block;
    std::string rule;    // the matching rule, for logging / dashboard
};

/// Thread-safe reversed-label trie for domain matching.
/// Labels are inserted reversed: "ads.example.com" → ["com", "example", "ads"]
/// so a walk from the root toward deeper nodes matches TLD → SLD → subdomain.
class BlocklistTrie {
public:
    BlocklistTrie();
    ~BlocklistTrie();

    /// Load domains from a hosts-format or domain-list file.
    /// Lines starting with # are comments. Hosts-format lines like
    /// "0.0.0.0 ads.example.com" are accepted.
    void load_file(const std::string& path, ListAction action);

    /// Insert a single domain rule.
    void insert(const Name& domain, ListAction action,
                bool include_subdomains = true);

    /// Look up a domain. Allowlist matches take priority over blocklist.
    [[nodiscard]]
    TrieLookupResult lookup(const Name& domain) const;

    /// Number of rules loaded.
    [[nodiscard]] size_t size() const;

    /// Build a new trie from files and atomically swap (for hot reload).
    static std::unique_ptr<BlocklistTrie> build_from_files(
        const std::vector<std::string>& blocklist_paths,
        const std::string& allowlist_path);

private:
    struct Node;
    std::unique_ptr<Node> root_;
};

}  // namespace dnsentinel::policy
