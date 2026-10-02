#pragma once
/// @file policy/blocklist_trie.h
/// Reversed-label trie for blocklist / allowlist lookups (plan §5.6).
/// Labels are stored from the TLD down ("ads.example.com" → com, example,
/// ads), so a rule for example.com covers all its subdomains, and a lookup
/// costs one step per label of the query however long the lists are.
///
/// A trie is built once and never changed: a Builder collects the rules and
/// freezes them into a compact layout (each distinct label stored once,
/// children sorted for binary search). Reloading lists means building a new
/// trie and swapping it in (see Blocklists).

#include "dnsentinel/types.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <vector>

namespace dnsentinel::policy {

enum class ListAction : uint8_t {
    Block,
    Allow,
};

/// Result of a trie lookup
struct TrieLookupResult {
    bool        matched = false;
    ListAction  action  = ListAction::Block;
    std::string rule;    // the matching rule, e.g. "doubleclick.net." (for logs and the dashboard)
    std::string source;  // the list it came from, e.g. "config/lists/feeds/ads.txt"
};

/// What reading one list file found.
struct ListFileStats {
    size_t rules   = 0;  // domains taken
    size_t skipped = 0;  // lines that weren't a domain we could use
};

class BlocklistTrie {
public:
    class Builder {
    public:
        /// Add one rule. With `include_subdomains` (what list files use) it
        /// covers every name below `domain` too.
        void add(const Name& domain, ListAction action, std::string_view source,
                 bool include_subdomains = true);

        /// Read a list file. Accepted lines: hosts format ("0.0.0.0
        /// ads.example.com", several names allowed), one domain per line,
        /// "*.example.com", and adblock-style "||example.com^". '#' starts a
        /// comment; '!' and '[' lines are adblock comments and headers.
        /// Hosts-file boilerplate (localhost and friends) is ignored. Other
        /// lines that aren't a usable domain are counted as skipped. A file
        /// that can't be read is an error.
        std::expected<ListFileStats, std::string> load_file(const std::string& path, ListAction action);

        /// Freeze the rules into a trie, leaving the builder empty.
        [[nodiscard]] BlocklistTrie build();

    private:
        struct Rule {
            std::string key;  // reversed canonical labels, each prefixed with its length
            uint8_t     flags;
            uint16_t    source;
        };
        uint16_t source_id(std::string_view source);

        std::vector<Rule>        rules_;
        std::vector<std::string> sources_;
    };

    /// An empty trie: matches nothing.
    BlocklistTrie() = default;

    /// Allow rules beat block rules at any depth (README §7.6.2): a domain
    /// on an allowlist is never blocked, nor is anything below it. Otherwise
    /// the deepest matching block rule is reported.
    [[nodiscard]] TrieLookupResult lookup(const Name& domain) const;

    /// Number of distinct domains with a rule (listed twice counts once).
    [[nodiscard]] size_t size() const { return rule_count_; }

    /// Approximate memory held by the trie.
    [[nodiscard]] size_t memory_bytes() const;

private:
    struct Node {
        uint32_t label_offset = 0;  // into labels_
        uint8_t  label_length = 0;
        uint8_t  flags        = 0;  // the rules ending at this node (k* in the .cpp)
        uint16_t block_source = 0;
        uint16_t allow_source = 0;
        uint32_t first_child  = 0;  // children are contiguous, sorted by (length, bytes)
        uint32_t child_count  = 0;
    };

    [[nodiscard]] std::string_view label_of(const Node& node) const;
    [[nodiscard]] const Node* child(const Node& parent, std::string_view label) const;

    std::vector<Node>        nodes_;    // nodes_[0] is the root
    std::string              labels_;   // every distinct label, once
    std::vector<std::string> sources_;  // list names, indexed by Node::*_source
    size_t                   rule_count_ = 0;
};

}  // namespace dnsentinel::policy
