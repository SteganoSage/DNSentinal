/// @file policy/blocklist_trie.cpp
/// List file parsing, trie construction and lookup.

#include "dnsentinel/policy/blocklist_trie.h"

#include <arpa/inet.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <deque>
#include <fstream>
#include <unordered_map>

namespace dnsentinel::policy {

namespace {

// Which rules end at a node.
constexpr uint8_t kBlockExact   = 1;  // this name only
constexpr uint8_t kBlockSubtree = 2;  // this name and everything below it
constexpr uint8_t kAllowExact   = 4;
constexpr uint8_t kAllowSubtree = 8;

/// Children are ordered by label length, then bytes: the order the
/// length-prefixed build keys sort in.
int compare_labels(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return a.size() < b.size() ? -1 : 1;
    return a.compare(b);
}

std::string_view trim(std::string_view s) {
    const size_t begin = s.find_first_not_of(" \t\r");
    if (begin == std::string_view::npos) return {};
    return s.substr(begin, s.find_last_not_of(" \t\r") - begin + 1);
}

std::vector<std::string_view> split_fields(std::string_view s) {
    std::vector<std::string_view> fields;
    size_t i = 0;
    while (i < s.size()) {
        while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) ++i;
        const size_t start = i;
        while (i < s.size() && s[i] != ' ' && s[i] != '\t') ++i;
        if (i > start) fields.push_back(s.substr(start, i - start));
    }
    return fields;
}

bool is_ip_address(std::string_view text) {
    const std::string s(text.substr(0, text.find('%')));  // "fe80::1%lo0": an IPv6 zone index
    unsigned char buf[16];
    return inet_pton(AF_INET, s.c_str(), buf) == 1 || inet_pton(AF_INET6, s.c_str(), buf) == 1;
}

/// Names every hosts file maps to itself; blocking them would break the machine.
bool is_hosts_boilerplate(std::string_view name) {
    static constexpr std::string_view kNames[] = {
        "localhost",     "localhost.localdomain", "local",          "broadcasthost",
        "ip6-localhost", "ip6-loopback",          "ip6-localnet",   "ip6-mcastprefix",
        "ip6-allnodes",  "ip6-allrouters",        "ip6-allhosts",   "0.0.0.0",
    };
    return std::find(std::begin(kNames), std::end(kNames), name) != std::end(kNames);
}

/// The domain an adblock-style or wildcard entry names, or empty if the
/// entry is anything more complicated than a whole domain.
std::string_view unwrap_domain(std::string_view entry) {
    if (entry.starts_with("||")) {
        if (!entry.ends_with('^')) return {};  // "||x^$third-party" and friends: not a whole-domain rule
        entry = entry.substr(2, entry.size() - 3);
    } else if (entry.starts_with("*.")) {
        entry = entry.substr(2);
    }
    if (entry.find_first_of("/*$^|@:=?&") != std::string_view::npos) return {};  // URLs, patterns
    return entry;
}

}  // namespace

// ─── Builder ────────────────────────────────────────────────────────────────

uint16_t BlocklistTrie::Builder::source_id(std::string_view source) {
    for (size_t i = 0; i < sources_.size(); ++i) {
        if (sources_[i] == source) return static_cast<uint16_t>(i);
    }
    sources_.emplace_back(source);
    return static_cast<uint16_t>(sources_.size() - 1);
}

void BlocklistTrie::Builder::add(const Name& domain, ListAction action, std::string_view source,
                                 bool include_subdomains) {
    std::string key;
    for (auto it = domain.labels.rbegin(); it != domain.labels.rend(); ++it) {
        key += static_cast<char>(it->size());
        key += *it;
    }
    const uint8_t flags = action == ListAction::Block ? (include_subdomains ? kBlockSubtree : kBlockExact)
                                                      : (include_subdomains ? kAllowSubtree : kAllowExact);
    rules_.push_back(Rule{std::move(key), flags, source_id(source)});
}

std::expected<ListFileStats, std::string> BlocklistTrie::Builder::load_file(const std::string& path,
                                                                            ListAction action) {
    std::ifstream file(path);
    if (!file) return std::unexpected("cannot open " + path + ": " + std::strerror(errno));

    ListFileStats stats;
    std::string   raw;
    while (std::getline(file, raw)) {
        std::string_view line = trim(raw);
        if (line.empty() || line.front() == '!' || line.front() == '[') continue;  // adblock comment / header
        line = trim(line.substr(0, line.find('#')));
        if (line.empty()) continue;

        const auto fields = split_fields(line);
        std::vector<std::string_view> names;
        if (is_ip_address(fields.front())) {  // hosts format: "0.0.0.0 a.com b.com"
            for (size_t i = 1; i < fields.size(); ++i) {
                if (!is_hosts_boilerplate(fields[i])) names.push_back(fields[i]);
            }
            if (fields.size() == 1) ++stats.skipped;
        } else if (fields.size() == 1) {
            names.push_back(unwrap_domain(fields.front()));
        } else {
            ++stats.skipped;  // several words, not hosts format
        }

        for (std::string_view text : names) {
            auto name = text.empty() ? std::nullopt : Name::from_string(text);
            if (!name || name->label_count() == 0) {  // never the root: that would match everything
                ++stats.skipped;
                continue;
            }
            add(*name, action, path);
            ++stats.rules;
        }
    }
    return stats;
}

BlocklistTrie BlocklistTrie::Builder::build() {
    // Sorting the length-prefixed keys puts every subtree's rules in one
    // contiguous run, a node's own rules first, and children in the order
    // lookups binary-search them in. Stable, so a domain on several lists
    // is reported as coming from the first one loaded.
    std::stable_sort(rules_.begin(), rules_.end(), [](const Rule& a, const Rule& b) { return a.key < b.key; });

    BlocklistTrie trie;
    trie.sources_ = std::move(sources_);
    trie.nodes_.emplace_back();  // the root
    std::unordered_map<std::string_view, uint32_t> interned;  // label → offset in labels_

    // Breadth-first, so each node's children are appended next to each other.
    struct Work {
        uint32_t node;
        size_t   begin, end;  // the rules under this node
        size_t   offset;      // how much of their keys this node accounts for
    };
    std::deque<Work> queue{{0, 0, rules_.size(), 0}};
    std::vector<Work> children;
    while (!queue.empty()) {
        const Work w = queue.front();
        queue.pop_front();

        size_t i = w.begin;
        for (; i < w.end && rules_[i].key.size() == w.offset; ++i) {  // rules for this very name
            Node& node = trie.nodes_[w.node];
            const uint8_t f = rules_[i].flags;
            if ((f & (kBlockExact | kBlockSubtree)) && !(node.flags & (kBlockExact | kBlockSubtree))) {
                node.block_source = rules_[i].source;
            }
            if ((f & (kAllowExact | kAllowSubtree)) && !(node.flags & (kAllowExact | kAllowSubtree))) {
                node.allow_source = rules_[i].source;
            }
            node.flags |= f;
        }

        children.clear();
        const auto first = static_cast<uint32_t>(trie.nodes_.size());
        while (i < w.end) {
            const auto       length = static_cast<uint8_t>(rules_[i].key[w.offset]);
            const std::string_view label(rules_[i].key.data() + w.offset + 1, length);
            size_t j = i + 1;
            while (j < w.end && std::string_view(rules_[j].key).substr(w.offset, 1 + length) ==
                                    std::string_view(rules_[i].key).substr(w.offset, 1 + length)) {
                ++j;
            }

            auto [it, fresh] = interned.try_emplace(label, static_cast<uint32_t>(trie.labels_.size()));
            if (fresh) trie.labels_.append(label);
            Node child;
            child.label_offset = it->second;
            child.label_length = length;
            trie.nodes_.push_back(child);
            children.push_back({static_cast<uint32_t>(trie.nodes_.size() - 1), i, j, w.offset + 1 + length});
            i = j;
        }
        trie.nodes_[w.node].first_child = first;
        trie.nodes_[w.node].child_count = static_cast<uint32_t>(children.size());
        queue.insert(queue.end(), children.begin(), children.end());
    }

    for (const Node& n : trie.nodes_) trie.rule_count_ += n.flags != 0;
    trie.nodes_.shrink_to_fit();
    trie.labels_.shrink_to_fit();
    rules_.clear();
    return trie;
}

// ─── Lookup ─────────────────────────────────────────────────────────────────

std::string_view BlocklistTrie::label_of(const Node& node) const {
    return std::string_view(labels_).substr(node.label_offset, node.label_length);
}

const BlocklistTrie::Node* BlocklistTrie::child(const Node& parent, std::string_view label) const {
    const Node* first = nodes_.data() + parent.first_child;
    const Node* last  = first + parent.child_count;
    const Node* it    = std::lower_bound(first, last, label, [this](const Node& n, std::string_view l) {
        return compare_labels(label_of(n), l) < 0;
    });
    return it != last && label_of(*it) == label ? it : nullptr;
}

TrieLookupResult BlocklistTrie::lookup(const Name& domain) const {
    TrieLookupResult result;
    if (nodes_.empty()) return result;

    const size_t n = domain.labels.size();
    size_t   block_depth = 0, allow_depth = 0;
    uint16_t block_source = 0, allow_source = 0;
    bool     blocked = false, allowed = false;

    const Node* node = nodes_.data();
    for (size_t depth = 0;; ++depth) {  // depth = labels matched so far
        const bool whole_name = depth == n;
        if ((node->flags & kBlockSubtree) || (whole_name && (node->flags & kBlockExact))) {
            blocked      = true;
            block_depth  = depth;  // deepest wins
            block_source = node->block_source;
        }
        if ((node->flags & kAllowSubtree) || (whole_name && (node->flags & kAllowExact))) {
            allowed      = true;
            allow_depth  = depth;
            allow_source = node->allow_source;
        }
        if (whole_name) break;
        node = child(*node, domain.labels[n - 1 - depth]);
        if (!node) break;
    }
    if (!blocked && !allowed) return result;

    const size_t depth = allowed ? allow_depth : block_depth;
    Name rule;
    for (size_t i = n - depth; i < n; ++i) rule.append_label(domain.labels[i]);
    result.matched = true;
    result.action  = allowed ? ListAction::Allow : ListAction::Block;
    result.rule    = rule.to_string();
    result.source  = sources_.at(allowed ? allow_source : block_source);
    return result;
}

size_t BlocklistTrie::memory_bytes() const {
    size_t bytes = nodes_.capacity() * sizeof(Node) + labels_.capacity();
    for (const auto& s : sources_) bytes += s.capacity();
    return bytes;
}

}  // namespace dnsentinel::policy
