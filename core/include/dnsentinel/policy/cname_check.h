#pragma once
/// @file policy/cname_check.h
/// CNAME-cloaking detection (plan §5.7, README §7.6.3). A tracker hidden
/// behind a first-party alias (metrics.shop.com → collect.tracker.net)
/// passes a check on the query name alone, so after resolution every name
/// the answer's CNAME chain goes through is looked up too.
///
/// One trie lookup per hop is enough: rules cover their subdomains, so a
/// lookup of collect.tracker.net already finds a rule on tracker.net (the
/// registrable domain) or on anything else above it.

#include "dnsentinel/policy/blocklist_trie.h"
#include "dnsentinel/types.h"

#include <optional>
#include <vector>

namespace dnsentinel::policy {

/// The names `qname`'s CNAME chain in `answers` leads through, in order,
/// not counting `qname` itself: for qname → a → b, {a, b}. Records off the
/// chain are ignored, the records may come in any order, and a loop ends
/// the chain at the first name seen twice.
[[nodiscard]] std::vector<Name> cname_chain(const Name& qname, const std::vector<RR>& answers);

/// A chain hop a blocklist covers.
struct CloakedName {
    std::vector<Name> chain;  // qname, then every hop up to and including the blocked one
    TrieLookupResult  match;  // the rule and list that block it
};

/// The first hop of `qname`'s CNAME chain that `trie` blocks, if any. A hop
/// that is allowlisted is fine itself but doesn't vouch for the hops after it.
[[nodiscard]] std::optional<CloakedName> find_cloaked(const Name& qname, const std::vector<RR>& answers,
                                                      const BlocklistTrie& trie);

}  // namespace dnsentinel::policy
