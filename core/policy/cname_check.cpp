/// @file policy/cname_check.cpp
/// Following an answer's CNAME chain and checking each hop.

#include "dnsentinel/policy/cname_check.h"

#include <algorithm>

namespace dnsentinel::policy {

std::vector<Name> cname_chain(const Name& qname, const std::vector<RR>& answers) {
    std::vector<Name> chain;
    const Name*       current = &qname;
    for (;;) {
        auto cname = std::find_if(answers.begin(), answers.end(), [current](const RR& rr) {
            return rr.type == RRType::CNAME && rr.name == *current && std::holds_alternative<RDataCNAME>(rr.rdata);
        });
        if (cname == answers.end()) break;
        const Name& target = std::get<RDataCNAME>(cname->rdata).target;
        if (target == qname || std::find(chain.begin(), chain.end(), target) != chain.end()) break;  // a loop
        chain.push_back(target);
        current = &target;  // in `answers`, so it stays put as `chain` grows
    }
    return chain;
}

std::optional<CloakedName> find_cloaked(const Name& qname, const std::vector<RR>& answers, const BlocklistTrie& trie) {
    const bool has_cname =
        std::any_of(answers.begin(), answers.end(), [](const RR& rr) { return rr.type == RRType::CNAME; });
    if (!has_cname) return std::nullopt;  // the common case: nothing to follow

    const std::vector<Name> chain = cname_chain(qname, answers);
    for (size_t i = 0; i < chain.size(); ++i) {
        auto match = trie.lookup(chain[i]);
        if (!match.matched || match.action != ListAction::Block) continue;
        CloakedName cloaked{{qname}, std::move(match)};
        cloaked.chain.insert(cloaked.chain.end(), chain.begin(), chain.begin() + static_cast<ptrdiff_t>(i) + 1);
        return cloaked;
    }
    return std::nullopt;
}

}  // namespace dnsentinel::policy
