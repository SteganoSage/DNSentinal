#pragma once
/// @file server/query_processor.h
/// The fast path (plan §1): every well-formed query from every transport
/// comes through here. Stages so far: access control, rejecting queries we
/// can't answer, the block and allow lists, resolution (the resolver
/// answers from the cache when it can), checking the answer's CNAME chain
/// against the lists, then removing private addresses from answers for
/// public names (rebinding protection). Rate limiting and ML slot in around
/// them as they land.

#include "dnsentinel/net/query_handler.h"
#include "dnsentinel/policy/acl.h"
#include "dnsentinel/policy/blocklists.h"
#include "dnsentinel/policy/rebinding.h"
#include "dnsentinel/types.h"

#include <functional>
#include <vector>

namespace dnsentinel::resolver {
class RecursiveResolver;
}

namespace dnsentinel::server {

/// Why a query got a blocked answer: for the log now, the query log and
/// dashboard later (plan §7.5), and experiment E12's count of the trackers
/// only the CNAME check catches.
struct BlockEvent {
    Question                 question;  // as the client asked it
    std::vector<Name>        chain;     // the query name, then the CNAME hops up to the blocked one
    policy::TrieLookupResult match;     // the rule and the list it is on

    [[nodiscard]] bool        via_cname() const { return chain.size() > 1; }
    [[nodiscard]] const Name& blocked_name() const { return chain.back(); }
};

/// Addresses taken out of an answer because a public name pointed at a
/// private one (plan §5.8): an attack, or a local name missing from
/// policy.rebinding_protection.exempt.
struct RebindingEvent {
    Question        question;  // as the client asked it
    std::vector<RR> removed;   // the A and AAAA records taken out
    bool            emptied = false;  // no address was left, so the client got NXDOMAIN
};

class QueryProcessor {
public:
    using BlockFn     = std::function<void(const BlockEvent&)>;
    using RebindingFn = std::function<void(const RebindingEvent&)>;

    /// `resolver` and `lists` must outlive the processor, and resolutions it
    /// started must not complete after it is gone: destroy it only once the
    /// loop has stopped, or with the resolver (which abandons them). `access`
    /// decides who may use it.
    QueryProcessor(resolver::RecursiveResolver& resolver, policy::AccessControl access,
                   const policy::Blocklists& lists, policy::RebindingFilter rebinding);

    /// Called for every blocked answer, before it is sent.
    void on_block(BlockFn fn) { on_block_ = std::move(fn); }
    /// Called whenever rebinding protection changes an answer, before it is sent.
    void on_rebinding(RebindingFn fn) { on_rebinding_ = std::move(fn); }

    /// A net::QueryHandler. A client outside the allowed subnets gets
    /// REFUSED, or nothing (DenyAction::Drop), before anything else happens.
    /// Queries that can't be answered get their error response at once, and
    /// so do blocked names (never sent upstream); the rest once resolution
    /// finishes (SERVFAIL if it fails), blocked after all if a name in the
    /// answer's CNAME chain is, and without private addresses unless the
    /// name is exempt (NXDOMAIN if no address is left). The response echoes
    /// the client's question exactly, case included.
    void handle(Message query, const net::ClientInfo& client, net::Responder respond);

private:
    void report(const Question& question, std::vector<Name> chain, policy::TrieLookupResult match);

    resolver::RecursiveResolver& resolver_;
    policy::AccessControl        access_;
    const policy::Blocklists&    lists_;
    policy::RebindingFilter      rebinding_;
    BlockFn                      on_block_;
    RebindingFn                  on_rebinding_;
};

}  // namespace dnsentinel::server
