#pragma once
/// @file server/query_processor.h
/// The fast path (plan §1): every well-formed query from every transport
/// comes through here. Stages so far: access control, rejecting queries we
/// can't answer, the block and allow lists, resolution (the resolver
/// answers from the cache when it can), then checking the answer's CNAME
/// chain against the lists. Rate limiting, the other policy checks and ML
/// slot in around them as they land.

#include "dnsentinel/net/query_handler.h"
#include "dnsentinel/policy/acl.h"
#include "dnsentinel/policy/blocklists.h"
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

class QueryProcessor {
public:
    using BlockFn = std::function<void(const BlockEvent&)>;

    /// `resolver` and `lists` must outlive the processor, and resolutions it
    /// started must not complete after it is gone: destroy it only once the
    /// loop has stopped, or with the resolver (which abandons them). `access`
    /// decides who may use it.
    QueryProcessor(resolver::RecursiveResolver& resolver, policy::AccessControl access,
                   const policy::Blocklists& lists);

    /// Called for every blocked answer, before it is sent.
    void on_block(BlockFn fn) { on_block_ = std::move(fn); }

    /// A net::QueryHandler. A client outside the allowed subnets gets
    /// REFUSED, or nothing (DenyAction::Drop), before anything else happens.
    /// Queries that can't be answered get their error response at once, and
    /// so do blocked names (never sent upstream); the rest once resolution
    /// finishes (SERVFAIL if it fails), blocked after all if a name in the
    /// answer's CNAME chain is. The response echoes the client's question
    /// exactly, case included.
    void handle(Message query, const net::ClientInfo& client, net::Responder respond);

private:
    void report(const Question& question, std::vector<Name> chain, policy::TrieLookupResult match);

    resolver::RecursiveResolver& resolver_;
    policy::AccessControl        access_;
    const policy::Blocklists&    lists_;
    BlockFn                      on_block_;
};

}  // namespace dnsentinel::server
