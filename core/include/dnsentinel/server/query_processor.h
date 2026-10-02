#pragma once
/// @file server/query_processor.h
/// The fast path (plan §1): every well-formed query from every transport
/// comes through here. Stages so far: access control, rejecting queries we
/// can't answer, the block and allow lists, then resolution (the resolver
/// answers from the cache when it can). Rate limiting, the other policy
/// checks and ML slot in around them as they land.

#include "dnsentinel/net/query_handler.h"
#include "dnsentinel/policy/acl.h"
#include "dnsentinel/policy/blocklists.h"
#include "dnsentinel/types.h"

namespace dnsentinel::resolver {
class RecursiveResolver;
}

namespace dnsentinel::server {

class QueryProcessor {
public:
    /// `resolver` and `lists` must outlive the processor. `access` decides
    /// who may use it.
    QueryProcessor(resolver::RecursiveResolver& resolver, policy::AccessControl access,
                   const policy::Blocklists& lists);

    /// A net::QueryHandler. A client outside the allowed subnets gets
    /// REFUSED, or nothing (DenyAction::Drop), before anything else happens.
    /// Queries that can't be answered get their error response at once, and
    /// so do blocked names (never sent upstream); the rest once resolution
    /// finishes (SERVFAIL if it fails). The response echoes the client's
    /// question exactly, case included.
    void handle(Message query, const net::ClientInfo& client, net::Responder respond);

private:
    resolver::RecursiveResolver& resolver_;
    policy::AccessControl        access_;
    const policy::Blocklists&    lists_;
};

}  // namespace dnsentinel::server
