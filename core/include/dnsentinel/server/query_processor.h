#pragma once
/// @file server/query_processor.h
/// The fast path (plan §1): every well-formed query from every transport
/// comes through here. Stages so far: access control, then rejecting
/// queries we can't answer, then resolution (the resolver answers from the
/// cache when it can). Rate limiting, policy and ML stages slot in before
/// resolution as they land.

#include "dnsentinel/net/query_handler.h"
#include "dnsentinel/policy/acl.h"
#include "dnsentinel/types.h"

namespace dnsentinel::resolver {
class RecursiveResolver;
}

namespace dnsentinel::server {

class QueryProcessor {
public:
    /// `resolver` must outlive the processor. `access` decides who may use it.
    QueryProcessor(resolver::RecursiveResolver& resolver, policy::AccessControl access);

    /// A net::QueryHandler. A client outside the allowed subnets gets
    /// REFUSED, or nothing (DenyAction::Drop), before anything else happens.
    /// Queries that can't be answered get their error response at once; the
    /// rest once resolution finishes (SERVFAIL if it fails). The response
    /// echoes the client's question exactly, case included.
    void handle(Message query, const net::ClientInfo& client, net::Responder respond);

private:
    resolver::RecursiveResolver& resolver_;
    policy::AccessControl        access_;
};

}  // namespace dnsentinel::server
