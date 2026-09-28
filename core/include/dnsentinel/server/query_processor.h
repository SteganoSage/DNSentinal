#pragma once
/// @file server/query_processor.h
/// The fast path (plan §1): every well-formed query from every transport
/// comes through here. Phase 2 scope: reject queries we can't answer, then
/// resolve (the resolver answers from the cache when it can) and respond.
/// ACL, rate limiting, policy and ML stages slot in before resolution as
/// they land.

#include "dnsentinel/net/query_handler.h"
#include "dnsentinel/types.h"

namespace dnsentinel::resolver {
class RecursiveResolver;
}

namespace dnsentinel::server {

class QueryProcessor {
public:
    /// `resolver` must outlive the processor.
    explicit QueryProcessor(resolver::RecursiveResolver& resolver);

    /// A net::QueryHandler. Queries that can't be answered get their error
    /// response at once; the rest once resolution finishes (SERVFAIL if it
    /// fails). The response echoes the client's question exactly, case
    /// included.
    void handle(Message query, const net::ClientInfo& client, net::Responder respond);

private:
    resolver::RecursiveResolver& resolver_;
};

}  // namespace dnsentinel::server
