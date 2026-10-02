/// @file server/query_processor.cpp
/// Query checks and the block lists, then resolution.

#include "dnsentinel/server/query_processor.h"

#include "dnsentinel/resolver/recursive_resolver.h"
#include "dnsentinel/wire/builder.h"

#include <optional>
#include <utility>

namespace dnsentinel::server {

namespace {

constexpr uint16_t kClassIN  = 1;
constexpr uint16_t kTypeOPT  = static_cast<uint16_t>(RRType::OPT);
constexpr uint16_t kTypeIXFR = 251;
constexpr uint16_t kTypeAXFR = 252;
constexpr uint16_t kTypeANY  = 255;

/// RFC 6891 §7: extended rcode for an EDNS version we don't speak.
constexpr auto kBadVers = static_cast<RCode>(16);

/// Why `query` can't be answered by resolving it, if it can't.
std::optional<RCode> reject_reason(const Message& query) {
    if (query.edns && query.edns->version != 0) return kBadVers;
    if (query.header.opcode != 0) return RCode::NotImp;  // only standard queries
    if (query.questions.size() != 1) return RCode::FormErr;

    const Question& q = query.questions.front();
    if (q.qclass != kClassIN) return RCode::Refused;
    // Zone transfers need an authoritative server, which we are not.
    if (q.qtype == kTypeIXFR || q.qtype == kTypeAXFR) return RCode::Refused;
    // OPT and the other meta types (RFC 6895 §3.1) aren't data to look up.
    if (q.qtype == kTypeOPT || (q.qtype >= 128 && q.qtype < kTypeANY)) return RCode::FormErr;
    return std::nullopt;
}

/// The answer for a name on a blocklist (README §7.6.2): an address that
/// goes nowhere, or NXDOMAIN, either way with a short TTL.
Message blocked_response(const Message& query, const policy::ListsConfig& lists) {
    if (lists.response == policy::BlockResponse::NxDomain) return wire::make_response(query, RCode::NXDomain);

    Message         response = wire::make_response(query);
    const Question& q        = query.questions.front();
    RR              rr;
    rr.name  = q.qname;
    rr.ttl   = lists.block_ttl;
    rr.trust = TrustRank::Answer;
    if (q.qtype == static_cast<uint16_t>(RRType::A)) {
        rr.type  = RRType::A;
        rr.rdata = RDataA{};  // 0.0.0.0
        response.answers.push_back(std::move(rr));
    } else if (q.qtype == static_cast<uint16_t>(RRType::AAAA)) {
        rr.type  = RRType::AAAA;
        rr.rdata = RDataAAAA{};  // ::
        response.answers.push_back(std::move(rr));
    }  // any other type: no records (NODATA)
    return response;
}

}  // namespace

QueryProcessor::QueryProcessor(resolver::RecursiveResolver& resolver, policy::AccessControl access,
                               const policy::Blocklists& lists)
    : resolver_(resolver), access_(std::move(access)), lists_(lists) {}

void QueryProcessor::handle(Message query, const net::ClientInfo& client, net::Responder respond) {
    // Access control first (plan §5.5): outsiders cost us nothing further,
    // and never cause an upstream query.
    if (!access_.allows(client.addr)) {
        if (access_.deny_action() == policy::DenyAction::Refuse) {
            respond(wire::make_response(query, RCode::Refused));
        }
        return;
    }
    if (auto rcode = reject_reason(query)) {
        respond(wire::make_response(query, *rcode));
        return;
    }
    // Block and allow lists (plan §5.6): a blocked name is answered here,
    // without a single upstream query; an allowed one is never blocked.
    if (auto match = lists_.lookup(query.questions.front().qname);
        match.matched && match.action == policy::ListAction::Block) {
        respond(blocked_response(query, lists_.config()));
        return;
    }

    resolver_.resolve(query.questions.front(),
                      [response = wire::make_response(query), respond = std::move(respond)](
                          std::expected<resolver::ResolveResult, resolver::ResolveError> result) mutable {
                          if (!result) {
                              response.header.rcode = static_cast<uint8_t>(RCode::ServFail);
                          } else {
                              response.header.rcode = result->response.header.rcode;
                              response.answers      = std::move(result->response.answers);
                              response.authority    = std::move(result->response.authority);
                          }
                          respond(response);
                      });
}

}  // namespace dnsentinel::server
