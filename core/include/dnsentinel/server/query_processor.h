#pragma once
/// @file server/query_processor.h
/// The fast path (plan §1): every well-formed query from every transport
/// comes through here. Stages so far: access control, the per-client rate
/// limit, rejecting queries we can't answer, the block and allow lists,
/// the DGA classifier (plan §7.8.2, on names the lists don't mention),
/// resolution (the resolver answers from the cache when it can), checking
/// the answer's CNAME chain against the lists, then removing private
/// addresses from answers for public names (rebinding protection). Every
/// UDP response, whatever produced it, passes response rate limiting on
/// its way out. ML slots in as it lands.

#ifdef DNSENTINEL_ML
#include "dnsentinel/ml/dga_check.h"
#endif
#include "dnsentinel/net/query_handler.h"
#include "dnsentinel/policy/acl.h"
#include "dnsentinel/policy/blocklists.h"
#include "dnsentinel/policy/rate_limiter.h"
#include "dnsentinel/policy/rebinding.h"
#include "dnsentinel/security/rrl.h"
#include "dnsentinel/types.h"

#include <functional>
#include <optional>
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

#ifdef DNSENTINEL_ML
/// A query for a name the DGA classifier judged machine-generated (plan §7.8.2).
struct DgaEvent {
    Question       question;  // as the client asked it
    ml::DgaVerdict verdict;   // its registrable domain and the model's score
    bool           cached   = false;  // judged before: not the first query for that domain
    bool           enforced = false;  // answered like a blocked name (enforce mode), not resolved
};
#endif

/// The processor's own checks, each built from its config section.
struct Checks {
    policy::AccessControl         access;      // who may use the resolver (§5.5)
    policy::RateLimiter           rate_limit;  // queries per client (§5.9)
    policy::RebindingFilter       rebinding;   // private addresses in answers (§5.8)
    security::ResponseRateLimiter rrl;         // identical UDP responses per client network (§5.9)
#ifdef DNSENTINEL_ML
    std::optional<ml::DgaCheck> dga{};  // the DGA classifier (§7.8.2); none: off
#endif
};

class QueryProcessor {
public:
    using BlockFn     = std::function<void(const BlockEvent&)>;
    using RebindingFn = std::function<void(const RebindingEvent&)>;
#ifdef DNSENTINEL_ML
    using DgaFn = std::function<void(const DgaEvent&)>;
#endif

    /// `resolver` and `lists` must outlive the processor, and resolutions it
    /// started must not complete after it is gone: destroy it only once the
    /// loop has stopped, or with the resolver (which abandons them).
    QueryProcessor(resolver::RecursiveResolver& resolver, const policy::Blocklists& lists, Checks checks);

    /// Called for every blocked answer, before it is sent.
    void on_block(BlockFn fn) { on_block_ = std::move(fn); }
    /// Called whenever rebinding protection changes an answer, before it is sent.
    void on_rebinding(RebindingFn fn) { on_rebinding_ = std::move(fn); }
#ifdef DNSENTINEL_ML
    /// Called for every query the DGA classifier flags, before it is answered
    /// (resolved in monitor mode, answered like a blocked name in enforce mode).
    void on_dga(DgaFn fn) { on_dga_ = std::move(fn); }
#endif

    /// The checks, for their counters.
    [[nodiscard]] const Checks& checks() const { return checks_; }

    /// A net::QueryHandler. A client outside the allowed subnets gets
    /// REFUSED, or nothing (DenyAction::Drop), before anything else happens;
    /// so does a client over its rate limit, according to its own setting.
    /// Queries that can't be answered get their error response at once, and
    /// so do blocked names (never sent upstream); the rest once resolution
    /// finishes (SERVFAIL if it fails), blocked after all if a name in the
    /// answer's CNAME chain is, and without private addresses unless the
    /// name is exempt (NXDOMAIN if no address is left). The response echoes
    /// the client's question exactly, case included. Over UDP, a response
    /// over the RRL cap is dropped or sent truncated instead.
    void handle(Message query, const net::ClientInfo& client, net::Responder respond);

private:
    void report(const Question& question, std::vector<Name> chain, policy::TrieLookupResult match);

    resolver::RecursiveResolver& resolver_;
    const policy::Blocklists&    lists_;
    Checks                       checks_;
    BlockFn                      on_block_;
    RebindingFn                  on_rebinding_;
#ifdef DNSENTINEL_ML
    DgaFn on_dga_;
#endif
};

}  // namespace dnsentinel::server
