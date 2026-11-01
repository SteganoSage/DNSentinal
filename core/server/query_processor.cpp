/// @file server/query_processor.cpp
/// Query checks, the dynamic rules, the block lists and the DGA classifier,
/// then resolution, then the checks on the answer: the CNAME chain and
/// rebinding protection. Each answer can be reported as an event.

#include "dnsentinel/server/query_processor.h"

#include "dnsentinel/policy/cname_check.h"
#include "dnsentinel/resolver/recursive_resolver.h"
#include "dnsentinel/wire/builder.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <memory>
#include <optional>
#include <string>
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

/// What decided a query's answer, for its event: filled in as the checks run.
struct Decision {
    telemetry::Action     action = telemetry::Action::Answer;
    std::string           rule;
    std::optional<double> dga;
};

/// Turn `response`, fresh from make_response(query), into the answer for a
/// blocked name (README §7.6.2): an address that goes nowhere, or NXDOMAIN,
/// either way with a short TTL.
Message blocked(Message response, policy::BlockResponse how, uint32_t ttl) {
    if (how == policy::BlockResponse::NxDomain) {
        response.header.rcode = static_cast<uint8_t>(RCode::NXDomain);
        return response;
    }

    const Question& q = response.questions.front();
    RR              rr;
    rr.name  = q.qname;
    rr.ttl   = ttl;
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

Message blocked(Message response, const policy::ListsConfig& lists) {
    return blocked(std::move(response), lists.response, lists.block_ttl);
}

/// A dynamic rule, for the event: "tunnel-domain.example for 192.168.1.23/32 (tunnel, 0.97, rule 7)".
std::string describe(const policy::DynamicRule& rule) {
    std::string domain = rule.domain.to_string();
    if (domain.size() > 1) domain.pop_back();
    char score[32];
    std::snprintf(score, sizeof score, "%.2f", rule.score);
    return domain + " for " + (rule.client ? rule.client->to_string() : std::string("everyone")) + " (" +
           (rule.reason.empty() ? "no reason given" : rule.reason) + ", " + score + ", rule " +
           std::to_string(rule.id) + ")";
}

}  // namespace

QueryProcessor::QueryProcessor(resolver::RecursiveResolver& resolver, const policy::Blocklists& lists, Checks checks)
    : resolver_(resolver), lists_(lists), checks_(std::move(checks)) {}

void QueryProcessor::report(const Question& question, std::vector<Name> chain, policy::TrieLookupResult match) {
    if (on_block_) on_block_(BlockEvent{question, std::move(chain), std::move(match)});
}

void QueryProcessor::handle(Message query, const net::ClientInfo& client, net::Responder respond) {
    using Clock = std::chrono::steady_clock;

    // Response rate limiting (plan §5.9) sees every UDP response on its way
    // out, refusals included: a forged source address can't be told apart
    // from a real one, and every response goes to whoever owns it.
    if (client.transport == net::Transport::Udp && checks_.rrl.enabled()) {
        respond = [this, addr = client.addr, send = std::move(respond)](const Message& response) {
            switch (checks_.rrl.check(addr, response, Clock::now())) {
            case security::RrlVerdict::Send: send(response); break;
            case security::RrlVerdict::Slip: send(security::truncated(response)); break;
            case security::RrlVerdict::Drop: break;
            }
        };
    }

    // The event for the slow path (README §6.2) and the query counters
    // (README §7.10): taken as the answer goes out, from what the checks
    // below decide. The event only if someone wants it.
    std::shared_ptr<Decision> decision;
    const bool                want_event = on_query_ && (!query_wanted_ || query_wanted_());
    if (want_event || metrics_ != nullptr) {
        decision = std::make_shared<Decision>();
        respond  = [this, decision, client, want_event, arrived = Clock::now(), wall = std::chrono::system_clock::now(),
                   send = std::move(respond)](const Message& response) {
            const auto latency = std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - arrived);
            if (metrics_ != nullptr) {
                const uint16_t qtype = response.questions.empty() ? 0 : response.questions.front().qtype;
                metrics_->record(client.transport, qtype, response.header.rcode, decision->action, latency);
            }
            if (want_event && !response.questions.empty()) {
                telemetry::QueryEvent event;
                event.time          = wall;
                event.client        = client.addr;
                event.transport     = client.transport;
                event.question      = response.questions.front();
                event.rcode         = response.header.rcode;
                event.answers       = static_cast<uint16_t>(response.answers.size());
                event.response_size = wire::build(response).size();
                event.latency_us    = static_cast<uint32_t>(latency.count());
                event.action = decision->action;
                event.rule   = decision->rule;
                event.dga    = decision->dga;
                on_query_(event);
            }
            send(response);
        };
    }
    auto decide = [&decision](telemetry::Action action, std::string rule = {}) {
        if (!decision) return;
        decision->action = action;
        decision->rule   = std::move(rule);
    };

    // Access control first (plan §5.5): outsiders cost us nothing further,
    // and never cause an upstream query.
    if (!checks_.access.allows(client.addr)) {
        if (checks_.access.deny_action() == policy::DenyAction::Refuse) {
            decide(telemetry::Action::Refused);
            respond(wire::make_response(query, RCode::Refused));
        }
        return;
    }
    // Then the client's own rate limit (plan §5.9).
    if (!checks_.rate_limit.allow(client.addr, Clock::now())) {
        if (checks_.rate_limit.config().action == policy::DenyAction::Refuse) {
            decide(telemetry::Action::RateLimited);
            respond(wire::make_response(query, RCode::Refused));
        }
        return;
    }
    if (auto rcode = reject_reason(query)) {
        decide(telemetry::Action::Rejected);
        respond(wire::make_response(query, *rcode));
        return;
    }
    // Block and allow lists (plan §5.6): a blocked name is answered here,
    // without a single upstream query; an allowed one is never blocked.
    const Question& question = query.questions.front();
    auto            match    = lists_.lookup(question.qname);
    // Before them, the slow path's dynamic rules (README §7.6.6); but an
    // allowlisted name was vouched for by a person, and no verdict overrides that.
    if (checks_.dynamic && !(match.matched && match.action == policy::ListAction::Allow)) {
        if (const auto* rule = checks_.dynamic->match(question.qname, client.addr, Clock::now())) {
            decide(telemetry::Action::Dynamic, describe(*rule));
            respond(blocked(wire::make_response(query), checks_.dynamic->config().response, lists_.config().block_ttl));
            return;
        }
    }
    if (match.matched && match.action == policy::ListAction::Block) {
        decide(telemetry::Action::Block, match.rule + " (" + match.source + ")");
        report(question, {question.qname}, std::move(match));
        respond(blocked(wire::make_response(query), lists_.config()));
        return;
    }
#ifdef DNSENTINEL_ML
    // The DGA classifier (plan §7.8.2), for names the lists say nothing
    // about: an allowlisted name was vouched for, a blocked one is answered.
    if (checks_.dga && !match.matched) {
        auto result = checks_.dga->check(question.qname);
        if (result && decision) decision->dga = result->verdict.score;
        if (result && result->verdict.dga) {
            const bool enforce = checks_.dga->mode() == ml::DgaMode::Enforce;
            if (on_dga_) on_dga_(DgaEvent{question, result->verdict, result->cached, enforce});
            if (enforce) {
                decide(telemetry::Action::Dga, result->verdict.registrable);
                respond(blocked(wire::make_response(query), lists_.config()));
                return;
            }
        }
    }
#endif
    // CNAME cloaking (plan §5.7) can only be seen in the answer. An
    // allowlisted name is exempt: whatever it aliases was vouched for too.
    const bool check_chain = lists_.config().check_cname_chain && !match.matched;

    resolver_.resolve(question, [this, check_chain, decision, response = wire::make_response(query),
                                 respond = std::move(respond)](
                                    std::expected<resolver::ResolveResult, resolver::ResolveError> result) mutable {
        if (!result) {
            response.header.rcode = static_cast<uint8_t>(RCode::ServFail);
            respond(response);
            return;
        }
        const Question& asked = response.questions.front();
        if (check_chain) {
            if (auto cloaked = policy::find_cloaked(asked.qname, result->response.answers, lists_.trie())) {
                if (decision) {
                    decision->action = telemetry::Action::CnameBlock;
                    decision->rule   = cloaked->match.rule + " (" + cloaked->match.source + ")";
                }
                report(asked, std::move(cloaked->chain), std::move(cloaked->match));
                respond(blocked(std::move(response), lists_.config()));
                return;
            }
        }
        // Rebinding protection (plan §5.8), on real answers only: our own
        // blocked answers point at 0.0.0.0 on purpose.
        auto& answers = result->response.answers;
        if (auto removed = checks_.rebinding.strip(asked.qname, answers); !removed.empty()) {
            const bool emptied = std::none_of(answers.begin(), answers.end(), [](const RR& rr) {
                return rr.type == RRType::A || rr.type == RRType::AAAA;
            });
            if (on_rebinding_) on_rebinding_(RebindingEvent{asked, std::move(removed), emptied});
            if (emptied) {  // the name pointed only inside the network
                if (decision) decision->action = telemetry::Action::Rebinding;
                response.header.rcode = static_cast<uint8_t>(RCode::NXDomain);
                respond(response);
                return;
            }
        }
        response.header.rcode = result->response.header.rcode;
        response.answers      = std::move(answers);
        response.authority    = std::move(result->response.authority);
        respond(response);
    });
}

}  // namespace dnsentinel::server
