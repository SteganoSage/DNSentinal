#pragma once
/// A tiny authoritative DNS server for tests: serves one zone on a loopback
/// address, refers queries for delegated child zones, answers from its
/// records (following in-zone CNAMEs), and returns NXDOMAIN / NODATA with
/// the zone's SOA otherwise. `tamper` and `delay` make it misbehave.

#include "dnsentinel/net/udp_listener.h"
#include "dnsentinel/wire/builder.h"
#include "../wire/wire_test_util.h"

#include <gtest/gtest.h>

#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace dnsentinel::test {

/// `label` + `zone`, e.g. child("ns", root) == "ns."
inline Name child_name(std::string_view label, const Name& zone) {
    Name n;
    n.append_label(label);
    for (const auto& l : zone.original_case) n.append_label(l);
    return n;
}

class FakeAuth {
public:
    FakeAuth(net::EventLoop& loop, const std::string& ip, uint16_t port, std::string_view zone)
        : loop_(loop), zone_(name(zone)) {
        RR soa;
        soa.name  = zone_;
        soa.type  = RRType::SOA;
        soa.ttl   = 300;
        soa.rdata = RDataSOA{child_name("ns", zone_), child_name("hostmaster", zone_), 1, 3600, 600, 86400, 300};
        soa_      = soa;

        auto listener = net::UdpListener::create(
            loop, {.address = ip, .port = port, .max_response_size = 4096},
            [this](Message query, const net::ClientInfo&, net::Responder respond) { on_query(query, respond); });
        EXPECT_TRUE(listener.has_value()) << ip << ":" << port << " " << (listener ? "" : listener.error().message());
        if (listener) listener_ = std::move(*listener);
    }

    [[nodiscard]] uint16_t port() const { return listener_ ? listener_->port() : 0; }

    /// Authoritative data for this zone.
    void add(std::string_view owner, RRType type, RData rdata, uint32_t ttl = 300) {
        records_.push_back(make_rr(owner, type, std::move(rdata), ttl));
    }

    /// Delegate `child` to name servers; a non-empty address becomes glue.
    void delegate(std::string_view child, const std::vector<std::pair<std::string, std::string>>& servers) {
        Delegation d;
        d.zone = name(child);
        for (const auto& [ns, ip] : servers) {
            d.ns.push_back(make_rr(child, RRType::NS, RDataNS{name(ns)}, 3600));
            if (!ip.empty()) d.glue.push_back(make_rr(ns, RRType::A, ipv4(ip.c_str()), 3600));
        }
        delegations_.push_back(std::move(d));
    }

    /// Misbehave: edit the response, or return false to drop it.
    std::function<bool(const Message& query, Message& response)> tamper;
    std::chrono::milliseconds                                    delay{0};

    int                   queries = 0;
    std::vector<Question> seen;

private:
    struct Delegation {
        Name            zone;
        std::vector<RR> ns;
        std::vector<RR> glue;
    };

    void on_query(const Message& query, const net::Responder& respond) {
        ++queries;
        if (!query.questions.empty()) seen.push_back(query.questions.front());
        Message response = answer(query);
        if (tamper && !tamper(query, response)) return;
        if (delay.count() > 0) {
            loop_.add_timer(delay, [respond, response] { respond(response); });
        } else {
            respond(response);
        }
    }

    [[nodiscard]] std::vector<RR> at(const Name& owner, uint16_t type) const {
        std::vector<RR> out;
        for (const auto& rr : records_) {
            if (rr.name == owner && static_cast<uint16_t>(rr.type) == type) out.push_back(rr);
        }
        return out;
    }

    [[nodiscard]] Message answer(const Message& query) const {
        Message r    = wire::make_response(query);
        r.header.ra  = false;
        if (query.questions.size() != 1) {
            r.header.rcode = static_cast<uint8_t>(RCode::FormErr);
            return r;
        }
        const Question& q = query.questions.front();
        if (!q.qname.is_subdomain_of(zone_)) {
            r.header.rcode = static_cast<uint8_t>(RCode::Refused);
            return r;
        }
        for (const auto& d : delegations_) {
            if (q.qname.is_subdomain_of(d.zone)) {  // referral: not authoritative
                r.authority  = d.ns;
                r.additional = d.glue;
                return r;
            }
        }

        r.header.aa = true;
        Name current = q.qname;
        for (int hops = 0; hops < 12; ++hops) {
            auto matching = at(current, q.qtype);
            if (!matching.empty()) {
                r.answers.insert(r.answers.end(), matching.begin(), matching.end());
                if (q.qtype == static_cast<uint16_t>(RRType::NS)) add_glue(r, matching);
                return r;
            }
            auto cname = at(current, static_cast<uint16_t>(RRType::CNAME));
            if (cname.empty() || q.qtype == static_cast<uint16_t>(RRType::CNAME)) break;
            r.answers.push_back(cname.front());
            current = std::get<RDataCNAME>(cname.front().rdata).target;
            if (!current.is_subdomain_of(zone_)) return r;  // the rest is another zone's business
        }

        bool exists = false;  // including empty non-terminals
        for (const auto& rr : records_) exists = exists || rr.name.is_subdomain_of(current);
        if (!exists) r.header.rcode = static_cast<uint8_t>(RCode::NXDomain);
        r.authority = {soa_};
        return r;
    }

    void add_glue(Message& r, const std::vector<RR>& ns_records) const {
        for (const auto& ns : ns_records) {
            auto a = at(std::get<RDataNS>(ns.rdata).nsdname, static_cast<uint16_t>(RRType::A));
            r.additional.insert(r.additional.end(), a.begin(), a.end());
        }
    }

    net::EventLoop&                   loop_;
    Name                              zone_;
    RR                                soa_;
    std::vector<RR>                   records_;
    std::vector<Delegation>           delegations_;
    std::unique_ptr<net::UdpListener> listener_;
};

}  // namespace dnsentinel::test
