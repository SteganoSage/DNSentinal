#include "dnsentinel/resolver/recursive_resolver.h"

#include "dnsentinel/cache/cache.h"
#include "dnsentinel/net/event_loop.h"
#include "fake_auth.h"

#include <gtest/gtest.h>

#include <arpa/inet.h>

#include <chrono>
#include <optional>
#include <random>
#include <set>
#include <string>
#include <vector>

using namespace dnsentinel;
using namespace dnsentinel::resolver;
using namespace dnsentinel::test;
using namespace std::chrono_literals;
using Outcome = std::expected<ResolveResult, ResolveError>;
using Clock   = std::chrono::steady_clock;

namespace {

std::vector<std::string> a_records(const Outcome& o) {
    std::vector<std::string> out;
    for (const auto& rr : o->response.answers) {
        if (const auto* a = std::get_if<RDataA>(&rr.rdata)) {
            char text[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &a->addr, text, sizeof text);
            out.emplace_back(text);
        }
    }
    return out;
}

std::vector<RRType> answer_types(const Outcome& o) {
    std::vector<RRType> out;
    for (const auto& rr : o->response.answers) out.push_back(rr.type);
    return out;
}

bool drop_everything(const Message&, Message&) { return false; }

/// A small DNS hierarchy on loopback addresses 127.X.Y.n (X and Y random per
/// test so parallel runs don't collide), every server on the same port:
///
///   .1     "."              → test. (.2), net. (.4)
///   .2     "test."          → example.test. (.3, .7); glueless.test. (NS
///                             ns.dns-host.net, no glue); cyc.test. (its NS is
///                             inside itself, no glue); nxns.test. (20 glueless
///                             NS names in victim.net)
///   .3/.7  "example.test."  www, alias, ext, mail, loop1/loop2, a.b, w0..w19, ns1
///   .4     "net."           → dns-host.net. (.5), victim.net. (.8)
///   .5     "dns-host.net."  ns.dns-host.net → .6
///   .6     "glueless.test." www
///   .8     "victim.net."    empty; counts the traffic sent its way
///   .9     added by attack tests: a server that must never be asked
class ResolverTest : public ::testing::Test {
protected:
    void SetUp() override {
        std::random_device rd;
        base_ = "127." + std::to_string(1 + rd() % 254) + "." + std::to_string(rd() % 255) + ".";

        root = add_server(1, ".");  // created first: it picks the shared port
        root->add(".", RRType::NS, RDataNS{name("a.root-servers.lab")});
        root->add("a.root-servers.lab", RRType::A, ipv4(ip(1).c_str()));
        root->delegate("test", {{"ns.test", ip(2)}});
        root->delegate("net", {{"ns.net", ip(4)}});

        tld = add_server(2, "test");
        tld->delegate("example.test", {{"ns1.example.test", ip(3)}, {"ns2.example.test", ip(7)}});
        tld->delegate("glueless.test", {{"ns.dns-host.net", ""}});
        tld->delegate("cyc.test", {{"ns.cyc.test", ""}});
        std::vector<std::pair<std::string, std::string>> nxns;
        for (int i = 0; i < 20; ++i) nxns.emplace_back("ns" + std::to_string(i) + ".victim.net", "");
        tld->delegate("nxns.test", nxns);

        ex1 = add_server(3, "example.test");
        ex2 = add_server(7, "example.test");
        for (FakeAuth* ex : {ex1, ex2}) {
            ex->add("www.example.test", RRType::A, ipv4("192.0.2.1"));
            ex->add("alias.example.test", RRType::CNAME, RDataCNAME{name("www.example.test")});
            ex->add("ext.example.test", RRType::CNAME, RDataCNAME{name("www.glueless.test")});
            ex->add("mail.example.test", RRType::MX, RDataMX{10, name("mail.example.test")});
            ex->add("mail.example.test", RRType::A, ipv4("192.0.2.25"));
            ex->add("loop1.example.test", RRType::CNAME, RDataCNAME{name("loop2.example.test")});
            ex->add("loop2.example.test", RRType::CNAME, RDataCNAME{name("loop1.example.test")});
            ex->add("a.b.example.test", RRType::A, ipv4("192.0.2.9"));
            ex->add("ns1.example.test", RRType::A, ipv4("192.0.2.53"));  // glue from test. says .3
            for (int i = 0; i < 20; ++i) {
                ex->add("w" + std::to_string(i) + ".example.test", RRType::A, ipv4("192.0.2.2"));
            }
        }

        net = add_server(4, "net");
        net->delegate("dns-host.net", {{"ns.dns-host.net", ip(5)}});
        net->delegate("victim.net", {{"ns.victim.net", ip(8)}});
        dns_host = add_server(5, "dns-host.net");
        dns_host->add("ns.dns-host.net", RRType::A, ipv4(ip(6).c_str()));
        glueless = add_server(6, "glueless.test");
        glueless->add("www.glueless.test", RRType::A, ipv4("192.0.2.66"));
        victim = add_server(8, "victim.net");

        config.upstream_port       = port_;
        config.query_timeout_ms    = 200;
        config.overall_deadline_ms = 3000;
    }

    [[nodiscard]] std::string ip(int n) const { return base_ + std::to_string(n); }

    FakeAuth* add_server(int n, std::string_view zone) {
        servers_.push_back(std::make_unique<FakeAuth>(*loop, ip(n), port_, zone));
        if (port_ == 0) port_ = servers_.back()->port();
        return servers_.back().get();
    }

    [[nodiscard]] RootHints hints() const {
        RootHints h;
        h.ns.push_back(make_rr(".", RRType::NS, RDataNS{name("a.root-servers.lab")}));
        h.addresses.push_back(make_rr("a.root-servers.lab", RRType::A, ipv4(ip(1).c_str())));
        return h;
    }

    /// Built on first use, so tests can adjust `config` first.
    RecursiveResolver& resolver() {
        if (!resolver_) resolver_ = std::make_unique<RecursiveResolver>(config, hints(), *loop, cache);
        return *resolver_;
    }
    void destroy_resolver() { resolver_.reset(); }

    void run_for(std::chrono::milliseconds limit) {
        auto guard = loop->add_timer(limit, [this] { loop->stop(); });
        loop->run();
        loop->cancel_timer(guard);
    }

    Outcome resolve(std::string_view qname, RRType type, uint16_t qclass = 1) {
        std::optional<Outcome> out;
        int calls = 0;
        resolver().resolve({name(qname), static_cast<uint16_t>(type), qclass}, [&](Outcome o) {
            ++calls;
            out = std::move(o);
            loop->stop();
        });
        run_for(10s);
        EXPECT_EQ(calls, 1) << qname;
        if (!out) return std::unexpected(ResolveError::ServFail);
        return std::move(*out);
    }

    [[nodiscard]] int total_queries() const {
        int total = 0;
        for (const auto& s : servers_) total += s->queries;
        return total;
    }

    std::unique_ptr<net::EventLoop> loop = net::EventLoop::create().value();
    cache::Cache   cache{cache::CacheConfig{}};
    ResolverConfig config;
    FakeAuth *root = nullptr, *tld = nullptr, *ex1 = nullptr, *ex2 = nullptr, *net = nullptr,
             *dns_host = nullptr, *glueless = nullptr, *victim = nullptr;

private:
    std::string                            base_;
    uint16_t                               port_ = 0;
    std::vector<std::unique_ptr<FakeAuth>> servers_;
    std::unique_ptr<RecursiveResolver>     resolver_;
};

}  // namespace

// ─── Walking the tree ───────────────────────────────────────────────────────

TEST_F(ResolverTest, WalksDelegationsFromTheRoot) {
    auto r = resolve("www.example.test", RRType::A);
    ASSERT_TRUE(r.has_value()) << resolve_error_to_string(r.error());
    EXPECT_EQ(r->response.header.rcode, 0);
    EXPECT_EQ(a_records(r), (std::vector<std::string>{"192.0.2.1"}));
    EXPECT_EQ(r->upstream_queries_used, 3u);  // root → test. → example.test.
    EXPECT_EQ(root->queries, 1);
    EXPECT_EQ(tld->queries, 1);
    EXPECT_EQ(ex1->queries + ex2->queries, 1);
}

TEST_F(ResolverTest, RepeatQueriesAreAnsweredFromCache) {
    ASSERT_TRUE(resolve("www.example.test", RRType::A).has_value());
    const int before = total_queries();
    auto r = resolve("www.example.test", RRType::A);
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(a_records(r), (std::vector<std::string>{"192.0.2.1"}));
    EXPECT_EQ(r->upstream_queries_used, 0u);
    EXPECT_EQ(total_queries(), before);
}

TEST_F(ResolverTest, CachedDelegationsSkipStraightToTheZone) {
    ASSERT_TRUE(resolve("www.example.test", RRType::A).has_value());
    auto r = resolve("mail.example.test", RRType::MX);
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(answer_types(r), (std::vector<RRType>{RRType::MX}));
    EXPECT_EQ(r->upstream_queries_used, 1u);
    EXPECT_EQ(root->queries, 1);
}

TEST_F(ResolverTest, FollowsCnameInsideTheZone) {
    auto r = resolve("alias.example.test", RRType::A);
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(answer_types(r), (std::vector<RRType>{RRType::CNAME, RRType::A}));
    EXPECT_EQ(a_records(r), (std::vector<std::string>{"192.0.2.1"}));
    EXPECT_EQ(r->upstream_queries_used, 3u);  // the zone answered the whole chain at once
}

TEST_F(ResolverTest, FollowsCnameIntoAZoneWithAGluelessNameServer) {
    // ext.example.test → www.glueless.test, whose zone's only name server
    // (ns.dns-host.net) came without glue and must be resolved first.
    auto r = resolve("ext.example.test", RRType::A);
    ASSERT_TRUE(r.has_value()) << resolve_error_to_string(r.error());
    EXPECT_EQ(answer_types(r), (std::vector<RRType>{RRType::CNAME, RRType::A}));
    EXPECT_EQ(a_records(r), (std::vector<std::string>{"192.0.2.66"}));
    EXPECT_EQ(dns_host->queries, 1);
    EXPECT_EQ(glueless->queries, 1);
}

// ─── Negative answers ───────────────────────────────────────────────────────

TEST_F(ResolverTest, NxdomainCoversEveryTypeAndIsCached) {
    auto r = resolve("nope.example.test", RRType::A);
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->response.header.rcode, static_cast<uint8_t>(RCode::NXDomain));
    EXPECT_TRUE(r->response.answers.empty());
    ASSERT_EQ(r->response.authority.size(), 1u);
    EXPECT_EQ(r->response.authority[0].type, RRType::SOA);

    const int before = total_queries();
    auto again = resolve("nope.example.test", RRType::TXT);  // different type, same verdict
    ASSERT_TRUE(again.has_value());
    EXPECT_EQ(again->response.header.rcode, static_cast<uint8_t>(RCode::NXDomain));
    EXPECT_EQ(total_queries(), before);
}

TEST_F(ResolverTest, NodataIsCached) {
    auto r = resolve("www.example.test", RRType::AAAA);
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->response.header.rcode, 0);
    EXPECT_TRUE(r->response.answers.empty());
    EXPECT_EQ(r->response.authority.size(), 1u);

    auto again = resolve("www.example.test", RRType::AAAA);
    ASSERT_TRUE(again.has_value());
    EXPECT_EQ(again->upstream_queries_used, 0u);
}

TEST_F(ResolverTest, EmptyNonTerminalIsNodataNotNxdomain) {
    auto r = resolve("b.example.test", RRType::A);  // only a.b.example.test has records
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->response.header.rcode, 0);
    EXPECT_TRUE(r->response.answers.empty());
}

// ─── Failures and time limits ───────────────────────────────────────────────

TEST_F(ResolverTest, DeadServerIsAvoidedAfterOneTimeout) {
    config.query_timeout_ms = 50;
    config.explore_one_in   = 0;
    ex1->tamper = drop_everything;
    for (int i = 0; i < 20; ++i) {
        auto r = resolve("w" + std::to_string(i) + ".example.test", RRType::A);
        ASSERT_TRUE(r.has_value()) << i << ": " << resolve_error_to_string(r.error());
        EXPECT_EQ(a_records(r), (std::vector<std::string>{"192.0.2.2"}));
    }
    // If it was picked first it timed out once; after that the live server
    // is measured and the dead one is only ever behind it (plan §4.3).
    EXPECT_LE(ex1->queries, 1);
}

TEST_F(ResolverTest, KnownFastServerIsGivenUpOnQuickly) {
    config.query_timeout_ms     = 2000;  // for servers never measured
    config.max_query_timeout_ms = 3000;
    config.explore_one_in       = 0;
    ASSERT_TRUE(resolve("www.example.test", RRType::A).has_value());  // measures one of example.test's servers

    // That server now loses one query. Its timeout comes from its measured
    // round trips (~100 ms floor), not the 2 s default, before the other
    // server is asked.
    bool dropped = false;
    ex1->tamper = ex2->tamper = [&](const Message& q, Message&) {
        if (dropped || q.questions.at(0).qname != name("w1.example.test")) return true;
        dropped = true;
        return false;
    };
    const auto start = Clock::now();
    auto r = resolve("w1.example.test", RRType::A);
    const auto took = Clock::now() - start;
    ASSERT_TRUE(r.has_value()) << resolve_error_to_string(r.error());
    EXPECT_TRUE(dropped);
    EXPECT_GE(took, 100ms);
    EXPECT_LT(took, 1s);
}

TEST_F(ResolverTest, FailsWhenEveryServerIsDown) {
    config.query_timeout_ms     = 50;
    config.max_query_timeout_ms = 200;
    ex1->tamper = ex2->tamper = drop_everything;
    const auto start = Clock::now();
    auto r = resolve("www.example.test", RRType::A);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), ResolveError::AllServersFailed);
    EXPECT_EQ(ex1->queries, 3);  // the first round plus two retry rounds
    EXPECT_EQ(ex2->queries, 3);
    EXPECT_GE(Clock::now() - start, 950ms);  // 50, 100, then 200 ms (capped) four times
}

TEST_F(ResolverTest, ServersThatTimedOutAreRetriedWithALongerWait) {
    // Both of example.test's servers lose their first query. Instead of
    // giving up, the resolver asks again, waiting longer (plan §3.3).
    config.query_timeout_ms = 50;
    int seen1 = 0, seen2 = 0;
    ex1->tamper = [&](const Message&, Message&) { return ++seen1 > 1; };
    ex2->tamper = [&](const Message&, Message&) { return ++seen2 > 1; };
    auto r = resolve("www.example.test", RRType::A);
    ASSERT_TRUE(r.has_value()) << resolve_error_to_string(r.error());
    EXPECT_EQ(a_records(r), (std::vector<std::string>{"192.0.2.1"}));
    EXPECT_EQ(ex1->queries + ex2->queries, 3);  // each lost one, then one answered
}

TEST_F(ResolverTest, UnreachableServersAreNotRetried) {
    // closed.test is delegated to two addresses where nothing listens, so
    // each query comes straight back as ICMP port unreachable. Asking again
    // is pointless: each is asked once. The budget covers root, test. and
    // those two queries, so any retry would exceed it.
    tld->delegate("closed.test", {{"ns1.closed.test", ip(10)}, {"ns2.closed.test", ip(11)}});
    config.max_upstream_queries = 4;
    auto r = resolve("www.closed.test", RRType::A);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), ResolveError::AllServersFailed);
}

TEST_F(ResolverTest, ServersThatRefuseAreNotRetried) {
    ex1->tamper = ex2->tamper = [](const Message&, Message& r) {
        r.header.rcode = static_cast<uint8_t>(RCode::Refused);
        r.answers.clear();
        return true;
    };
    auto r = resolve("www.example.test", RRType::A);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), ResolveError::AllServersFailed);
    EXPECT_EQ(ex1->queries + ex2->queries, 2);  // an answer, even a refusal, isn't retried
}

TEST_F(ResolverTest, OverallDeadlineBoundsResolution) {
    config.query_timeout_ms    = 1000;
    config.overall_deadline_ms = 150;
    ex1->delay = ex2->delay = 2s;
    const auto start = Clock::now();
    auto r = resolve("www.example.test", RRType::A);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), ResolveError::Timeout);
    EXPECT_LT(Clock::now() - start, 1s);
}

TEST_F(ResolverTest, RefusedResponsesMoveOnToAnotherServer) {
    config.explore_one_in = 0;
    ex1->tamper = [](const Message&, Message& r) {
        r.header.rcode = static_cast<uint8_t>(RCode::Refused);
        r.answers.clear();
        return true;
    };
    for (int i = 0; i < 6; ++i) {
        EXPECT_TRUE(resolve("w" + std::to_string(i) + ".example.test", RRType::A).has_value()) << i;
    }
    EXPECT_LE(ex1->queries, 1);  // then the server that answers is preferred
}

TEST_F(ResolverTest, TruncatedAnswerIsFetchedOverTcp) {
    ex1->truncate_udp = ex2->truncate_udp = true;
    auto r = resolve("www.example.test", RRType::A);
    ASSERT_TRUE(r.has_value()) << resolve_error_to_string(r.error());
    EXPECT_EQ(a_records(r), (std::vector<std::string>{"192.0.2.1"}));
    EXPECT_EQ(ex1->tcp_queries + ex2->tcp_queries, 1);  // the same server, asked again over TCP
    EXPECT_EQ(ex1->queries + ex2->queries, 2);
    EXPECT_EQ(r->upstream_queries_used, 4u);
}

TEST_F(ResolverTest, TruncatedEvenOverTcpMovesOnToAnotherServer) {
    ex1->tamper = [](const Message&, Message& r) {  // TC on every transport: broken
        r.header.tc = true;
        r.answers.clear();
        return true;
    };
    for (int i = 0; i < 6; ++i) {
        EXPECT_TRUE(resolve("w" + std::to_string(i) + ".example.test", RRType::A).has_value()) << i;
    }
    EXPECT_EQ(ex2->tcp_queries, 0);
}

// ─── Attacks and resource limits ────────────────────────────────────────────

TEST_F(ResolverTest, OutOfBailiwickRecordsAreNeverCached) {
    // Kaminsky-style injection: example.test's server slips in records for a
    // zone it has no authority over.
    ex1->tamper = ex2->tamper = [](const Message&, Message& r) {
        r.answers.push_back(make_rr("www.bank.net", RRType::A, ipv4("6.6.6.6")));
        r.additional.push_back(make_rr("ns.bank.net", RRType::A, ipv4("6.6.6.6")));
        return true;
    };
    auto r = resolve("www.example.test", RRType::A);
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(a_records(r), (std::vector<std::string>{"192.0.2.1"}));
    EXPECT_FALSE(cache.lookup({name("www.bank.net"), 1, 1}).entry.has_value());
    EXPECT_FALSE(cache.lookup({name("ns.bank.net"), 1, 1}).entry.has_value());
}

TEST_F(ResolverTest, InjectedCnameTargetIsNotBelieved) {
    // The CNAME points out of the zone; a forged address for the target in
    // the same response must be ignored and the target resolved properly.
    ex1->tamper = ex2->tamper = [](const Message&, Message& r) {
        r.answers.push_back(make_rr("www.glueless.test", RRType::A, ipv4("6.6.6.6")));
        return true;
    };
    auto r = resolve("ext.example.test", RRType::A);
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(a_records(r), (std::vector<std::string>{"192.0.2.66"}));
}

TEST_F(ResolverTest, UpwardAndUnrelatedReferralsAreIgnored) {
    auto refer_to = [](std::string zone) {
        return [zone](const Message&, Message& r) {
            r.header.aa = false;
            r.answers.clear();
            r.authority  = {make_rr(zone, RRType::NS, RDataNS{name("ns.evil.lab")})};
            r.additional = {make_rr("ns.evil.lab", RRType::A, ipv4("127.0.0.66"))};
            return true;
        };
    };
    ex1->tamper = ex2->tamper = refer_to("test");  // back up the tree
    EXPECT_FALSE(resolve("www.example.test", RRType::A).has_value());
    EXPECT_EQ(tld->queries, 1);

    ex1->tamper = ex2->tamper = refer_to("evil.lab");  // an unrelated zone
    EXPECT_FALSE(resolve("mail.example.test", RRType::A).has_value());
    EXPECT_FALSE(cache.lookup({name("evil.lab"), 2, 1}).entry.has_value());
    EXPECT_FALSE(cache.lookup({name("ns.evil.lab"), 1, 1}).entry.has_value());
}

TEST_F(ResolverTest, ReferralsMustLeadTowardsTheName) {
    // test.'s server answers a query for www.example.test with a referral to
    // evil.test: inside its own zone, so bailiwick allows it, but not an
    // ancestor of the name. Following it would hand the query to an attacker.
    FakeAuth* evil = add_server(9, "evil.test");
    tld->tamper = [this](const Message&, Message& r) {
        if (r.authority.empty() || r.authority[0].type != RRType::NS) return true;
        r.authority  = {make_rr("evil.test", RRType::NS, RDataNS{name("ns.evil.test")}, 3600)};
        r.additional = {make_rr("ns.evil.test", RRType::A, ipv4(ip(9).c_str()), 3600)};
        return true;
    };
    EXPECT_FALSE(resolve("www.example.test", RRType::A).has_value());
    EXPECT_EQ(evil->queries, 0);
}

TEST_F(ResolverTest, LameSelfReferralIsNotFollowed) {
    // example.test's servers refer queries for their own zone back to
    // themselves; following that would loop until a limit hit.
    ex1->tamper = ex2->tamper = [this](const Message&, Message& r) {
        r.header.aa = false;
        r.answers.clear();
        r.authority  = {make_rr("example.test", RRType::NS, RDataNS{name("ns1.example.test")}, 3600),
                        make_rr("example.test", RRType::NS, RDataNS{name("ns2.example.test")}, 3600)};
        r.additional = {make_rr("ns1.example.test", RRType::A, ipv4(ip(3).c_str()), 3600),
                        make_rr("ns2.example.test", RRType::A, ipv4(ip(7).c_str()), 3600)};
        return true;
    };
    auto r = resolve("www.example.test", RRType::A);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), ResolveError::AllServersFailed);
    EXPECT_EQ(ex1->queries + ex2->queries, 2);  // each asked once, then given up on
}

TEST_F(ResolverTest, OutOfBailiwickGlueIsNeverUsed) {
    // A compromised test. server delegates example.test to a name server in
    // another zone and supplies "glue" for it pointing at an attacker. test.
    // has no authority over bank.net, so that address must not be believed.
    FakeAuth* evil = add_server(9, "example.test");
    evil->add("www.example.test", RRType::A, ipv4("6.6.6.6"));
    tld->tamper = [this](const Message&, Message& r) {
        if (r.authority.empty() || r.authority[0].type != RRType::NS) return true;
        r.authority  = {make_rr("example.test", RRType::NS, RDataNS{name("ns.bank.net")}, 3600)};
        r.additional = {make_rr("ns.bank.net", RRType::A, ipv4(ip(9).c_str()), 3600)};
        return true;
    };
    auto r = resolve("www.example.test", RRType::A);
    EXPECT_EQ(evil->queries, 0);
    if (r.has_value()) {
        EXPECT_NE(a_records(r), (std::vector<std::string>{"6.6.6.6"}));
    }
    EXPECT_FALSE(cache.lookup({name("ns.bank.net"), 1, 1}).entry.has_value());
}

TEST_F(ResolverTest, GlueIsNeverServedAsAnAnswer) {
    // test.'s referral carried glue saying ns1.example.test is .3. That only
    // helps find servers: a client asking for ns1.example.test gets the
    // zone's own authoritative answer, which here differs.
    ASSERT_TRUE(resolve("www.example.test", RRType::A).has_value());
    auto r = resolve("ns1.example.test", RRType::A);
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(a_records(r), (std::vector<std::string>{"192.0.2.53"}));
    EXPECT_EQ(r->upstream_queries_used, 1u);
}

TEST_F(ResolverTest, CnameLoopIsBounded) {
    auto r = resolve("loop1.example.test", RRType::A);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), ResolveError::MaxCnameChainExceeded);
}

TEST_F(ResolverTest, NameServerCycleFailsFast) {
    // cyc.test's only name server is ns.cyc.test, with no glue: finding its
    // address would need its address.
    auto r = resolve("www.cyc.test", RRType::A);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), ResolveError::AllServersFailed);
    EXPECT_LE(total_queries(), 3);
}

TEST_F(ResolverTest, NxnsReferralCannotFloodAVictim) {
    // nxns.test is delegated to 20 glueless names inside victim.net: an
    // NXNSAttack. Only max_glueless_ns of them may be looked up.
    auto r = resolve("www.nxns.test", RRType::A);
    ASSERT_FALSE(r.has_value());
    EXPECT_GT(victim->queries, 0);
    EXPECT_LE(victim->queries, config.max_glueless_ns);
}

TEST_F(ResolverTest, UpstreamQueryBudgetIsEnforced) {
    config.max_upstream_queries = 2;
    auto r = resolve("www.example.test", RRType::A);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), ResolveError::MaxQueriesExceeded);
    EXPECT_EQ(total_queries(), 2);
}

TEST_F(ResolverTest, OnlyTheInternetClassIsResolved) {
    auto r = resolve("www.example.test", RRType::A, /*CH*/ 3);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), ResolveError::ServFail);
    EXPECT_EQ(total_queries(), 0);
}

// ─── Stub zones ─────────────────────────────────────────────────────────────

TEST_F(ResolverTest, StubZoneSkipsTheRoot) {
    config.stub_zones = {{name("example.test"), {ipv4(ip(3).c_str()).addr}}};
    auto r = resolve("www.example.test", RRType::A);
    ASSERT_TRUE(r.has_value()) << resolve_error_to_string(r.error());
    EXPECT_EQ(a_records(r), (std::vector<std::string>{"192.0.2.1"}));
    EXPECT_EQ(r->upstream_queries_used, 1u);
    EXPECT_EQ(root->queries, 0);
    EXPECT_EQ(tld->queries, 0);
    EXPECT_EQ(ex1->queries, 1);

    // Names outside the stub zone still start at the root.
    ASSERT_TRUE(resolve("www.glueless.test", RRType::A).has_value());
    EXPECT_GT(root->queries, 0);
}

TEST_F(ResolverTest, DelegationsBelowAStubZoneAreFollowed) {
    config.stub_zones = {{name("test"), {ipv4(ip(2).c_str()).addr}}};
    auto r = resolve("www.example.test", RRType::A);
    ASSERT_TRUE(r.has_value()) << resolve_error_to_string(r.error());
    EXPECT_EQ(a_records(r), (std::vector<std::string>{"192.0.2.1"}));
    EXPECT_EQ(root->queries, 0);
    EXPECT_EQ(tld->queries, 1);
    EXPECT_EQ(ex1->queries + ex2->queries, 1);
}

TEST_F(ResolverTest, StubZoneBeatsACachedDelegationForTheSameZone) {
    FakeAuth* other = add_server(9, "example.test");
    other->add("www.example.test", RRType::A, ipv4("6.6.6.6"));
    cache.insert({name("example.test"), 2, 1}, {make_rr("example.test", RRType::NS, RDataNS{name("ns.other.lab")})},
                 TrustRank::Answer, 3600);
    cache.insert({name("ns.other.lab"), 1, 1}, {make_rr("ns.other.lab", RRType::A, ipv4(ip(9).c_str()))},
                 TrustRank::Answer, 3600);

    config.stub_zones = {{name("example.test"), {ipv4(ip(3).c_str()).addr}}};
    auto r = resolve("www.example.test", RRType::A);
    ASSERT_TRUE(r.has_value()) << resolve_error_to_string(r.error());
    EXPECT_EQ(a_records(r), (std::vector<std::string>{"192.0.2.1"}));
    EXPECT_EQ(other->queries, 0);
}

// ─── 0x20 encoding (plan §5.2) ─────────────────────────────────────────────

namespace {

bool has_upper_case(const Question& q) {
    for (const auto& label : q.qname.original_case) {
        for (char c : label) {
            if (c >= 'A' && c <= 'Z') return true;
        }
    }
    return false;
}

}  // namespace

TEST_F(ResolverTest, UpstreamQueriesUseRandomLetterCase) {
    ASSERT_TRUE(resolve("www.example.test", RRType::A).has_value());
    int queries = 0, mixed = 0;
    for (FakeAuth* s : {root, tld, ex1, ex2}) {
        for (const auto& q : s->seen) {
            ++queries;
            mixed += has_upper_case(q);
        }
    }
    EXPECT_EQ(queries, 3);
    EXPECT_GT(mixed, 0);  // 13 letters each: all three in lower case has odds 2^-39
}

TEST_F(ResolverTest, Without0x20QueriesKeepTheCaseAsked) {
    config.use_0x20 = false;
    ASSERT_TRUE(resolve("www.example.test", RRType::A).has_value());
    for (FakeAuth* s : {root, tld, ex1, ex2}) {
        for (const auto& q : s->seen) EXPECT_FALSE(has_upper_case(q));
    }
}

TEST_F(ResolverTest, AnswersComeBackInTheCaseTheClientAsked) {
    // Servers echo our random case into the answer's owner names (they
    // compress them against the question); the client must not see it.
    auto r = resolve("WWW.Example.TEST", RRType::A);
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->response.answers.at(0).name.original_case, (std::vector<std::string>{"WWW", "Example", "TEST"}));
}

TEST_F(ResolverTest, CaseNormalisingServerIsAskedAgainWithout0x20) {
    // Some servers echo the question in lower case whatever was asked. The
    // first time, the resolver waits for an exact echo, then asks again
    // plainly; after that it doesn't use 0x20 with that server at all.
    config.query_timeout_ms = 50;
    auto normalise = [](const Message&, Message& r) {
        r.questions[0].qname.original_case = r.questions[0].qname.labels;
        return true;
    };
    ex1->tamper = ex2->tamper = normalise;
    for (int i = 0; i < 6; ++i) {
        auto r = resolve("w" + std::to_string(i) + ".example.test", RRType::A);
        ASSERT_TRUE(r.has_value()) << i << ": " << resolve_error_to_string(r.error());
        EXPECT_EQ(a_records(r), (std::vector<std::string>{"192.0.2.2"}));
    }
    for (FakeAuth* ex : {ex1, ex2}) {
        int random_case = 0;
        for (const auto& q : ex->seen) random_case += has_upper_case(q);
        EXPECT_LE(random_case, 1);  // once at most, then plain queries only
    }
}

// ─── Spoof detection → TCP (plan §5.4) ─────────────────────────────────────

TEST_F(ResolverTest, ForgedRepliesSwitchTheQueryToTcp) {
    // Kaminsky-style race: forged replies reach the resolver's port before
    // the real answer. At 5 (the default threshold) it stops trusting UDP for
    // that query and asks the same server over TCP, raising an alert.
    ex1->forged_replies = ex2->forged_replies = 5;
    std::vector<SpoofAlert> alerts;
    resolver().on_spoof_alert([&](const SpoofAlert& a) { alerts.push_back(a); });

    auto r = resolve("www.example.test", RRType::A);
    ASSERT_TRUE(r.has_value()) << resolve_error_to_string(r.error());
    EXPECT_EQ(a_records(r), (std::vector<std::string>{"192.0.2.1"}));
    EXPECT_EQ(ex1->tcp_queries + ex2->tcp_queries, 1);
    EXPECT_EQ(ex1->queries + ex2->queries, 2);  // the raced UDP query, then TCP to the same server

    ASSERT_EQ(alerts.size(), 1u);
    EXPECT_EQ(alerts[0].question.qname, name("www.example.test"));
    EXPECT_EQ(alerts[0].question.qtype, 1);
    EXPECT_EQ(alerts[0].replies, 5u);
    const std::string asked = ip(ex1->tcp_queries ? 3 : 7);
    EXPECT_EQ(alerts[0].server, ipv4(asked.c_str()).addr);
}

TEST_F(ResolverTest, AFewForgedRepliesAreJustIgnored) {
    ex1->forged_replies = ex2->forged_replies = 4;  // below the threshold
    int alerts = 0;
    resolver().on_spoof_alert([&](const SpoofAlert&) { ++alerts; });
    auto r = resolve("www.example.test", RRType::A);
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(a_records(r), (std::vector<std::string>{"192.0.2.1"}));
    EXPECT_EQ(ex1->tcp_queries + ex2->tcp_queries, 0);
    EXPECT_EQ(alerts, 0);
}

TEST_F(ResolverTest, SpoofDetectionCanBeTurnedOff) {
    config.spoof_tcp_threshold = 0;
    ex1->forged_replies = ex2->forged_replies = 20;
    int alerts = 0;
    resolver().on_spoof_alert([&](const SpoofAlert&) { ++alerts; });
    auto r = resolve("www.example.test", RRType::A);
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(ex1->tcp_queries + ex2->tcp_queries, 0);  // the real UDP answer, after all 20
    EXPECT_EQ(alerts, 0);
}

// ─── In-flight deduplication (plan §4.4) ───────────────────────────────────

TEST_F(ResolverTest, IdenticalQueriesInFlightShareOneResolution) {
    // 20 clients ask for the same uncached name at once, half of them in
    // another case: one resolution, one query per server, 20 answers.
    const char* spellings[] = {"www.example.test", "WWW.Example.TEST"};
    std::vector<Outcome> outcomes;
    for (int i = 0; i < 20; ++i) {
        resolver().resolve({name(spellings[i % 2]), 1, 1}, [&](Outcome o) {
            outcomes.push_back(std::move(o));
            if (outcomes.size() == 20) loop->stop();
        });
    }
    run_for(5s);
    ASSERT_EQ(outcomes.size(), 20u);
    EXPECT_EQ(total_queries(), 3);  // root, test., example.test: once each

    int coalesced = 0;
    for (size_t i = 0; i < outcomes.size(); ++i) {  // first asker first, then in order
        ASSERT_TRUE(outcomes[i].has_value()) << i;
        EXPECT_EQ(a_records(outcomes[i]), (std::vector<std::string>{"192.0.2.1"}));
        EXPECT_EQ(outcomes[i]->response.questions.at(0).qname.original_case,
                  name(spellings[i % 2]).original_case);  // each gets its own question back
        EXPECT_EQ(outcomes[i]->upstream_queries_used, outcomes[i]->coalesced ? 0u : 3u);
        coalesced += outcomes[i]->coalesced;
    }
    EXPECT_FALSE(outcomes[0]->coalesced);
    EXPECT_EQ(coalesced, 19);
}

TEST_F(ResolverTest, DifferentTypesAreNotCoalesced) {
    std::vector<Outcome> outcomes;
    for (RRType type : {RRType::A, RRType::AAAA}) {
        resolver().resolve({name("www.example.test"), static_cast<uint16_t>(type), 1}, [&](Outcome o) {
            outcomes.push_back(std::move(o));
            if (outcomes.size() == 2) loop->stop();
        });
    }
    run_for(5s);
    ASSERT_EQ(outcomes.size(), 2u);
    for (const auto& o : outcomes) {
        ASSERT_TRUE(o.has_value());
        EXPECT_FALSE(o->coalesced);
    }
    EXPECT_EQ(ex1->queries + ex2->queries, 2);
}

TEST_F(ResolverTest, JoinersShareAFailureAndLaterQueriesStartAfresh) {
    config.query_timeout_ms     = 50;
    config.max_query_timeout_ms = 200;
    ex1->tamper = ex2->tamper = drop_everything;
    std::vector<Outcome> outcomes;
    for (int i = 0; i < 5; ++i) {
        resolver().resolve({name("www.example.test"), 1, 1}, [&](Outcome o) {
            outcomes.push_back(std::move(o));
            if (outcomes.size() == 5) loop->stop();
        });
    }
    run_for(5s);
    ASSERT_EQ(outcomes.size(), 5u);
    for (const auto& o : outcomes) {
        ASSERT_FALSE(o.has_value());
        EXPECT_EQ(o.error(), ResolveError::AllServersFailed);
    }
    EXPECT_EQ(ex1->queries + ex2->queries, 6);  // one resolution: each server, three rounds

    // Failures aren't cached: a query after it ended starts a new resolution.
    EXPECT_FALSE(resolve("www.example.test", RRType::A).has_value());
    EXPECT_EQ(ex1->queries + ex2->queries, 12);
}

TEST_F(ResolverTest, JoinersAreCalledBackEvenIfAnEarlierCallbackDestroysTheResolver) {
    int called = 0;
    for (int i = 0; i < 3; ++i) {
        resolver().resolve({name("www.example.test"), 1, 1}, [&](Outcome o) {
            EXPECT_TRUE(o.has_value());
            if (++called == 1) destroy_resolver();
            if (called == 3) loop->stop();
        });
    }
    run_for(5s);
    EXPECT_EQ(called, 3);
}

// ─── API guarantees ─────────────────────────────────────────────────────────

TEST_F(ResolverTest, CallbackNeverRunsInsideResolve) {
    ASSERT_TRUE(resolve("www.example.test", RRType::A).has_value());  // now cached
    bool returned = false, called = false;
    resolver().resolve({name("www.example.test"), 1, 1}, [&](Outcome o) {
        EXPECT_TRUE(returned);
        EXPECT_TRUE(o.has_value());
        called = true;
        loop->stop();
    });
    returned = true;
    run_for(2s);
    EXPECT_TRUE(called);
}

TEST_F(ResolverTest, DestroyingTheResolverDropsPendingCallbacks) {
    ex1->delay = ex2->delay = 200ms;
    int called = 0;
    for (int i = 0; i < 3; ++i) {  // one resolution and two clients joined to it
        resolver().resolve({name("www.example.test"), 1, 1}, [&](Outcome) { ++called; });
    }
    run_for(50ms);  // root and test. answered; waiting on example.test
    destroy_resolver();
    run_for(400ms);
    EXPECT_EQ(called, 0);
}

TEST_F(ResolverTest, PrimingCachesTheRootNameServers) {
    std::optional<std::expected<void, ResolveError>> primed;
    resolver().prime_root([&](std::expected<void, ResolveError> r) {
        primed = r;
        loop->stop();
    });
    run_for(2s);
    ASSERT_TRUE(primed.has_value());
    ASSERT_TRUE(primed->has_value());

    auto ns = cache.lookup({Name{}, 2, 1});
    ASSERT_TRUE(ns.entry.has_value());
    EXPECT_EQ(ns.entry->trust, TrustRank::Answer);
    EXPECT_TRUE(cache.lookup({name("a.root-servers.lab"), 1, 1}).entry.has_value());  // glue
    EXPECT_TRUE(resolve("www.example.test", RRType::A).has_value());
}

TEST(ResolveError, StringsAreDistinct) {
    std::set<std::string> seen;
    for (int e = 0; e <= static_cast<int>(ResolveError::NetworkError); ++e) {
        seen.insert(resolve_error_to_string(static_cast<ResolveError>(e)));
    }
    EXPECT_EQ(seen.size(), static_cast<size_t>(ResolveError::NetworkError) + 1);
}
