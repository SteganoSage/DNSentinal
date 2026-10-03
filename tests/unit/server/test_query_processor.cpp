#include "dnsentinel/server/query_processor.h"

#include "dnsentinel/cache/cache.h"
#include "dnsentinel/net/event_loop.h"
#include "dnsentinel/net/udp_listener.h"
#include "dnsentinel/resolver/recursive_resolver.h"
#include "dnsentinel/wire/builder.h"
#include "dnsentinel/wire/parser.h"
#include "../policy/list_file.h"
#include "../resolver/fake_auth.h"

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <functional>
#include <optional>
#include <random>
#include <span>
#include <string>

using namespace dnsentinel;
using namespace dnsentinel::policy;
using namespace dnsentinel::resolver;
using namespace dnsentinel::server;
using namespace dnsentinel::test;
using namespace std::chrono_literals;

namespace {

/// One fake server, authoritative for the whole namespace, as the only root.
class QueryProcessorTest : public ::testing::Test {
protected:
    void SetUp() override {
        std::random_device rd;
        const std::string ip = "127." + std::to_string(1 + rd() % 254) + "." + std::to_string(rd() % 255) + ".1";
        auth = std::make_unique<FakeAuth>(*loop, ip, 0, ".");
        auth->add("www.example.test", RRType::A, ipv4("192.0.2.1"));

        ResolverConfig config;
        config.upstream_port       = auth->port();
        config.query_timeout_ms    = 50;
        config.overall_deadline_ms = 500;
        RootHints hints;
        hints.ns.push_back(make_rr(".", RRType::NS, RDataNS{name("a.root.lab")}));
        hints.addresses.push_back(make_rr("a.root.lab", RRType::A, ipv4(ip.c_str())));
        resolver  = std::make_unique<RecursiveResolver>(config, hints, *loop, cache);
        processor = std::make_unique<QueryProcessor>(*resolver, AccessControl(AccessConfig{}), *lists);  // localhost only
    }

    /// Use these block and allow lists from now on.
    void use_lists(ListsConfig config) {
        processor.reset();  // it refers to the old lists
        lists = std::make_unique<Blocklists>(std::move(config));
        auto loaded = lists->load();
        ASSERT_TRUE(loaded.has_value()) << loaded.error();
        processor = std::make_unique<QueryProcessor>(*resolver, AccessControl(AccessConfig{}), *lists);
    }

    static Message query(std::string_view qname, uint16_t qtype = 1, uint16_t qclass = 1) {
        Message q;
        q.header.id = 0x4242;
        q.header.rd = true;
        q.questions.push_back({name(qname), qtype, qclass});
        return q;
    }

    void run_for(std::chrono::milliseconds limit) {
        auto guard = loop->add_timer(limit, [this] { loop->stop(); });
        loop->run();
        loop->cancel_timer(guard);
    }

    static net::ClientInfo client_at(const char* ip) {
        net::ClientInfo client;
        auto* v4       = reinterpret_cast<sockaddr_in*>(&client.addr);
        v4->sin_family = AF_INET;
        inet_pton(AF_INET, ip, &v4->sin_addr);
        return client;
    }

    std::optional<Message> ask(Message q, const char* from = "127.0.0.1") {
        std::optional<Message> out;
        int calls = 0;
        processor->handle(std::move(q), client_at(from), [&](const Message& r) {
            ++calls;
            out = r;
            loop->stop();  // if this runs inside handle(), run() below returns at once
        });
        run_for(2s);
        EXPECT_EQ(calls, 1);
        return out;
    }

    std::unique_ptr<net::EventLoop>    loop = net::EventLoop::create().value();
    std::unique_ptr<FakeAuth>          auth;
    cache::Cache                       cache{cache::CacheConfig{}};
    std::unique_ptr<RecursiveResolver> resolver;
    std::unique_ptr<Blocklists>        lists = std::make_unique<Blocklists>(ListsConfig{});
    std::unique_ptr<QueryProcessor>    processor;
};

}  // namespace

TEST_F(QueryProcessorTest, AnswersFromTheResolver) {
    const Message q = query("WWW.Example.TEST");
    auto r = ask(q);
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->header.id, 0x4242);
    EXPECT_TRUE(r->header.qr);
    EXPECT_TRUE(r->header.ra);
    EXPECT_TRUE(r->header.rd);
    EXPECT_FALSE(r->header.aa);  // we are not the authority
    EXPECT_EQ(r->header.rcode, 0);
    ASSERT_EQ(r->questions.size(), 1u);
    EXPECT_EQ(r->questions[0].qname.original_case, q.questions[0].qname.original_case);
    ASSERT_EQ(r->answers.size(), 1u);
    EXPECT_EQ(r->answers[0].rdata, RData{ipv4("192.0.2.1")});
}

TEST_F(QueryProcessorTest, NxdomainCarriesTheSoa) {
    auto r = ask(query("nope.example.test"));
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->header.rcode, static_cast<uint8_t>(RCode::NXDomain));
    EXPECT_TRUE(r->answers.empty());
    ASSERT_EQ(r->authority.size(), 1u);
    EXPECT_EQ(r->authority[0].type, RRType::SOA);
}

TEST_F(QueryProcessorTest, ResolutionFailureIsServfail) {
    auth->tamper = [](const Message&, Message&) { return false; };
    auto r = ask(query("www.example.test"));
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->header.rcode, static_cast<uint8_t>(RCode::ServFail));
    EXPECT_TRUE(r->answers.empty());
}

TEST_F(QueryProcessorTest, RejectsWhatItCannotResolve) {
    struct Case {
        const char*                  what;
        std::function<void(Message&)> edit;
        RCode                        expected;
    };
    const Case cases[] = {
        {"opcode STATUS", [](Message& q) { q.header.opcode = 2; }, RCode::NotImp},
        {"no question", [](Message& q) { q.questions.clear(); }, RCode::FormErr},
        {"two questions", [](Message& q) { q.questions.push_back(q.questions[0]); }, RCode::FormErr},
        {"class CH", [](Message& q) { q.questions[0].qclass = 3; }, RCode::Refused},
        {"AXFR", [](Message& q) { q.questions[0].qtype = 252; }, RCode::Refused},
        {"qtype OPT", [](Message& q) { q.questions[0].qtype = 41; }, RCode::FormErr},
        {"qtype TSIG", [](Message& q) { q.questions[0].qtype = 250; }, RCode::FormErr},
    };
    for (const auto& c : cases) {
        Message q = query("www.example.test");
        c.edit(q);
        auto r = ask(q);
        ASSERT_TRUE(r.has_value()) << c.what;
        EXPECT_EQ(r->header.rcode, static_cast<uint8_t>(c.expected)) << c.what;
        EXPECT_EQ(r->header.id, 0x4242) << c.what;
    }
    EXPECT_EQ(auth->queries, 0);  // none of them went upstream
}

TEST_F(QueryProcessorTest, UnknownEdnsVersionIsBadvers) {
    Message q = query("www.example.test");
    q.edns    = EdnsInfo{.version = 1};
    auto r = ask(q);
    ASSERT_TRUE(r.has_value());
    ASSERT_TRUE(r->edns.has_value());
    EXPECT_EQ(r->header.rcode, 0);          // BADVERS = 16: low bits 0,
    EXPECT_EQ(r->edns->extended_rcode, 1);  // high bits in the OPT
    EXPECT_EQ(auth->queries, 0);
}

TEST_F(QueryProcessorTest, ServesAClientOverUdp) {
    auto listener = net::UdpListener::create(
        *loop, {.address = "127.0.0.1", .port = 0},
        [this](Message q, const net::ClientInfo& c, net::Responder r) { processor->handle(std::move(q), c, std::move(r)); });
    ASSERT_TRUE(listener.has_value()) << listener.error().message();

    const int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    ASSERT_GE(fd, 0);
    std::optional<Message> reply;
    ASSERT_FALSE(loop->add_fd(fd, net::kReadable, [&](uint32_t) {
        uint8_t       buf[4096];
        const ssize_t n = recv(fd, buf, sizeof buf, 0);
        if (n > 0) {
            if (auto m = wire::parse(std::span<const uint8_t>(buf, static_cast<size_t>(n)))) reply = std::move(*m);
        }
        loop->stop();
    }));

    sockaddr_in to{};
    to.sin_family = AF_INET;
    to.sin_port   = htons((*listener)->port());
    inet_pton(AF_INET, "127.0.0.1", &to.sin_addr);
    const auto bytes = wire::build(query("www.example.test"));
    ASSERT_EQ(sendto(fd, bytes.data(), bytes.size(), 0, reinterpret_cast<const sockaddr*>(&to), sizeof to),
              static_cast<ssize_t>(bytes.size()));
    run_for(2s);
    loop->remove_fd(fd);
    close(fd);

    ASSERT_TRUE(reply.has_value());
    EXPECT_EQ(reply->header.id, 0x4242);
    EXPECT_EQ(reply->header.rcode, 0);
    ASSERT_EQ(reply->answers.size(), 1u);
    EXPECT_EQ(reply->answers[0].rdata, RData{ipv4("192.0.2.1")});
}

// ─── Access control (plan §5.5) ─────────────────────────────────────────────

TEST_F(QueryProcessorTest, ClientsOutsideTheAllowedSubnetsAreRefused) {
    auto r = ask(query("www.example.test"), "192.0.2.99");
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->header.rcode, static_cast<uint8_t>(RCode::Refused));
    EXPECT_EQ(r->header.id, 0x4242);
    EXPECT_TRUE(r->answers.empty());
    EXPECT_EQ(auth->queries, 0);  // never resolved: outsiders can't make us send anything upstream
}

TEST_F(QueryProcessorTest, ClientsOutsideCanBeIgnoredInstead) {
    processor = std::make_unique<QueryProcessor>(
        *resolver, AccessControl(AccessConfig{AccessConfig::localhost(), DenyAction::Drop}), *lists);
    int calls = 0;
    processor->handle(query("www.example.test"), client_at("192.0.2.99"), [&](const Message&) { ++calls; });
    run_for(100ms);
    EXPECT_EQ(calls, 0);
    EXPECT_EQ(auth->queries, 0);
}

TEST_F(QueryProcessorTest, AccessIsCheckedBeforeAnythingElse) {
    // An outsider learns nothing about what we'd do with its query: a status
    // query (NOTIMP for an allowed client) still just gets REFUSED.
    Message q         = query("www.example.test");
    q.header.opcode   = 2;
    auto r = ask(q, "192.0.2.99");
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->header.rcode, static_cast<uint8_t>(RCode::Refused));
}

// ─── Block and allow lists (plan §5.6) ──────────────────────────────────────

TEST_F(QueryProcessorTest, BlockedNamesGetAnAddressThatGoesNowhere) {
    const ListFile block("example.test\n");  // the whole zone
    use_lists({.blocklists = {block.path()}});

    const Message q = query("Ads.Example.TEST");
    auto r = ask(q);
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->header.id, 0x4242);
    EXPECT_TRUE(r->header.qr);
    EXPECT_TRUE(r->header.ra);
    EXPECT_EQ(r->header.rcode, 0);
    ASSERT_EQ(r->questions.size(), 1u);
    EXPECT_EQ(r->questions[0].qname.original_case, q.questions[0].qname.original_case);
    ASSERT_EQ(r->answers.size(), 1u);
    EXPECT_EQ(r->answers[0].name, name("ads.example.test"));
    EXPECT_EQ(r->answers[0].type, RRType::A);
    EXPECT_EQ(r->answers[0].ttl, 60u);
    EXPECT_EQ(r->answers[0].rdata, RData{ipv4("0.0.0.0")});

    r = ask(query("www.example.test", static_cast<uint16_t>(RRType::AAAA)));
    ASSERT_TRUE(r.has_value());
    ASSERT_EQ(r->answers.size(), 1u);
    EXPECT_EQ(r->answers[0].type, RRType::AAAA);
    EXPECT_EQ(r->answers[0].rdata, RData{ipv6("::")});

    r = ask(query("www.example.test", static_cast<uint16_t>(RRType::TXT)));  // nothing to point nowhere
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->header.rcode, 0);
    EXPECT_TRUE(r->answers.empty());

    EXPECT_EQ(auth->queries, 0);  // blocked names never go upstream
}

TEST_F(QueryProcessorTest, BlockedNamesCanGetNxdomainInstead) {
    const ListFile block("0.0.0.0 www.example.test\n");
    use_lists({.blocklists = {block.path()}, .response = BlockResponse::NxDomain, .block_ttl = 5});
    auto r = ask(query("www.example.test"));
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->header.rcode, static_cast<uint8_t>(RCode::NXDomain));
    EXPECT_TRUE(r->answers.empty());
    EXPECT_EQ(auth->queries, 0);
}

TEST_F(QueryProcessorTest, BlockTtlIsConfigurable) {
    const ListFile block("www.example.test\n");
    use_lists({.blocklists = {block.path()}, .block_ttl = 5});
    auto r = ask(query("www.example.test"));
    ASSERT_TRUE(r.has_value());
    ASSERT_EQ(r->answers.size(), 1u);
    EXPECT_EQ(r->answers[0].ttl, 5u);
}

TEST_F(QueryProcessorTest, AllowlistedNamesAreResolved) {
    const ListFile block("example.test\n");
    const ListFile allow("www.example.test\n");
    use_lists({.blocklists = {block.path()}, .allowlists = {allow.path()}});

    auto r = ask(query("www.example.test"));
    ASSERT_TRUE(r.has_value());
    ASSERT_EQ(r->answers.size(), 1u);
    EXPECT_EQ(r->answers[0].rdata, RData{ipv4("192.0.2.1")});  // the real answer
    EXPECT_GT(auth->queries, 0);

    r = ask(query("mail.example.test"));  // the rest of the zone is still blocked
    ASSERT_TRUE(r.has_value());
    ASSERT_EQ(r->answers.size(), 1u);
    EXPECT_EQ(r->answers[0].rdata, RData{ipv4("0.0.0.0")});
}

TEST_F(QueryProcessorTest, OutsidersAreRefusedEvenForBlockedNames) {
    const ListFile block("example.test\n");
    use_lists({.blocklists = {block.path()}});
    auto r = ask(query("www.example.test"), "192.0.2.99");
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->header.rcode, static_cast<uint8_t>(RCode::Refused));  // not 0.0.0.0
    EXPECT_TRUE(r->answers.empty());
}

// ─── CNAME cloaking (plan §5.7) ─────────────────────────────────────────────

namespace {

/// metrics.shop.test is a first-party alias of a tracker.
void add_cloaked_tracker(FakeAuth& auth) {
    auth.add("metrics.shop.test", RRType::CNAME, RDataCNAME{name("collect.tracker.test")});
    auth.add("collect.tracker.test", RRType::A, ipv4("192.0.2.66"));
}

}  // namespace

TEST_F(QueryProcessorTest, CnameCloakedTrackersAreBlocked) {
    add_cloaked_tracker(*auth);
    const ListFile block("tracker.test\n");
    use_lists({.blocklists = {block.path()}});
    std::vector<BlockEvent> events;
    processor->on_block([&](const BlockEvent& e) { events.push_back(e); });

    const Message q = query("Metrics.Shop.TEST");
    auto r = ask(q);
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->header.rcode, 0);
    EXPECT_EQ(r->questions[0].qname.original_case, q.questions[0].qname.original_case);
    ASSERT_EQ(r->answers.size(), 1u);  // no CNAME, nothing from the real answer
    EXPECT_EQ(r->answers[0].name, name("metrics.shop.test"));
    EXPECT_EQ(r->answers[0].rdata, RData{ipv4("0.0.0.0")});
    EXPECT_EQ(r->answers[0].ttl, 60u);
    EXPECT_GT(auth->queries, 0);  // it had to be resolved to be seen

    ASSERT_EQ(events.size(), 1u);
    EXPECT_TRUE(events[0].via_cname());
    EXPECT_EQ(events[0].chain, (std::vector<Name>{name("metrics.shop.test"), name("collect.tracker.test")}));
    EXPECT_EQ(events[0].blocked_name(), name("collect.tracker.test"));
    EXPECT_EQ(events[0].match.rule, "tracker.test.");
    EXPECT_EQ(events[0].match.source, block.path());

    // The tracker has no AAAA: the real answer is the CNAME plus the SOA.
    r = ask(query("metrics.shop.test", static_cast<uint16_t>(RRType::AAAA)));
    ASSERT_TRUE(r.has_value());
    ASSERT_EQ(r->answers.size(), 1u);
    EXPECT_EQ(r->answers[0].rdata, RData{ipv6("::")});
    EXPECT_TRUE(r->authority.empty());
}

TEST_F(QueryProcessorTest, CnameCloakedNamesGetNxdomainInNxdomainMode) {
    add_cloaked_tracker(*auth);
    const ListFile block("tracker.test\n");
    use_lists({.blocklists = {block.path()}, .response = BlockResponse::NxDomain});
    auto r = ask(query("metrics.shop.test"));
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->header.rcode, static_cast<uint8_t>(RCode::NXDomain));
    EXPECT_TRUE(r->answers.empty());
}

TEST_F(QueryProcessorTest, CnameCheckCanBeTurnedOff) {
    add_cloaked_tracker(*auth);
    const ListFile block("tracker.test\n");
    use_lists({.blocklists = {block.path()}, .check_cname_chain = false});  // name-only blocking (E12's baseline)
    int blocks = 0;
    processor->on_block([&](const BlockEvent&) { ++blocks; });

    auto r = ask(query("metrics.shop.test"));
    ASSERT_TRUE(r.has_value());
    ASSERT_EQ(r->answers.size(), 2u);
    EXPECT_EQ(r->answers[0].type, RRType::CNAME);
    EXPECT_EQ(r->answers[1].rdata, RData{ipv4("192.0.2.66")});  // the tracker slips through
    EXPECT_EQ(blocks, 0);
}

TEST_F(QueryProcessorTest, CnameCheckSparesAllowlistedNames) {
    add_cloaked_tracker(*auth);
    const ListFile block("tracker.test\n");
    const ListFile allow("metrics.shop.test\n");
    use_lists({.blocklists = {block.path()}, .allowlists = {allow.path()}});
    auto r = ask(query("metrics.shop.test"));
    ASSERT_TRUE(r.has_value());
    ASSERT_EQ(r->answers.size(), 2u);
    EXPECT_EQ(r->answers[1].rdata, RData{ipv4("192.0.2.66")});
}

TEST_F(QueryProcessorTest, CnameChainsToCleanNamesPass) {
    auth->add("alias.shop.test", RRType::CNAME, RDataCNAME{name("www.example.test")});
    const ListFile block("tracker.test\n");
    use_lists({.blocklists = {block.path()}});
    int blocks = 0;
    processor->on_block([&](const BlockEvent&) { ++blocks; });

    auto r = ask(query("alias.shop.test"));
    ASSERT_TRUE(r.has_value());
    ASSERT_EQ(r->answers.size(), 2u);
    EXPECT_EQ(r->answers[1].rdata, RData{ipv4("192.0.2.1")});
    EXPECT_EQ(blocks, 0);
}

TEST_F(QueryProcessorTest, CnameCheckAppliesToCachedAnswers) {
    // Resolved and cached while nothing was listed; then the lists change.
    add_cloaked_tracker(*auth);
    ASSERT_EQ(ask(query("metrics.shop.test"))->answers.size(), 2u);
    const int upstream = auth->queries;

    const ListFile block("tracker.test\n");
    use_lists({.blocklists = {block.path()}});
    auto r = ask(query("metrics.shop.test"));
    ASSERT_TRUE(r.has_value());
    ASSERT_EQ(r->answers.size(), 1u);
    EXPECT_EQ(r->answers[0].rdata, RData{ipv4("0.0.0.0")});
    EXPECT_EQ(auth->queries, upstream);  // answered from the cache, and still checked
}

TEST_F(QueryProcessorTest, CnameAndDirectBlocksAreReportedApart) {
    add_cloaked_tracker(*auth);
    const ListFile block("tracker.test\nwww.example.test\n");
    use_lists({.blocklists = {block.path()}});
    std::vector<BlockEvent> events;
    processor->on_block([&](const BlockEvent& e) { events.push_back(e); });

    const Message direct = query("WWW.example.test");
    ask(direct);
    ask(query("metrics.shop.test"));
    ASSERT_EQ(events.size(), 2u);
    EXPECT_FALSE(events[0].via_cname());
    EXPECT_EQ(events[0].blocked_name(), name("www.example.test"));
    EXPECT_EQ(events[0].question.qname.original_case, direct.questions[0].qname.original_case);
    EXPECT_EQ(events[0].match.rule, "www.example.test.");
    EXPECT_TRUE(events[1].via_cname());
}
