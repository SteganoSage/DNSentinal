#include "dnsentinel/security/rrl.h"

#include "../wire/wire_test_util.h"

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <chrono>
#include <string>
#include <vector>

using namespace dnsentinel;
using namespace dnsentinel::security;
using namespace dnsentinel::test;
using namespace std::chrono_literals;

namespace {

using Clock = ResponseRateLimiter::Clock;
const Clock::time_point t0 = Clock::time_point{} + 1h;

sockaddr_storage client(const char* ip) {
    sockaddr_storage addr{};
    auto* v4 = reinterpret_cast<sockaddr_in*>(&addr);
    auto* v6 = reinterpret_cast<sockaddr_in6*>(&addr);
    if (inet_pton(AF_INET, ip, &v4->sin_addr) == 1) {
        v4->sin_family = AF_INET;
    } else {
        addr = {};
        EXPECT_EQ(inet_pton(AF_INET6, ip, &v6->sin6_addr), 1) << ip;
        v6->sin6_family = AF_INET6;
    }
    return addr;
}

Message response(std::string_view qname, uint16_t qtype = 1, RCode rcode = RCode::NoError) {
    Message r;
    r.header.id    = 0x1234;
    r.header.qr    = true;
    r.header.rcode = static_cast<uint8_t>(rcode);
    r.questions.push_back({name(qname), qtype, 1});
    if (rcode == RCode::NoError && qtype == 1) r.answers.push_back(make_rr(qname, RRType::A, ipv4("192.0.2.1")));
    return r;
}

/// A negative answer with the zone's SOA, as resolvers send them.
Message negative(std::string_view qname, std::string_view zone) {
    Message r = response(qname, 1, RCode::NXDomain);
    r.authority.push_back(make_rr(zone, RRType::SOA, RDataSOA{name("ns.test"), name("h.test"), 1, 1, 1, 1, 60}));
    return r;
}

std::string verdicts(ResponseRateLimiter& rrl, const char* ip, const Message& r, int count, Clock::time_point when) {
    std::string out;
    for (int i = 0; i < count; ++i) {
        switch (rrl.check(client(ip), r, when)) {
        case RrlVerdict::Send: out += 'S'; break;
        case RrlVerdict::Drop: out += 'D'; break;
        case RrlVerdict::Slip: out += 'T'; break;  // sent truncated
        }
    }
    return out;
}

}  // namespace

TEST(Rrl, ResponsesOverTheCapAreDroppedOrSlipped) {
    ResponseRateLimiter rrl({.responses_per_second = 3, .slip = 2});
    EXPECT_EQ(verdicts(rrl, "198.51.100.7", response("www.example.test"), 9, t0), "SSSDTDTDT");
    EXPECT_EQ(rrl.dropped(), 3u);
    EXPECT_EQ(rrl.slipped(), 3u);
}

TEST(Rrl, SlipZeroDropsEverythingAndOneTruncatesEverything) {
    ResponseRateLimiter none({.responses_per_second = 1, .slip = 0});
    EXPECT_EQ(verdicts(none, "198.51.100.7", response("a.test"), 4, t0), "SDDD");
    ResponseRateLimiter all({.responses_per_second = 1, .slip = 1});
    EXPECT_EQ(verdicts(all, "198.51.100.7", response("a.test"), 4, t0), "STTT");
}

TEST(Rrl, CountsStartAgainEachWindow) {
    ResponseRateLimiter rrl({.responses_per_second = 2, .slip = 0});
    EXPECT_EQ(verdicts(rrl, "198.51.100.7", response("a.test"), 3, t0), "SSD");
    EXPECT_EQ(verdicts(rrl, "198.51.100.7", response("a.test"), 1, t0 + 999ms), "D");
    EXPECT_EQ(verdicts(rrl, "198.51.100.7", response("a.test"), 3, t0 + 1s), "SSD");

    ResponseRateLimiter two_seconds({.responses_per_second = 2, .window_seconds = 2, .slip = 0});
    EXPECT_EQ(verdicts(two_seconds, "198.51.100.7", response("a.test"), 5, t0), "SSSSD");  // 2/s over 2 s
}

TEST(Rrl, OnlyIdenticalResponsesAreCountedTogether) {
    ResponseRateLimiter rrl({.responses_per_second = 1, .slip = 0});
    const char* ip = "198.51.100.7";
    EXPECT_EQ(verdicts(rrl, ip, response("a.test"), 2, t0), "SD");
    EXPECT_EQ(verdicts(rrl, ip, response("b.test"), 1, t0), "S");                        // another name
    EXPECT_EQ(verdicts(rrl, ip, response("a.test", 28), 1, t0), "S");                    // another type
    EXPECT_EQ(verdicts(rrl, ip, response("a.test", 1, RCode::ServFail), 1, t0), "S");    // another rcode
    EXPECT_EQ(verdicts(rrl, ip, response("A.TEST"), 1, t0), "D");                        // case doesn't matter
}

TEST(Rrl, ClientsInOneNetworkShareTheCount) {
    ResponseRateLimiter rrl({.responses_per_second = 1, .slip = 0});
    const Message r = response("a.test");
    EXPECT_EQ(verdicts(rrl, "198.51.100.7", r, 1, t0), "S");
    EXPECT_EQ(verdicts(rrl, "198.51.100.200", r, 1, t0), "D");          // same /24
    EXPECT_EQ(verdicts(rrl, "::ffff:198.51.100.9", r, 1, t0), "D");     // same /24, IPv4-mapped
    EXPECT_EQ(verdicts(rrl, "198.51.101.7", r, 1, t0), "S");            // the next /24
    EXPECT_EQ(verdicts(rrl, "2001:db8:0:ff::1", r, 1, t0), "S");
    EXPECT_EQ(verdicts(rrl, "2001:db8:0:aa::2", r, 1, t0), "D");        // same /56
    EXPECT_EQ(verdicts(rrl, "2001:db8:0:100::1", r, 1, t0), "S");       // the next /56

    ResponseRateLimiter per_host({.responses_per_second = 1, .slip = 0, .ipv4_prefix = 32});
    EXPECT_EQ(verdicts(per_host, "198.51.100.7", r, 1, t0), "S");
    EXPECT_EQ(verdicts(per_host, "198.51.100.8", r, 1, t0), "S");
}

TEST(Rrl, NegativeAnswersAreCountedPerZone) {
    // Random names under one zone, as in a random-subdomain flood.
    ResponseRateLimiter rrl({.responses_per_second = 2, .slip = 0});
    std::string out;
    for (int i = 0; i < 5; ++i) {
        out += verdicts(rrl, "198.51.100.7", negative("r" + std::to_string(i) + ".example.test", "example.test"), 1, t0);
    }
    EXPECT_EQ(out, "SSDDD");

    // Without an SOA there's no zone to go by: each name counts alone.
    EXPECT_EQ(verdicts(rrl, "198.51.100.7", response("x1.test", 1, RCode::NXDomain), 1, t0), "S");
    EXPECT_EQ(verdicts(rrl, "198.51.100.7", response("x2.test", 1, RCode::NXDomain), 1, t0), "S");
}

TEST(Rrl, OffExemptAndNonIpClientsAreNeverLimited) {
    ResponseRateLimiter off({.responses_per_second = 0});
    EXPECT_FALSE(off.enabled());
    EXPECT_EQ(verdicts(off, "198.51.100.7", response("a.test"), 50, t0), std::string(50, 'S'));

    ResponseRateLimiter rrl({.responses_per_second = 1, .slip = 0, .exempt = {*policy::parse_subnet("10.0.0.0/8")}});
    EXPECT_EQ(verdicts(rrl, "10.1.2.3", response("a.test"), 5, t0), "SSSSS");
    sockaddr_storage unknown{};
    EXPECT_EQ(rrl.check(unknown, response("a.test"), t0), RrlVerdict::Send);
    EXPECT_EQ(rrl.check(unknown, response("a.test"), t0), RrlVerdict::Send);
}

TEST(Rrl, AFullTableSharesOneCountForNewFingerprints) {
    ResponseRateLimiter rrl({.responses_per_second = 2, .slip = 0, .max_entries = 2});
    EXPECT_EQ(verdicts(rrl, "198.51.100.7", response("a.test"), 1, t0), "S");
    EXPECT_EQ(verdicts(rrl, "198.51.100.7", response("b.test"), 1, t0), "S");
    std::string out;
    for (const char* n : {"c.test", "d.test", "e.test"}) out += verdicts(rrl, "198.51.100.7", response(n), 1, t0);
    EXPECT_EQ(out, "SSD");  // c, d and e share one count
    EXPECT_EQ(rrl.tracked(), 2u);

    EXPECT_EQ(verdicts(rrl, "198.51.100.7", response("f.test"), 1, t0 + 5s), "S");  // expired ones forgotten
    EXPECT_EQ(rrl.tracked(), 1u);
}

TEST(Rrl, TruncatedKeepsTheHeaderAndQuestionOnly) {
    Message r = negative("x.example.test", "example.test");
    r.answers.push_back(make_rr("x.example.test", RRType::A, ipv4("192.0.2.1")));
    r.additional.push_back(make_rr("ns.test", RRType::A, ipv4("192.0.2.53")));
    r.edns = EdnsInfo{.udp_payload_size = 1232};

    const Message t = truncated(r);
    EXPECT_TRUE(t.header.tc);
    EXPECT_EQ(t.header.id, r.header.id);
    EXPECT_EQ(t.header.rcode, r.header.rcode);
    EXPECT_EQ(t.questions, r.questions);
    EXPECT_TRUE(t.answers.empty());
    EXPECT_TRUE(t.authority.empty());
    EXPECT_TRUE(t.additional.empty());
    EXPECT_EQ(t.edns, r.edns);
}
