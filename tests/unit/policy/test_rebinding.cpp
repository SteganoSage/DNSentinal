#include "dnsentinel/policy/rebinding.h"

#include "../wire/wire_test_util.h"

#include <gtest/gtest.h>

#include <string>
#include <vector>

using namespace dnsentinel;
using namespace dnsentinel::policy;
using namespace dnsentinel::test;

namespace {

RR a(std::string_view owner, const char* address) { return make_rr(owner, RRType::A, ipv4(address)); }
RR aaaa(std::string_view owner, const char* address) { return make_rr(owner, RRType::AAAA, ipv6(address)); }
RR cname(std::string_view owner, std::string_view target) { return make_rr(owner, RRType::CNAME, RDataCNAME{name(target)}); }

bool private_v4(const char* address) { return is_private_address(ipv4(address)); }
bool private_v6(const char* address) { return is_private_address(ipv6(address)); }

}  // namespace

// ─── Address ranges ─────────────────────────────────────────────────────────

TEST(Rebinding, Ipv4PrivateAndSpecialRanges) {
    // Each range, its first and last address, and the addresses just outside it.
    for (const char* inside : {"0.0.0.0", "0.255.255.255", "10.0.0.0", "10.255.255.255", "100.64.0.0",
                               "100.127.255.255", "127.0.0.1", "127.255.255.255", "169.254.0.1", "169.254.255.255",
                               "172.16.0.0", "172.31.255.255", "192.168.0.0", "192.168.255.255"}) {
        EXPECT_TRUE(private_v4(inside)) << inside;
    }
    for (const char* outside : {"1.0.0.0", "9.255.255.255", "11.0.0.0", "100.63.255.255", "100.128.0.0",
                                "126.255.255.255", "128.0.0.0", "169.253.255.255", "169.255.0.0", "172.15.255.255",
                                "172.32.0.0", "192.167.255.255", "192.169.0.0", "8.8.8.8", "192.0.2.1"}) {
        EXPECT_FALSE(private_v4(outside)) << outside;
    }
}

TEST(Rebinding, Ipv6PrivateAndSpecialRanges) {
    for (const char* inside : {"::", "::1", "fc00::", "fd12:3456::1", "fdff:ffff::1", "fe80::1", "febf:ffff::1",
                               "::ffff:192.168.1.1", "::ffff:127.0.0.1", "::ffff:10.0.0.1"}) {
        EXPECT_TRUE(private_v6(inside)) << inside;
    }
    for (const char* outside : {"::2", "fbff:ffff::1", "fe00::1", "fec0::1", "2001:db8::1", "2606:4700::1111",
                                "::ffff:8.8.8.8"}) {
        EXPECT_FALSE(private_v6(outside)) << outside;
    }
}

TEST(Rebinding, OnlyAddressRecordsHaveAddresses) {
    EXPECT_FALSE(is_private_address(RDataCNAME{name("router.home")}));
    EXPECT_FALSE(is_private_address(RDataTXT{{"192.168.1.1"}}));
}

// ─── Stripping answers ──────────────────────────────────────────────────────

TEST(Rebinding, StripsPrivateAddressesFromPublicNames) {
    const RebindingFilter filter{RebindingConfig{}};
    std::vector<RR> answers = {a("evil.test", "203.0.113.5"), a("evil.test", "192.168.1.1"),
                               aaaa("evil.test", "2001:db8::5"), aaaa("evil.test", "fd00::1")};
    const auto removed = filter.strip(name("evil.test"), answers);
    EXPECT_EQ(removed, (std::vector<RR>{a("evil.test", "192.168.1.1"), aaaa("evil.test", "fd00::1")}));
    EXPECT_EQ(answers, (std::vector<RR>{a("evil.test", "203.0.113.5"), aaaa("evil.test", "2001:db8::5")}));

    // What's left keeps the server's order (it can matter for load spreading).
    answers = {a("evil.test", "10.0.0.1"), a("evil.test", "203.0.113.1"), a("evil.test", "203.0.113.2"),
               a("evil.test", "203.0.113.3")};
    EXPECT_EQ(filter.strip(name("evil.test"), answers).size(), 1u);
    EXPECT_EQ(answers, (std::vector<RR>{a("evil.test", "203.0.113.1"), a("evil.test", "203.0.113.2"),
                                        a("evil.test", "203.0.113.3")}));
}

TEST(Rebinding, LeavesEverythingElseAlone) {
    const RebindingFilter filter{RebindingConfig{}};
    std::vector<RR> answers = {cname("www.shop.test", "edge.cdn.test"), a("edge.cdn.test", "10.1.2.3")};
    EXPECT_EQ(filter.strip(name("www.shop.test"), answers).size(), 1u);
    EXPECT_EQ(answers, (std::vector<RR>{cname("www.shop.test", "edge.cdn.test")}));

    std::vector<RR> clean = {a("www.shop.test", "203.0.113.5")};
    EXPECT_TRUE(filter.strip(name("www.shop.test"), clean).empty());
    EXPECT_EQ(clean.size(), 1u);
}

TEST(Rebinding, ExemptNamesKeepPrivateAddresses) {
    const RebindingFilter filter{RebindingConfig{}};
    for (const char* local : {"nas.home", "router.lan", "printer.local", "x.home.arpa", "db.internal", "localhost",
                              "home"}) {
        std::vector<RR> answers = {a(local, "192.168.1.10")};
        EXPECT_TRUE(filter.strip(name(local), answers).empty()) << local;
        EXPECT_EQ(answers.size(), 1u) << local;
        EXPECT_TRUE(filter.exempt(name(local))) << local;
    }
    // Whole labels only: these are public names.
    for (const char* outside : {"home.example.com", "myhome", "lan.party.test", "arpa"}) {
        EXPECT_FALSE(filter.exempt(name(outside))) << outside;
    }
}

TEST(Rebinding, OnlyTheQueryNameDecides) {
    const RebindingFilter filter{RebindingConfig{}};
    // A public name aliasing a local one is still a public name to the browser.
    std::vector<RR> attack = {cname("evil.test", "router.home"), a("router.home", "192.168.1.1")};
    EXPECT_EQ(filter.strip(name("evil.test"), attack).size(), 1u);

    // A local name may alias anything.
    std::vector<RR> local = {cname("nas.home", "nas.ddns.example"), a("nas.ddns.example", "192.168.1.5")};
    EXPECT_TRUE(filter.strip(name("nas.home"), local).empty());
}

TEST(Rebinding, CanBeTurnedOff) {
    const RebindingFilter filter{RebindingConfig{.enabled = false}};
    std::vector<RR> answers = {a("evil.test", "192.168.1.1")};
    EXPECT_TRUE(filter.strip(name("evil.test"), answers).empty());
    EXPECT_EQ(answers.size(), 1u);
}

TEST(Rebinding, ExemptListReplacesTheDefaults) {
    const RebindingFilter filter{RebindingConfig{.exempt = {name("plex.direct")}}};
    EXPECT_TRUE(filter.exempt(name("192-168-1-5.abc.plex.direct")));
    std::vector<RR> answers = {a("nas.home", "192.168.1.10")};
    EXPECT_EQ(filter.strip(name("nas.home"), answers).size(), 1u);  // no longer exempt
}
