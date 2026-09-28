#include "dnsentinel/security/bailiwick.h"

#include "../wire/wire_test_util.h"

#include <gtest/gtest.h>

using namespace dnsentinel;
using namespace dnsentinel::security;
using namespace dnsentinel::test;

TEST(Bailiwick, DropsRecordsOutsideTheZone) {
    Message m;
    m.answers    = {make_rr("www.example.test", RRType::A, ipv4("192.0.2.1")),
                    make_rr("www.bank.net", RRType::A, ipv4("6.6.6.6"))};
    m.authority  = {make_rr("example.test", RRType::NS, RDataNS{name("ns1.example.test")}),
                    make_rr("bank.net", RRType::NS, RDataNS{name("ns.evil.lab")})};
    m.additional = {make_rr("ns1.example.test", RRType::A, ipv4("192.0.2.53")),
                    make_rr("ns.bank.net", RRType::A, ipv4("6.6.6.6")),
                    make_rr("notexample.test", RRType::A, ipv4("6.6.6.6"))};  // string suffix, not a subdomain

    EXPECT_EQ(filter_to_bailiwick(m, name("example.test")), 4u);
    for (const auto* section : {&m.answers, &m.authority, &m.additional}) {
        ASSERT_EQ(section->size(), 1u);
        EXPECT_TRUE(section->front().name.is_subdomain_of(name("example.test")));
    }
}

TEST(Bailiwick, RootServersMayTalkAboutAnything) {
    Message m;
    m.answers = {make_rr("www.bank.net", RRType::A, ipv4("192.0.2.1"))};
    EXPECT_EQ(filter_to_bailiwick(m, name(".")), 0u);
    EXPECT_EQ(m.answers.size(), 1u);
}

TEST(Bailiwick, NsTargetsMayPointAnywhere) {
    // Only the owner name is checked: a zone can use name servers elsewhere.
    Message m;
    m.authority = {make_rr("sub.example.test", RRType::NS, RDataNS{name("ns.dns-host.net")})};
    EXPECT_EQ(filter_to_bailiwick(m, name("example.test")), 0u);
}
