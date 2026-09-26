#include "dnsentinel/types.h"

#include <gtest/gtest.h>

using namespace dnsentinel;

namespace {

RR make_a(const char* name, uint32_t addr, TrustRank trust = TrustRank::Answer) {
    RR rr;
    rr.name  = Name::from_string(name).value();
    rr.type  = RRType::A;
    rr.ttl   = 300;
    rr.rdata = RDataA{addr};
    rr.trust = trust;
    return rr;
}

}  // namespace

TEST(Types, RDataDefaultsAreZeroed) {
    RDataA a;
    RDataAAAA aaaa;
    RDataSOA soa;
    EXPECT_EQ(a.addr, 0u);
    EXPECT_EQ(aaaa, RDataAAAA{});
    EXPECT_EQ(soa.minimum, 0u);
}

TEST(Types, RREqualityIgnoresTrustRank) {
    EXPECT_EQ(make_a("example.com", 0x01020304, TrustRank::Answer),
              make_a("example.com", 0x01020304, TrustRank::Additional));
}

TEST(Types, RREqualityComparesRData) {
    RR a = make_a("example.com", 0x01020304);
    EXPECT_NE(a, make_a("example.com", 0x01020305));

    RR cname = a;
    cname.type  = RRType::CNAME;
    cname.rdata = RDataCNAME{Name::from_string("example.com").value()};
    EXPECT_NE(a, cname);
}

TEST(Types, AAAAEqualityComparesAllBytes) {
    RDataAAAA x{}, y{};
    x.addr[15] = 1;
    EXPECT_NE(x, y);
    y.addr[15] = 1;
    EXPECT_EQ(x, y);
}

TEST(Types, MessageEquality) {
    Message m1;
    m1.header.id = 0x1234;
    m1.questions.push_back({Name::from_string("example.com").value(), 1, 1});
    m1.answers.push_back(make_a("example.com", 0x01020304));
    m1.edns = EdnsInfo{.udp_payload_size = 1232};

    Message m2 = m1;
    EXPECT_EQ(m1, m2);

    m2.header.id = 0x1235;
    EXPECT_NE(m1, m2);

    m2 = m1;
    m2.edns.reset();
    EXPECT_NE(m1, m2);
}
