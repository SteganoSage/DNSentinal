#include "dnsentinel/policy/dynamic_rules.h"

#include "../wire/wire_test_util.h"

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <netinet/in.h>

using namespace dnsentinel;
using namespace dnsentinel::policy;
using namespace dnsentinel::test;
using namespace std::chrono_literals;

namespace {

sockaddr_storage at(const char* ip) {
    sockaddr_storage address{};
    auto*            v4 = reinterpret_cast<sockaddr_in*>(&address);
    v4->sin_family      = AF_INET;
    inet_pton(AF_INET, ip, &v4->sin_addr);
    return address;
}

const auto kNow = DynamicRules::Clock::now();

}  // namespace

TEST(DynamicRules, CoverTheNameAndEverythingBelowIt) {
    DynamicRules rules;
    ASSERT_TRUE(rules.add(name("tunnel.example"), std::nullopt, 60, "tunnel", 0.97, "analyzer", kNow));
    EXPECT_NE(rules.match(name("tunnel.example"), at("10.0.0.1"), kNow), nullptr);
    EXPECT_NE(rules.match(name("aGVsbG8.x.TUNNEL.example"), at("10.0.0.2"), kNow), nullptr);
    EXPECT_EQ(rules.match(name("example"), at("10.0.0.1"), kNow), nullptr);
    EXPECT_EQ(rules.match(name("nottunnel.example"), at("10.0.0.1"), kNow), nullptr);
    EXPECT_EQ(rules.blocked(), 2u);
}

TEST(DynamicRules, ApplyOnlyToTheirClient) {
    DynamicRules rules;
    ASSERT_TRUE(rules.add(name("tunnel.example"), parse_subnet("192.168.1.23").value(), 60, "tunnel", 0.9, "", kNow));
    ASSERT_TRUE(rules.add(name("other.example"), parse_subnet("10.1.0.0/16").value(), 60, "", 0, "", kNow));
    EXPECT_NE(rules.match(name("a.tunnel.example"), at("192.168.1.23"), kNow), nullptr);
    EXPECT_EQ(rules.match(name("a.tunnel.example"), at("192.168.1.24"), kNow), nullptr);
    EXPECT_NE(rules.match(name("other.example"), at("10.1.200.3"), kNow), nullptr);
    EXPECT_EQ(rules.match(name("other.example"), at("10.2.0.1"), kNow), nullptr);
}

TEST(DynamicRules, ExpireOnTheirOwn) {
    DynamicRules rules;
    ASSERT_TRUE(rules.add(name("tunnel.example"), std::nullopt, 60, "", 0, "", kNow));
    EXPECT_NE(rules.match(name("tunnel.example"), at("10.0.0.1"), kNow + 59s), nullptr);
    EXPECT_EQ(rules.match(name("tunnel.example"), at("10.0.0.1"), kNow + 60s), nullptr);  // before expire() too
    EXPECT_EQ(rules.active(kNow + 61s).size(), 0u);
    auto gone = rules.expire(kNow + 61s);
    ASSERT_EQ(gone.size(), 1u);
    EXPECT_EQ(gone[0].hits, 1u);
    EXPECT_EQ(rules.size(), 0u);
}

TEST(DynamicRules, AddingTheSameRuleRenewsIt) {
    DynamicRules rules;
    auto first = rules.add(name("tunnel.example"), std::nullopt, 60, "tunnel", 0.8, "a", kNow);
    ASSERT_TRUE(first);
    const uint64_t id = (*first)->id;
    auto again = rules.add(name("Tunnel.Example."), std::nullopt, 600, "tunnel", 0.99, "b", kNow + 30s);
    ASSERT_TRUE(again);
    EXPECT_EQ((*again)->id, id);
    EXPECT_EQ((*again)->expires, kNow + 630s);
    EXPECT_DOUBLE_EQ((*again)->score, 0.99);
    EXPECT_EQ(rules.size(), 1u);
    EXPECT_EQ(rules.added(), 1u);
    // the same domain for one client is another rule
    ASSERT_TRUE(rules.add(name("tunnel.example"), parse_subnet("10.0.0.1").value(), 60, "", 0, "", kNow));
    EXPECT_EQ(rules.size(), 2u);
}

TEST(DynamicRules, AreBounded) {
    DynamicRules rules({.max_rules = 2, .max_ttl = 100});
    auto capped = rules.add(name("a.example"), std::nullopt, 100000, "", 0, "", kNow);
    ASSERT_TRUE(capped);
    EXPECT_EQ((*capped)->expires, kNow + 100s);  // max_ttl
    ASSERT_TRUE(rules.add(name("b.example"), std::nullopt, 10, "", 0, "", kNow));
    auto full = rules.add(name("c.example"), std::nullopt, 10, "", 0, "", kNow);
    ASSERT_FALSE(full);
    EXPECT_NE(full.error().find("full"), std::string::npos);
    EXPECT_TRUE(rules.add(name("b.example"), std::nullopt, 20, "", 0, "", kNow));  // renewing still works
    EXPECT_FALSE(rules.add(name("d.example"), std::nullopt, 0, "", 0, "", kNow));  // no TTL
    EXPECT_FALSE(rules.add(Name{}, std::nullopt, 10, "", 0, "", kNow));             // not the whole namespace
}

TEST(DynamicRules, CanBeRemovedEarly) {
    DynamicRules rules;
    auto added = rules.add(name("tunnel.example"), std::nullopt, 60, "", 0, "", kNow);
    ASSERT_TRUE(added);
    const uint64_t id = (*added)->id;
    EXPECT_FALSE(rules.remove(id + 100));
    EXPECT_TRUE(rules.remove(id));
    EXPECT_EQ(rules.match(name("tunnel.example"), at("10.0.0.1"), kNow), nullptr);
    EXPECT_EQ(rules.size(), 0u);
}
