#include "dnsentinel/policy/cname_check.h"

#include "../wire/wire_test_util.h"

#include <gtest/gtest.h>

#include <string>
#include <vector>

using namespace dnsentinel;
using namespace dnsentinel::policy;
using namespace dnsentinel::test;

namespace {

RR cname(std::string_view owner, std::string_view target) { return make_rr(owner, RRType::CNAME, RDataCNAME{name(target)}); }
RR a(std::string_view owner) { return make_rr(owner, RRType::A, ipv4("192.0.2.1")); }

std::vector<std::string> names(const std::vector<Name>& chain) {
    std::vector<std::string> out;
    for (const auto& n : chain) out.push_back(n.to_string());
    return out;
}

using Strings = std::vector<std::string>;

/// A trie blocking `blocked` and allowing `allowed`, all covering subdomains.
BlocklistTrie lists(std::initializer_list<const char*> blocked, std::initializer_list<const char*> allowed = {}) {
    BlocklistTrie::Builder builder;
    for (const char* d : blocked) builder.add(name(d), ListAction::Block, "trackers.txt");
    for (const char* d : allowed) builder.add(name(d), ListAction::Allow, "allow.txt");
    return builder.build();
}

}  // namespace

// ─── Following the chain ────────────────────────────────────────────────────

TEST(CnameCheck, FollowsTheChainFromTheQueryName) {
    const std::vector<RR> answers = {cname("metrics.shop.test", "edge.cdn.test"),
                                     cname("edge.cdn.test", "collect.tracker.test"), a("collect.tracker.test")};
    EXPECT_EQ(names(cname_chain(name("metrics.shop.test"), answers)),
              (Strings{"edge.cdn.test.", "collect.tracker.test."}));
    EXPECT_TRUE(cname_chain(name("www.shop.test"), {a("www.shop.test")}).empty());
    EXPECT_TRUE(cname_chain(name("www.shop.test"), {}).empty());
}

TEST(CnameCheck, RecordOrderAndCaseDoNotMatter) {
    const std::vector<RR> answers = {a("C.test"), cname("B.TEST", "c.test"), cname("a.test", "b.test")};
    EXPECT_EQ(names(cname_chain(name("A.Test"), answers)), (Strings{"b.test.", "c.test."}));
}

TEST(CnameCheck, IgnoresRecordsOffTheChain) {
    const std::vector<RR> answers = {cname("other.test", "tracker.test"), cname("a.test", "b.test"), a("b.test")};
    EXPECT_EQ(names(cname_chain(name("a.test"), answers)), (Strings{"b.test."}));
}

TEST(CnameCheck, ALoopEndsTheChain) {
    EXPECT_EQ(names(cname_chain(name("a.test"), {cname("a.test", "b.test"), cname("b.test", "a.test")})),
              (Strings{"b.test."}));
    EXPECT_EQ(names(cname_chain(name("a.test"), {cname("a.test", "b.test"), cname("b.test", "c.test"),
                                                 cname("c.test", "b.test")})),
              (Strings{"b.test.", "c.test."}));
    EXPECT_TRUE(cname_chain(name("a.test"), {cname("a.test", "a.test")}).empty());
}

TEST(CnameCheck, SkipsCnameRecordsItCannotRead) {
    RR broken = cname("a.test", "b.test");
    broken.rdata = RDataRaw{{1, 2, 3}};
    EXPECT_TRUE(cname_chain(name("a.test"), {broken}).empty());
}

// ─── Checking each hop ──────────────────────────────────────────────────────

TEST(CnameCheck, FindsACloakedTracker) {
    const auto            trie    = lists({"tracker.test"});
    const std::vector<RR> answers = {cname("metrics.shop.test", "collect.tracker.test"), a("collect.tracker.test")};
    auto cloaked = find_cloaked(name("metrics.shop.test"), answers, trie);
    ASSERT_TRUE(cloaked.has_value());
    EXPECT_EQ(names(cloaked->chain), (Strings{"metrics.shop.test.", "collect.tracker.test."}));
    EXPECT_EQ(cloaked->match.rule, "tracker.test.");  // the registrable domain's rule covers the hop
    EXPECT_EQ(cloaked->match.source, "trackers.txt");
}

TEST(CnameCheck, ReportsTheFirstBlockedHop) {
    const auto            trie    = lists({"middle.test", "end.test"});
    const std::vector<RR> answers = {cname("a.test", "x.middle.test"), cname("x.middle.test", "y.end.test"),
                                     a("y.end.test")};
    auto cloaked = find_cloaked(name("a.test"), answers, trie);
    ASSERT_TRUE(cloaked.has_value());
    EXPECT_EQ(names(cloaked->chain), (Strings{"a.test.", "x.middle.test."}));
    EXPECT_EQ(cloaked->match.rule, "middle.test.");
}

TEST(CnameCheck, AnAllowedHopDoesNotVouchForTheNextOne) {
    const auto            trie    = lists({"tracker.test"}, {"cdn.test"});
    const std::vector<RR> answers = {cname("a.test", "edge.cdn.test"), cname("edge.cdn.test", "t.tracker.test"),
                                     a("t.tracker.test")};
    auto cloaked = find_cloaked(name("a.test"), answers, trie);
    ASSERT_TRUE(cloaked.has_value());
    EXPECT_EQ(cloaked->chain.back(), name("t.tracker.test"));

    // An allowed hop on its own blocks nothing.
    EXPECT_FALSE(find_cloaked(name("a.test"), {cname("a.test", "edge.cdn.test"), a("edge.cdn.test")}, trie));
}

TEST(CnameCheck, CleanChainsAndPlainAnswersPass) {
    const auto trie = lists({"tracker.test"});
    EXPECT_FALSE(find_cloaked(name("www.shop.test"), {cname("www.shop.test", "shop.cdn.test"), a("shop.cdn.test")}, trie));
    EXPECT_FALSE(find_cloaked(name("www.shop.test"), {a("www.shop.test")}, trie));
    EXPECT_FALSE(find_cloaked(name("www.shop.test"), {}, trie));
    // Only the chain counts: a blocked name elsewhere in the answer is not a hop.
    EXPECT_FALSE(find_cloaked(name("www.shop.test"), {a("www.shop.test"), cname("x.test", "t.tracker.test")}, trie));
    // The query name itself is checked before resolution, not here.
    EXPECT_FALSE(find_cloaked(name("t.tracker.test"), {a("t.tracker.test")}, trie));
}
