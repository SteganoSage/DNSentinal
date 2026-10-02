#include "dnsentinel/policy/blocklist_trie.h"

#include "../wire/wire_test_util.h"
#include "list_file.h"

#include <gtest/gtest.h>

#include <random>
#include <string>
#include <vector>

using namespace dnsentinel;
using namespace dnsentinel::policy;
using namespace dnsentinel::test;

namespace {

/// Build a trie from {domain, action} rules, all covering their subdomains.
BlocklistTrie trie_of(std::initializer_list<std::pair<const char*, ListAction>> rules,
                      std::string_view source = "test") {
    BlocklistTrie::Builder builder;
    for (const auto& [domain, action] : rules) builder.add(name(domain), action, source);
    return builder.build();
}

constexpr auto Block = ListAction::Block;
constexpr auto Allow = ListAction::Allow;

bool blocks(const BlocklistTrie& trie, const char* domain) {
    auto r = trie.lookup(name(domain));
    return r.matched && r.action == Block;
}

}  // namespace

// ─── Lookups ────────────────────────────────────────────────────────────────

TEST(BlocklistTrie, EmptyTrieMatchesNothing) {
    EXPECT_FALSE(BlocklistTrie{}.lookup(name("example.com")).matched);
    EXPECT_FALSE(BlocklistTrie::Builder{}.build().lookup(name("example.com")).matched);
    EXPECT_FALSE(BlocklistTrie{}.lookup(name(".")).matched);
    EXPECT_EQ(BlocklistTrie{}.size(), 0u);
}

TEST(BlocklistTrie, RuleCoversTheDomainAndEverythingBelowIt) {
    const auto trie = trie_of({{"example.com", Block}});
    for (const char* hit : {"example.com", "ads.example.com", "a.b.c.example.com"}) {
        auto r = trie.lookup(name(hit));
        EXPECT_TRUE(r.matched) << hit;
        EXPECT_EQ(r.action, Block) << hit;
        EXPECT_EQ(r.rule, "example.com.") << hit;
        EXPECT_EQ(r.source, "test") << hit;
    }
    for (const char* miss : {"com", ".", "notexample.com", "example.org", "example.com.au", "xample.com"}) {
        EXPECT_FALSE(trie.lookup(name(miss)).matched) << miss;
    }
}

TEST(BlocklistTrie, ExactRuleCoversOnlyThatName) {
    BlocklistTrie::Builder builder;
    builder.add(name("tracker.example.com"), Block, "test", /*include_subdomains=*/false);
    const auto trie = builder.build();
    EXPECT_TRUE(blocks(trie, "tracker.example.com"));
    EXPECT_FALSE(trie.lookup(name("x.tracker.example.com")).matched);
    EXPECT_FALSE(trie.lookup(name("example.com")).matched);
}

TEST(BlocklistTrie, MatchingIgnoresCase) {
    const auto trie = trie_of({{"Ads.Example.COM", Block}});
    EXPECT_TRUE(blocks(trie, "ads.example.com"));
    EXPECT_TRUE(blocks(trie, "X.ADS.EXAMPLE.com"));
    EXPECT_EQ(trie.lookup(name("ADS.example.com")).rule, "ads.example.com.");
}

TEST(BlocklistTrie, DeepestBlockRuleIsReported) {
    BlocklistTrie::Builder builder;
    builder.add(name("example.com"), Block, "ads.txt");
    builder.add(name("t.example.com"), Block, "trackers.txt");
    const auto trie = builder.build();

    auto r = trie.lookup(name("x.t.example.com"));
    EXPECT_EQ(r.rule, "t.example.com.");
    EXPECT_EQ(r.source, "trackers.txt");
    r = trie.lookup(name("www.example.com"));
    EXPECT_EQ(r.rule, "example.com.");
    EXPECT_EQ(r.source, "ads.txt");
}

TEST(BlocklistTrie, AllowBeatsBlockAtAnyDepth) {
    // Allow below a block: the allowed subtree is carved out.
    auto trie = trie_of({{"example.com", Block}, {"cdn.example.com", Allow}});
    EXPECT_TRUE(blocks(trie, "www.example.com"));
    EXPECT_TRUE(blocks(trie, "example.com"));
    for (const char* allowed : {"cdn.example.com", "img.cdn.example.com"}) {
        auto r = trie.lookup(name(allowed));
        EXPECT_TRUE(r.matched) << allowed;
        EXPECT_EQ(r.action, Allow) << allowed;
        EXPECT_EQ(r.rule, "cdn.example.com.") << allowed;
    }

    // Allow above a block: a deeper block doesn't override it (README §7.6.2).
    trie = trie_of({{"example.com", Allow}, {"ads.example.com", Block}});
    auto r = trie.lookup(name("x.ads.example.com"));
    EXPECT_EQ(r.action, Allow);
    EXPECT_EQ(r.rule, "example.com.");

    // Both on the same name.
    trie = trie_of({{"example.com", Block}, {"example.com", Allow}});
    EXPECT_EQ(trie.lookup(name("example.com")).action, Allow);
}

TEST(BlocklistTrie, ExactAllowCoversOnlyThatName) {
    BlocklistTrie::Builder builder;
    builder.add(name("example.com"), Block, "test");
    builder.add(name("www.example.com"), Allow, "test", /*include_subdomains=*/false);
    const auto trie = builder.build();
    EXPECT_EQ(trie.lookup(name("www.example.com")).action, Allow);
    EXPECT_TRUE(blocks(trie, "x.www.example.com"));
}

TEST(BlocklistTrie, SizeCountsDistinctDomains) {
    BlocklistTrie::Builder builder;
    builder.add(name("a.com"), Block, "one.txt");
    builder.add(name("a.com"), Block, "two.txt");  // on two lists
    builder.add(name("A.COM"), Block, "one.txt");  // twice on one
    builder.add(name("b.a.com"), Block, "one.txt");
    builder.add(name("c.com"), Allow, "allow.txt");
    const auto trie = builder.build();
    EXPECT_EQ(trie.size(), 3u);
    EXPECT_EQ(trie.lookup(name("a.com")).source, "one.txt");  // the first list it was read from
    EXPECT_GT(trie.memory_bytes(), 0u);
}

TEST(BlocklistTrie, ADomainOnSeveralListsIsReportedFromTheFirst) {
    // Enough rules that sorting them can't get away with being unstable.
    BlocklistTrie::Builder builder;
    for (const char* source : {"first.txt", "second.txt", "third.txt"}) {
        for (int i = 0; i < 200; ++i) builder.add(name("d" + std::to_string(i) + ".example"), Block, source);
    }
    const auto trie = builder.build();
    EXPECT_EQ(trie.size(), 200u);
    for (int i = 0; i < 200; ++i) {
        EXPECT_EQ(trie.lookup(name("d" + std::to_string(i) + ".example")).source, "first.txt") << i;
    }
}

TEST(BlocklistTrie, BuildEmptiesTheBuilder) {
    BlocklistTrie::Builder builder;
    builder.add(name("a.com"), Block, "test");
    EXPECT_EQ(builder.build().size(), 1u);
    EXPECT_EQ(builder.build().size(), 0u);
}

TEST(BlocklistTrie, FindsEveryOneOfManySiblings) {
    // Siblings of every length and byte value: the binary search over a
    // node's children must agree with the order they were built in.
    BlocklistTrie::Builder   builder;
    std::vector<std::string> labels;
    for (int i = 0; i < 300; ++i) {
        std::string label(1 + i % 7, static_cast<char>('a' + i % 26));
        label += std::to_string(i);
        if (i % 5 == 0) label.insert(label.begin(), '-');
        labels.push_back(label);
        builder.add(name(label + ".com"), Block, "test");
    }
    const auto trie = builder.build();
    EXPECT_EQ(trie.size(), labels.size());
    for (const auto& label : labels) {
        EXPECT_TRUE(blocks(trie, (label + ".com").c_str())) << label;
        EXPECT_FALSE(trie.lookup(name(label + "x.com")).matched) << label;
        EXPECT_FALSE(trie.lookup(name(label + ".net")).matched) << label;
    }
}

TEST(BlocklistTrie, AgreesWithABruteForceCheck) {
    // Random rules and names over a tiny alphabet, so they overlap a lot.
    std::mt19937 rng(20261002);
    auto random_name = [&](int max_labels) {
        static const char* kLabels[] = {"a", "b", "ab", "ba", "c", "com", "x"};
        Name n;
        const int count = 1 + static_cast<int>(rng() % static_cast<unsigned>(max_labels));
        for (int i = 0; i < count; ++i) n.append_label(kLabels[rng() % std::size(kLabels)]);
        return n;
    };

    for (int round = 0; round < 20; ++round) {
        struct Rule {
            Name       domain;
            ListAction action;
            bool       subtree;
        };
        std::vector<Rule>      rules;
        BlocklistTrie::Builder builder;
        for (int i = 0; i < 40; ++i) {
            Rule rule{random_name(3), rng() % 4 == 0 ? Allow : Block, rng() % 3 != 0};
            builder.add(rule.domain, rule.action, "test", rule.subtree);
            rules.push_back(rule);
        }
        const auto trie = builder.build();

        for (int i = 0; i < 200; ++i) {
            const Name q = random_name(5);
            bool       allowed = false, blocked = false;
            size_t     deepest_block = 0;
            for (const auto& rule : rules) {
                const bool covers = rule.subtree ? q.is_subdomain_of(rule.domain) : q == rule.domain;
                if (!covers) continue;
                if (rule.action == Allow) allowed = true;
                if (rule.action == Block) {
                    blocked       = true;
                    deepest_block = std::max(deepest_block, rule.domain.label_count());
                }
            }
            const auto r = trie.lookup(q);
            ASSERT_EQ(r.matched, allowed || blocked) << q.to_string();
            if (!r.matched) continue;
            ASSERT_EQ(r.action, allowed ? Allow : Block) << q.to_string();
            if (!allowed) {
                ASSERT_EQ(name(r.rule).label_count(), deepest_block) << q.to_string();
            }
        }
    }
}

// ─── List files ─────────────────────────────────────────────────────────────

TEST(BlocklistTrie, ReadsEveryListFormat) {
    const ListFile file(
        "# a hosts file\n"
        "127.0.0.1 localhost\n"                     // boilerplate: ignored
        "::1 localhost ip6-localhost ip6-loopback\n"
        "fe80::1%lo0 localhost\n"                 // an address with a zone index
        "0.0.0.0 0.0.0.0\n"
        "255.255.255.255 broadcasthost\n"
        "0.0.0.0 ads.example.com\n"
        "0.0.0.0\tone.test two.test   # several on a line, then a comment\n"
        "127.0.0.1 HOSTS.Example.ORG\r\n"           // CRLF, mixed case
        "\n"
        "   \n"
        "plain.example.net\n"
        "  indented.example.net  \n"
        "*.wild.example\n"
        "||adblock.example^\n"
        "! an adblock comment\n"
        "[Adblock Plus 2.0]\n"
        "||thirdparty.example^$third-party\n"       // a modifier: not a whole-domain rule
        "@@||exception.example^\n"                  // an exception: not ours to follow
        "/banner/*\n"                               // a URL pattern
        "http://url.example/path\n"
        "two words\n"
        "0.0.0.0\n"                                 // an address with no name
        "bad..dots.example\n"
        ".\n"                                       // the root: would block everything
        + std::string(64, 'x') + ".example\n");     // label too long

    BlocklistTrie::Builder builder;
    auto stats = builder.load_file(file.path(), Block);
    ASSERT_TRUE(stats.has_value()) << stats.error();
    EXPECT_EQ(stats->rules, 8u);
    EXPECT_EQ(stats->skipped, 9u);

    const auto trie = builder.build();
    for (const char* hit : {"ads.example.com", "one.test", "two.test", "hosts.example.org", "plain.example.net",
                            "indented.example.net", "wild.example", "x.wild.example", "adblock.example"}) {
        EXPECT_TRUE(blocks(trie, hit)) << hit;
    }
    for (const char* miss : {"localhost", "ip6-localhost", "broadcasthost", "thirdparty.example",
                             "exception.example", "url.example", "words", "example.com"}) {
        EXPECT_FALSE(trie.lookup(name(miss)).matched) << miss;
    }
    EXPECT_EQ(trie.lookup(name("ads.example.com")).source, file.path());
}

TEST(BlocklistTrie, AllowFilesUseTheSameFormats) {
    const ListFile block("example.com\n");
    const ListFile allow("0.0.0.0 good.example.com\n||also.example.com^\n");
    BlocklistTrie::Builder builder;
    ASSERT_TRUE(builder.load_file(block.path(), Block).has_value());
    ASSERT_TRUE(builder.load_file(allow.path(), Allow).has_value());
    const auto trie = builder.build();
    EXPECT_TRUE(blocks(trie, "bad.example.com"));
    EXPECT_EQ(trie.lookup(name("x.good.example.com")).action, Allow);
    EXPECT_EQ(trie.lookup(name("x.good.example.com")).source, allow.path());
    EXPECT_EQ(trie.lookup(name("also.example.com")).action, Allow);
}

TEST(BlocklistTrie, MissingFileIsAnError) {
    BlocklistTrie::Builder builder;
    auto stats = builder.load_file("/nonexistent/dnsentinel/list.txt", Block);
    ASSERT_FALSE(stats.has_value());
    EXPECT_NE(stats.error().find("/nonexistent/dnsentinel/list.txt"), std::string::npos) << stats.error();
}
