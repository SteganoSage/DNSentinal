#include "dnsentinel/types.h"

#include <gtest/gtest.h>

#include <string>
#include <unordered_map>
#include <vector>

using dnsentinel::Name;

namespace {

Name must_parse(std::string_view text) {
    auto n = Name::from_string(text);
    EXPECT_TRUE(n.has_value()) << "failed to parse: " << text;
    return n.value_or(Name{});
}

}  // namespace

// ─── from_string / to_string ────────────────────────────────────────────────

TEST(Name, ParsesPresentationFormat) {
    Name n = must_parse("www.example.com");
    EXPECT_EQ(n.labels, (std::vector<std::string>{"www", "example", "com"}));
    EXPECT_EQ(n.label_count(), 3u);
    EXPECT_EQ(n.to_string(), "www.example.com.");
}

TEST(Name, TrailingDotIsOptional) {
    EXPECT_EQ(must_parse("example.com."), must_parse("example.com"));
}

TEST(Name, Root) {
    Name root = must_parse(".");
    EXPECT_EQ(root.label_count(), 0u);
    EXPECT_EQ(root.to_string(), ".");
    EXPECT_EQ(root.wire_length(), 1u);
    EXPECT_EQ(Name{}, root);
}

TEST(Name, RejectsEmptyLabels) {
    for (const char* bad : {"", "..", "a..b", ".a", "a..", ".a."}) {
        EXPECT_FALSE(Name::from_string(bad).has_value()) << bad;
    }
}

TEST(Name, EnforcesLabelLengthLimit) {
    std::string label63(63, 'a');
    EXPECT_TRUE(Name::from_string(label63 + ".com").has_value());
    EXPECT_FALSE(Name::from_string(label63 + "a.com").has_value());
}

TEST(Name, EnforcesWireLengthLimit) {
    // 3 × (1+63) + (1+61) + 1 root = 255 bytes: the maximum.
    std::string l63(63, 'a');
    std::string at_limit = l63 + "." + l63 + "." + l63 + "." + std::string(61, 'b');
    auto n = Name::from_string(at_limit);
    ASSERT_TRUE(n.has_value());
    EXPECT_EQ(n->wire_length(), 255u);

    std::string over = l63 + "." + l63 + "." + l63 + "." + std::string(62, 'b');
    EXPECT_FALSE(Name::from_string(over).has_value());
}

TEST(Name, EscapedDotStaysInsideLabel) {
    Name n = must_parse("a\\.b.com");
    EXPECT_EQ(n.labels, (std::vector<std::string>{"a.b", "com"}));
    EXPECT_EQ(n.to_string(), "a\\.b.com.");
}

TEST(Name, DecimalEscapes) {
    Name n = must_parse("\\000\\255x.com");
    ASSERT_EQ(n.label_count(), 2u);
    EXPECT_EQ(n.labels[0], std::string("\x00\xFFx", 3));
    EXPECT_EQ(n.to_string(), "\\000\\255x.com.");
}

TEST(Name, RejectsBadEscapes) {
    for (const char* bad : {"a\\", "\\25", "\\2a5.com", "\\256.com"}) {
        EXPECT_FALSE(Name::from_string(bad).has_value()) << bad;
    }
}

TEST(Name, ToStringEscapesUnprintableBytes) {
    // A crafted label must not be able to inject newlines or spaces into logs.
    Name n;
    n.append_label("evil\nlabel here");
    n.append_label("com");
    EXPECT_EQ(n.to_string(), "evil\\010label\\032here.com.");
}

TEST(Name, ToStringFromStringRoundTrip) {
    Name n;
    n.append_label(std::string("\x00.\\\"();@$\x7F\x80 ok", 14));
    n.append_label("example");
    auto back = Name::from_string(n.to_string());
    ASSERT_TRUE(back.has_value());
    EXPECT_EQ(*back, n);
}

// ─── Case handling ──────────────────────────────────────────────────────────

TEST(Name, ComparisonIsCaseInsensitive) {
    Name upper = must_parse("WWW.Example.COM");
    Name lower = must_parse("www.example.com");
    EXPECT_EQ(upper, lower);
    EXPECT_EQ(upper.to_string(), "www.example.com.");
}

TEST(Name, PreservesOriginalCase) {
    Name n = must_parse("wWw.ExAmPlE.cOm");
    EXPECT_EQ(n.original_case, (std::vector<std::string>{"wWw", "ExAmPlE", "cOm"}));
    EXPECT_EQ(n.labels, (std::vector<std::string>{"www", "example", "com"}));
}

TEST(Name, CaseFoldingIsAsciiOnly) {
    Name n;
    // '@' and '[' sit just outside 'A'..'Z'; 0xC9 is 'É' in Latin-1.
    n.append_label("@AZ[\xC9");
    EXPECT_EQ(n.labels[0], "@az[\xC9");
}

// ─── wire_length ────────────────────────────────────────────────────────────

TEST(Name, WireLength) {
    // \x03www\x07example\x03com\x00
    EXPECT_EQ(must_parse("www.example.com").wire_length(), 17u);
}

// ─── Hashing ────────────────────────────────────────────────────────────────

TEST(Name, HashIsConsistentWithEquality) {
    Name a = must_parse("MAIL.Example.com");
    Name b = must_parse("mail.example.COM");
    EXPECT_EQ(a.hash(), b.hash());
    EXPECT_EQ(std::hash<Name>{}(a), a.hash());
}

TEST(Name, HashRespectsLabelBoundaries) {
    Name a = must_parse("ab.c");
    Name b = must_parse("a.bc");
    EXPECT_NE(a, b);
    EXPECT_NE(a.hash(), b.hash());
}

TEST(Name, UsableAsUnorderedMapKey) {
    std::unordered_map<Name, int> m;
    m[must_parse("Example.COM")] = 1;
    m[must_parse("example.com.")] = 2;
    m[must_parse("other.com")] = 3;
    EXPECT_EQ(m.size(), 2u);
    EXPECT_EQ(m.at(must_parse("EXAMPLE.com")), 2);
}

// ─── Hierarchy ──────────────────────────────────────────────────────────────

TEST(Name, IsSubdomainOf) {
    Name www = must_parse("www.Example.com");
    EXPECT_TRUE(www.is_subdomain_of(must_parse("example.COM")));
    EXPECT_TRUE(www.is_subdomain_of(must_parse("com")));
    EXPECT_TRUE(www.is_subdomain_of(must_parse(".")));
    EXPECT_TRUE(www.is_subdomain_of(www));  // a name is inside its own zone
    EXPECT_FALSE(must_parse("example.com").is_subdomain_of(www));
    // Whole labels only: a string suffix is not a subdomain.
    EXPECT_FALSE(must_parse("notexample.com").is_subdomain_of(must_parse("example.com")));
    EXPECT_FALSE(must_parse("example.org").is_subdomain_of(must_parse("example.com")));
}

TEST(Name, Parent) {
    Name n = must_parse("wWw.Example.com");
    EXPECT_EQ(n.parent(), must_parse("example.com"));
    EXPECT_EQ(n.parent().original_case, (std::vector<std::string>{"Example", "com"}));
    EXPECT_EQ(n.parent().parent().parent(), must_parse("."));
    EXPECT_EQ(must_parse(".").parent(), must_parse("."));
}
