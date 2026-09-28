#include "dnsentinel/resolver/root_hints.h"

#include "../wire/wire_test_util.h"

#include <gtest/gtest.h>

#include <string>

using namespace dnsentinel;
using namespace dnsentinel::resolver;
using namespace dnsentinel::test;

TEST(RootHints, LoadsTheIanaFile) {
    auto hints = load_root_hints(std::string(DNSENTINEL_SOURCE_DIR) + "/config/named.root");
    ASSERT_TRUE(hints.has_value()) << hints.error();
    EXPECT_EQ(hints->ns.size(), 13u);
    EXPECT_EQ(hints->addresses.size(), 26u);  // an A and an AAAA per server
    EXPECT_EQ(std::get<RDataNS>(hints->ns.front().rdata).nsdname, name("a.root-servers.net"));
    EXPECT_EQ(hints->addresses.front(), make_rr("a.root-servers.net", RRType::A, ipv4("198.41.0.4"), 3600000));
}

TEST(RootHints, TtlAndClassAreOptional) {
    auto hints = parse_root_hints(
        "; lab mini-internet\n"
        ".              NS  a.root.lab.\n"
        "a.root.lab. IN A   10.10.0.2   ; the lab root server\n"
        "\n"
        "a.root.lab. 60 IN AAAA fd00::2\n");
    ASSERT_TRUE(hints.has_value()) << hints.error();
    EXPECT_EQ(hints->ns.size(), 1u);
    ASSERT_EQ(hints->addresses.size(), 2u);
    EXPECT_EQ(hints->addresses[0].rdata, RData{ipv4("10.10.0.2")});
    EXPECT_EQ(hints->addresses[1].ttl, 60u);
}

TEST(RootHints, ErrorsNameTheLine) {
    struct Case {
        const char* text;
        const char* expected;
    };
    const Case cases[] = {
        {". NS a.root.lab.\na.root.lab. MX 10 mail.lab.\n", "line 2"},
        {"example.com. NS ns.example.com.\n", "must belong to the root"},
        {". NS a.root.lab.\na.root.lab. A 999.1.1.1\n", "invalid IPv4"},
        {". NS\n", "expected"},
        {"a.root.lab. A 10.0.0.1\n", "no root NS"},
        {". NS a.root.lab.\n", "no root server addresses"},
    };
    for (const auto& c : cases) {
        auto hints = parse_root_hints(c.text);
        ASSERT_FALSE(hints.has_value()) << c.text;
        EXPECT_NE(hints.error().find(c.expected), std::string::npos) << hints.error();
    }
}

TEST(RootHints, MissingFileIsAnError) {
    auto hints = load_root_hints("/nonexistent/named.root");
    ASSERT_FALSE(hints.has_value());
    EXPECT_NE(hints.error().find("cannot open"), std::string::npos);
}
