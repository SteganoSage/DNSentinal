#include "dnsentinel/policy/acl.h"

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <string>

using namespace dnsentinel::policy;

namespace {

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

Subnet subnet(const char* text) {
    auto s = parse_subnet(text);
    EXPECT_TRUE(s.has_value()) << text << ": " << (s ? "" : s.error());
    return s.value_or(Subnet{});
}

}  // namespace

// ─── Parsing ────────────────────────────────────────────────────────────────

TEST(Acl, ParsesSubnets) {
    EXPECT_EQ(subnet("192.168.0.0/16").to_string(), "192.168.0.0/16");
    EXPECT_EQ(subnet("10.1.2.3").to_string(), "10.1.2.3/32");  // a single host
    EXPECT_EQ(subnet("0.0.0.0/0").to_string(), "0.0.0.0/0");
    EXPECT_EQ(subnet("fd00::/8").to_string(), "fd00::/8");
    EXPECT_EQ(subnet("::1").to_string(), "::1/128");
    EXPECT_EQ(subnet("172.16.0.0/12").prefix, 12);
}

TEST(Acl, RejectsBadSubnets) {
    struct Case {
        const char* text;
        const char* message;
    };
    const Case cases[] = {
        {"10.0.0.0/33", "0 to 32"},
        {"fd00::/129", "0 to 128"},
        {"10.0.0.0/", "0 to 32"},
        {"10.0.0.0/8x", "0 to 32"},
        {"300.1.1.1/8", "not an IP address"},
        {"", "not an IP address"},
        {"10.1.2.3/8", "did you mean 10.0.0.0/8?"},          // host bits set: a typo
        {"192.168.1.0/16", "did you mean 192.168.0.0/16?"},
        {"fd12::1/8", "did you mean fd00::/8?"},
    };
    for (const auto& c : cases) {
        auto s = parse_subnet(c.text);
        ASSERT_FALSE(s.has_value()) << c.text;
        EXPECT_NE(s.error().find(c.message), std::string::npos) << c.text << ": " << s.error();
    }
}

// ─── Matching ───────────────────────────────────────────────────────────────

TEST(Acl, MatchesWholeBytesAndPartialOnes) {
    const Subnet lan = subnet("192.168.0.0/16");
    EXPECT_TRUE(lan.contains(client("192.168.0.1")));
    EXPECT_TRUE(lan.contains(client("192.168.255.254")));
    EXPECT_FALSE(lan.contains(client("192.169.0.1")));

    const Subnet private12 = subnet("172.16.0.0/12");  // a prefix that splits a byte
    EXPECT_TRUE(private12.contains(client("172.16.0.0")));
    EXPECT_TRUE(private12.contains(client("172.31.255.255")));
    EXPECT_FALSE(private12.contains(client("172.32.0.0")));
    EXPECT_FALSE(private12.contains(client("172.15.255.255")));

    EXPECT_TRUE(subnet("10.1.2.3").contains(client("10.1.2.3")));
    EXPECT_FALSE(subnet("10.1.2.3").contains(client("10.1.2.4")));
}

TEST(Acl, ZeroPrefixMatchesTheWholeFamilyOnly) {
    const Subnet any_v4 = subnet("0.0.0.0/0");
    EXPECT_TRUE(any_v4.contains(client("8.8.8.8")));
    EXPECT_FALSE(any_v4.contains(client("2001:db8::1")));  // IPv4 rules never match IPv6
}

TEST(Acl, MatchesIpv6) {
    const Subnet ula = subnet("fd00::/8");
    EXPECT_TRUE(ula.contains(client("fd12:3456::1")));
    EXPECT_FALSE(ula.contains(client("fe80::1")));
    EXPECT_TRUE(subnet("::1").contains(client("::1")));
}

TEST(Acl, Ipv4MappedClientsMatchIpv4Rules) {
    // A dual-stack socket reports IPv4 clients as ::ffff:a.b.c.d.
    EXPECT_TRUE(subnet("192.168.0.0/16").contains(client("::ffff:192.168.1.5")));
    EXPECT_FALSE(subnet("10.0.0.0/8").contains(client("::ffff:192.168.1.5")));
}

TEST(Acl, NonIpClientsAreNeverAllowed) {
    sockaddr_storage unknown{};  // no address family at all
    EXPECT_FALSE(subnet("0.0.0.0/0").contains(unknown));
}

// ─── The access list ────────────────────────────────────────────────────────

TEST(Acl, DefaultIsLocalhostOnly) {
    AccessControl acl{AccessConfig{}};
    EXPECT_TRUE(acl.allows(client("127.0.0.1")));
    EXPECT_TRUE(acl.allows(client("127.8.9.10")));
    EXPECT_TRUE(acl.allows(client("::1")));
    EXPECT_FALSE(acl.allows(client("192.168.1.5")));
    EXPECT_EQ(acl.deny_action(), DenyAction::Refuse);
}

TEST(Acl, AllowsAnyListedSubnet) {
    AccessControl acl{AccessConfig{{subnet("192.168.0.0/16"), subnet("10.0.0.0/8")}, DenyAction::Drop}};
    EXPECT_TRUE(acl.allows(client("192.168.1.5")));
    EXPECT_TRUE(acl.allows(client("10.20.30.40")));
    EXPECT_FALSE(acl.allows(client("127.0.0.1")));  // not listed: localhost is only the default
    EXPECT_FALSE(acl.allows(client("8.8.8.8")));
    EXPECT_EQ(acl.deny_action(), DenyAction::Drop);
}
