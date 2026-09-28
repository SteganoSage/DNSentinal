#include "dnsentinel/server/config.h"

#include "../wire/wire_test_util.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <string>

using namespace dnsentinel;
using namespace dnsentinel::server;
using namespace dnsentinel::test;

namespace {

bool lists(const Config& c, const std::string& feature) {
    return std::find(c.not_implemented.begin(), c.not_implemented.end(), feature) != c.not_implemented.end();
}

}  // namespace

TEST(Config, LoadsTheRepoConfig) {
    auto c = load_config(std::string(DNSENTINEL_SOURCE_DIR) + "/config/dnsentinel.yaml");
    ASSERT_TRUE(c.has_value()) << c.error();
    EXPECT_EQ(c->udp.address, "0.0.0.0");
    EXPECT_EQ(c->udp.port, 53);
    EXPECT_EQ(c->udp.max_response_size, 1232);
    EXPECT_EQ(c->tcp.address, "0.0.0.0");
    EXPECT_EQ(c->tcp.port, 53);
    EXPECT_EQ(c->resolver.root_hints_path, "config/named.root");
    EXPECT_EQ(c->resolver.query_timeout_ms, 800u);
    EXPECT_EQ(c->resolver.overall_deadline_ms, 5000u);
    EXPECT_EQ(c->cache.max_memory_bytes, size_t{256} << 20);
    EXPECT_EQ(c->cache.num_shards, 16u);
    EXPECT_FALSE(lists(*c, "listen.tcp"));
    for (const char* feature : {"listen.dot", "listen.doh", "resolver.qname_minimisation",
                                "resolver.use_0x20", "cache.serve_stale", "access", "policy", "telemetry"}) {
        EXPECT_TRUE(lists(*c, feature)) << feature;
    }
}

TEST(Config, EmptyConfigKeepsDefaults) {
    auto c = parse_config("");
    ASSERT_TRUE(c.has_value()) << c.error();
    EXPECT_EQ(c->udp.port, 53);
    EXPECT_EQ(c->resolver.edns_buffer, 1232);
    EXPECT_EQ(c->resolver.max_upstream_queries, 30u);
    EXPECT_TRUE(c->resolver.stub_zones.empty());
}

TEST(Config, OnlyFeaturesThatAreOnAreReportedMissing) {
    auto c = parse_config(
        "resolver:\n"
        "  qname_minimisation: false\n"
        "  use_0x20: false\n"
        "cache:\n"
        "  serve_stale: { enabled: false }\n"
        "  prefetch: { enabled: false }\n");
    ASSERT_TRUE(c.has_value()) << c.error();
    EXPECT_TRUE(c->not_implemented.empty());
}

TEST(Config, ParsesStubZones) {
    auto c = parse_config(
        "resolver:\n"
        "  stub_zones:\n"
        "    lab.: [\"10.10.0.2\", \"10.10.0.3\"]\n"
        "    corp.example: [\"192.0.2.1\"]\n");
    ASSERT_TRUE(c.has_value()) << c.error();
    const auto& stubs = c->resolver.stub_zones;
    ASSERT_EQ(stubs.size(), 2u);
    EXPECT_EQ(stubs[0].zone, name("lab"));
    EXPECT_EQ(stubs[0].servers, (std::vector<uint32_t>{ipv4("10.10.0.2").addr, ipv4("10.10.0.3").addr}));
    EXPECT_EQ(stubs[1].zone, name("corp.example"));
}

TEST(Config, TcpListensWhereUdpDoesUnlessToldOtherwise) {
    auto same = parse_config("listen:\n  udp: \"127.0.0.1:5353\"\n");
    ASSERT_TRUE(same.has_value()) << same.error();
    EXPECT_EQ(same->tcp.address, "127.0.0.1");
    EXPECT_EQ(same->tcp.port, 5353);

    auto apart = parse_config("listen:\n  udp: \"127.0.0.1:5353\"\n  tcp: \"[::1]:5354\"\n");
    ASSERT_TRUE(apart.has_value()) << apart.error();
    EXPECT_EQ(apart->tcp.address, "::1");
    EXPECT_EQ(apart->tcp.port, 5354);
    EXPECT_EQ(apart->udp.port, 5353);
}

TEST(Config, ParsesIpv6ListenAddress) {
    auto c = parse_config("listen:\n  udp: \"[::1]:5353\"\n");
    ASSERT_TRUE(c.has_value()) << c.error();
    EXPECT_EQ(c->udp.address, "::1");
    EXPECT_EQ(c->udp.port, 5353);
}

TEST(Config, ErrorsNameTheSettingAndLine) {
    struct Case {
        const char* yaml;
        const char* expected;
    };
    const Case cases[] = {
        {"resolver:\n  edns_buffer: 100\n", "line 2: resolver.edns_buffer must be between 512 and 4096"},
        {"resolver:\n  overal_deadline_ms: 10\n", "line 2: unknown setting 'resolver.overal_deadline_ms'"},
        {"bogus: 1\n", "unknown setting 'bogus'"},
        {"cache:\n  shards: many\n", "cache.shards must be a whole number"},
        {"cache:\n  max_ttl: -1\n", "cache.max_ttl must be a whole number"},
        {"resolver:\n  use_0x20: maybe\n", "resolver.use_0x20 must be true or false"},
        {"resolver:\n  mode: forward\n", "'forward' is not implemented yet"},
        {"resolver:\n  mode: stub\n", "must be 'recursive' or 'forward'"},
        {"resolver: [1, 2]\n", "resolver must be a mapping"},
        {"resolver:\n  mode: recursive\n  mode: recursive\n", "resolver.mode is set twice"},
        {"resolver:\n  query_timeout_ms: 5000\n", "above resolver.max_query_timeout_ms"},
        {"cache:\n  min_ttl: 100\n  max_ttl: 10\n", "cache.min_ttl (100) is above cache.max_ttl (10)"},
        {"cache:\n  prefetch: true\n", "cache.prefetch must be a mapping"},
        {"listen:\n  udp: \"0.0.0.0\"\n", "must be \"address:port\""},
        {"listen:\n  udp: \"::1:53\"\n", "must be \"address:port\""},
        {"listen:\n  udp: \"300.0.0.1:53\"\n", "invalid IP address '300.0.0.1'"},
        {"listen:\n  udp: \"127.0.0.1:0\"\n", "port must be between 1 and 65535"},
        {"listen:\n  tcp: \"localhost:53\"\n", "listen.tcp: invalid IP address 'localhost'"},
        {"resolver: { edns_buffer: 1232\n", "invalid YAML"},
        {"resolver:\n  stub_zones:\n    lab.: [\"fd00::2\"]\n", "line 3: resolver.stub_zones: IPv6 server fd00::2"},
        {"resolver:\n  stub_zones:\n    lab.: [\"lab-root\"]\n", "invalid server address 'lab-root'"},
        {"resolver:\n  stub_zones:\n    lab.: []\n", "lab. needs a list of server addresses"},
        {"resolver:\n  stub_zones:\n    a..b: [\"10.0.0.1\"]\n", "invalid zone name 'a..b'"},
        {"resolver:\n  stub_zones:\n    lab: [\"10.0.0.1\"]\n    lab.: [\"10.0.0.2\"]\n", "lab. is listed twice"},
        {"resolver:\n  stub_zones: [\"10.0.0.1\"]\n", "must map zone names to lists of server addresses"},
    };
    for (const auto& c : cases) {
        auto config = parse_config(c.yaml);
        ASSERT_FALSE(config.has_value()) << c.yaml;
        EXPECT_NE(config.error().find(c.expected), std::string::npos) << config.error();
    }
}

TEST(Config, MissingFileIsAnError) {
    auto c = load_config("/nonexistent/dnsentinel.yaml");
    ASSERT_FALSE(c.has_value());
    EXPECT_NE(c.error().find("cannot open /nonexistent/dnsentinel.yaml"), std::string::npos);
}
