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
    EXPECT_FALSE(lists(*c, "resolver.qname_minimisation"));
    EXPECT_FALSE(lists(*c, "listen.dot"));
    ASSERT_TRUE(c->dot.has_value());
    EXPECT_EQ(c->dot->tcp.address, "0.0.0.0");
    EXPECT_EQ(c->dot->tcp.port, 853);
    EXPECT_EQ(c->dot->cert, "certs/server.crt");
    EXPECT_EQ(c->dot->key, "certs/server.key");
    for (const char* feature : {"listen.doh", "cache.serve_stale",
                                "telemetry"}) {
        EXPECT_TRUE(lists(*c, feature)) << feature;
    }
    EXPECT_TRUE(c->resolver.use_0x20);
    EXPECT_FALSE(lists(*c, "resolver.use_0x20"));  // implemented (plan §5.2)
    EXPECT_FALSE(lists(*c, "access"));             // implemented (plan §5.5)
    std::vector<std::string> allowed;
    for (const auto& subnet : c->access.allow) allowed.push_back(subnet.to_string());
    EXPECT_EQ(allowed, (std::vector<std::string>{"127.0.0.0/8", "::1/128", "192.168.0.0/16", "10.0.0.0/8"}));
    EXPECT_EQ(c->access.deny, policy::DenyAction::Refuse);
    EXPECT_FALSE(lists(*c, "policy"));  // the lists are implemented (plan §5.6)
    EXPECT_EQ(c->lists.blocklists,
              (std::vector<std::string>{"config/lists/feeds/ads.txt", "config/lists/feeds/trackers.txt",
                                        "config/lists/feeds/malware.txt", "config/lists/custom_block.txt"}));
    EXPECT_EQ(c->lists.allowlists, (std::vector<std::string>{"config/lists/allow.txt"}));
    EXPECT_EQ(c->lists.response, policy::BlockResponse::NullIp);
    EXPECT_EQ(c->lists.block_ttl, 60u);
    EXPECT_TRUE(c->lists.check_cname_chain);
    EXPECT_FALSE(lists(*c, "policy.check_cname_chain"));  // implemented (plan §5.7)
    EXPECT_FALSE(lists(*c, "policy.rebinding_protection"));  // implemented (plan §5.8)
    EXPECT_TRUE(c->rebinding.enabled);
    EXPECT_EQ(c->rebinding.exempt, policy::RebindingConfig::default_exempt());
    EXPECT_FALSE(lists(*c, "rate_limit"));  // implemented (plan §5.9)
    EXPECT_EQ(c->rate_limit.qps, 100u);
    EXPECT_EQ(c->rate_limit.burst, 200u);
    EXPECT_EQ(c->rate_limit.action, policy::DenyAction::Drop);
    EXPECT_EQ(c->rrl.responses_per_second, 10u);
    EXPECT_EQ(c->rrl.slip, 2u);
}

TEST(Config, RateLimitDefaults) {
    auto c = parse_config("");
    ASSERT_TRUE(c.has_value()) << c.error();
    EXPECT_EQ(c->rate_limit.qps, 100u);
    EXPECT_EQ(c->rate_limit.burst, 200u);
    EXPECT_EQ(c->rate_limit.action, policy::DenyAction::Drop);
    EXPECT_TRUE(c->rate_limit.exempt.empty());
    EXPECT_EQ(c->rrl.responses_per_second, 0u);  // RRL is off unless configured
}

TEST(Config, RateLimitParsesEverySetting) {
    auto c = parse_config(
        "rate_limit:\n"
        "  per_client: { qps: 50, burst: 80, action: refuse }\n"
        "  rrl: { responses_per_second: 5, window_seconds: 2, slip: 3, ipv4_prefix: 28, ipv6_prefix: 64 }\n"
        "  exempt: [\"192.168.1.1\", \"fd00::/8\"]\n");
    ASSERT_TRUE(c.has_value()) << c.error();
    EXPECT_EQ(c->rate_limit.qps, 50u);
    EXPECT_EQ(c->rate_limit.burst, 80u);
    EXPECT_EQ(c->rate_limit.action, policy::DenyAction::Refuse);
    EXPECT_EQ(c->rrl.responses_per_second, 5u);
    EXPECT_EQ(c->rrl.window_seconds, 2u);
    EXPECT_EQ(c->rrl.slip, 3u);
    EXPECT_EQ(c->rrl.ipv4_prefix, 28);
    EXPECT_EQ(c->rrl.ipv6_prefix, 64);
    ASSERT_EQ(c->rate_limit.exempt.size(), 2u);
    EXPECT_EQ(c->rate_limit.exempt[0].to_string(), "192.168.1.1/32");
    EXPECT_EQ(c->rrl.exempt, c->rate_limit.exempt);  // one list for both limits
}

TEST(Config, RebindingProtectionIsOnByDefault) {
    auto c = parse_config("");
    ASSERT_TRUE(c.has_value()) << c.error();
    EXPECT_TRUE(c->rebinding.enabled);
    EXPECT_EQ(c->rebinding.exempt, policy::RebindingConfig::default_exempt());
}

TEST(Config, RebindingExemptListReplacesTheDefaults) {
    auto c = parse_config(
        "policy:\n"
        "  rebinding_protection:\n"
        "    enabled: false\n"
        "    exempt: [plex.direct, Corp.Example.]\n");
    ASSERT_TRUE(c.has_value()) << c.error();
    EXPECT_FALSE(c->rebinding.enabled);
    EXPECT_EQ(c->rebinding.exempt, (std::vector<Name>{name("plex.direct"), name("corp.example")}));
}

TEST(Config, RebindingExemptsStubZones) {
    auto c = parse_config(
        "resolver:\n"
        "  stub_zones:\n"
        "    lab.: [\"10.10.0.2\"]\n"
        "    corp.example: [\"10.10.0.3\"]\n"
        "policy:\n"
        "  rebinding_protection:\n"
        "    exempt: [example]\n");
    ASSERT_TRUE(c.has_value()) << c.error();
    // corp.example is already covered by example; lab. is added.
    EXPECT_EQ(c->rebinding.exempt, (std::vector<Name>{name("example"), name("lab")}));
}

TEST(Config, CnameCheckIsOnUnlessTurnedOff) {
    EXPECT_TRUE(parse_config("")->lists.check_cname_chain);
    auto c = parse_config("policy:\n  check_cname_chain: false\n");
    ASSERT_TRUE(c.has_value()) << c.error();
    EXPECT_FALSE(c->lists.check_cname_chain);
}

TEST(Config, ListsDefaultToNone) {
    auto c = parse_config("");
    ASSERT_TRUE(c.has_value()) << c.error();
    EXPECT_TRUE(c->lists.blocklists.empty());
    EXPECT_TRUE(c->lists.allowlists.empty());
    EXPECT_EQ(c->lists.response, policy::BlockResponse::NullIp);
    EXPECT_EQ(c->lists.block_ttl, 60u);
    EXPECT_EQ(c->lists.reload_check_seconds, 60u);
}

TEST(Config, ParsesPolicyLists) {
    auto c = parse_config(
        "policy:\n"
        "  blocklists: [a.txt, b.txt]\n"
        "  allowlist: allow.txt\n"  // one path or a list
        "  block_response: nxdomain\n"
        "  block_ttl: 5\n"
        "  reload_check_seconds: 0\n"
        "  check_cname_chain: false\n");
    ASSERT_TRUE(c.has_value()) << c.error();
    EXPECT_EQ(c->lists.blocklists, (std::vector<std::string>{"a.txt", "b.txt"}));
    EXPECT_EQ(c->lists.allowlists, (std::vector<std::string>{"allow.txt"}));
    EXPECT_EQ(c->lists.response, policy::BlockResponse::NxDomain);
    EXPECT_EQ(c->lists.block_ttl, 5u);
    EXPECT_EQ(c->lists.reload_check_seconds, 0u);
    for (const auto& feature : c->not_implemented) EXPECT_FALSE(feature.starts_with("policy")) << feature;

    c = parse_config("policy:\n  allowlist: [x.txt, y.txt]\n");
    ASSERT_TRUE(c.has_value()) << c.error();
    EXPECT_EQ(c->lists.allowlists, (std::vector<std::string>{"x.txt", "y.txt"}));
}

TEST(Config, AccessDefaultsToLocalhostOnly) {
    auto c = parse_config("");
    ASSERT_TRUE(c.has_value()) << c.error();
    EXPECT_EQ(c->access.allow, policy::AccessConfig::localhost());
    EXPECT_EQ(c->access.deny, policy::DenyAction::Refuse);
}

TEST(Config, ParsesAccess) {
    auto c = parse_config("access:\n  allow: [\"10.0.0.0/8\", \"fd00::/8\", \"192.0.2.7\"]\n  deny_action: drop\n");
    ASSERT_TRUE(c.has_value()) << c.error();
    std::vector<std::string> allowed;
    for (const auto& subnet : c->access.allow) allowed.push_back(subnet.to_string());
    EXPECT_EQ(allowed, (std::vector<std::string>{"10.0.0.0/8", "fd00::/8", "192.0.2.7/32"}));
    EXPECT_EQ(c->access.deny, policy::DenyAction::Drop);
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
    EXPECT_FALSE(c->resolver.use_0x20);
}

TEST(Config, SpoofDetectionCanBeTurnedOff) {
    auto c = parse_config("resolver:\n  spoof_tcp_threshold: 0\n");
    ASSERT_TRUE(c.has_value()) << c.error();
    EXPECT_EQ(c->resolver.spoof_tcp_threshold, 0u);
    EXPECT_EQ(parse_config("")->resolver.spoof_tcp_threshold, 5u);  // on by default
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

TEST(Config, DotIsOffUnlessConfigured) {
    auto off = parse_config("listen:\n  udp: \"127.0.0.1:5353\"\n");
    ASSERT_TRUE(off.has_value()) << off.error();
    EXPECT_FALSE(off->dot.has_value());

    auto on = parse_config(
        "listen:\n"
        "  dot:\n"
        "    addr: \"127.0.0.1:8853\"\n"
        "    cert: /tmp/lab.crt\n"
        "    key: /tmp/lab.key\n");
    ASSERT_TRUE(on.has_value()) << on.error();
    ASSERT_TRUE(on->dot.has_value());
    EXPECT_EQ(on->dot->tcp.address, "127.0.0.1");
    EXPECT_EQ(on->dot->tcp.port, 8853);
    EXPECT_EQ(on->dot->cert, "/tmp/lab.crt");
    EXPECT_EQ(on->dot->key, "/tmp/lab.key");
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
        {"listen:\n  dot:\n    addr: \"127.0.0.1:853\"\n    cert: a.crt\n", "line 3: listen.dot needs addr, cert and key"},
        {"listen:\n  dot:\n    addr: \"127.0.0.1\"\n", "listen.dot.addr must be \"address:port\""},
        {"listen:\n  dot:\n    port: 853\n", "unknown setting 'listen.dot.port'"},
        {"resolver: { edns_buffer: 1232\n", "invalid YAML"},
        {"resolver:\n  stub_zones:\n    lab.: [\"fd00::2\"]\n", "line 3: resolver.stub_zones: IPv6 server fd00::2"},
        {"resolver:\n  stub_zones:\n    lab.: [\"lab-root\"]\n", "invalid server address 'lab-root'"},
        {"resolver:\n  stub_zones:\n    lab.: []\n", "lab. needs a list of server addresses"},
        {"resolver:\n  stub_zones:\n    a..b: [\"10.0.0.1\"]\n", "invalid zone name 'a..b'"},
        {"resolver:\n  stub_zones:\n    lab: [\"10.0.0.1\"]\n    lab.: [\"10.0.0.2\"]\n", "lab. is listed twice"},
        {"resolver:\n  stub_zones: [\"10.0.0.1\"]\n", "must map zone names to lists of server addresses"},
        {"access:\n  allow:\n    - \"10.0.0.0/8\"\n    - \"10.1.2.3/8\"\n", "line 4: access.allow: '10.1.2.3/8' has host bits set; did you mean 10.0.0.0/8?"},
        {"access:\n  allow: \"10.0.0.0/8\"\n", "access.allow must be a list of subnets"},
        {"access:\n  allow: []\n", "access.allow is empty: no client could use the resolver"},
        {"access:\n  deny_action: reject\n", "access.deny_action must be 'refuse' or 'drop'"},
        {"access:\n  alow: [\"10.0.0.0/8\"]\n", "unknown setting 'access.alow'"},
        {"policy:\n  blocklists: [a.txt, b.txt, a.txt]\n", "line 2: policy.blocklists: a.txt is listed twice"},
        {"policy:\n  blocklists: [[a.txt]]\n", "policy.blocklists must be a file path or a list of them"},
        {"policy:\n  allowlist: \"\"\n", "policy.allowlist must be a file path or a list of them"},
        {"policy:\n  block_response: sinkhole\n", "policy.block_response must be 'null_ip' or 'nxdomain'"},
        {"policy:\n  block_ttl: 100000\n", "policy.block_ttl must be between 0 and 86400"},
        {"policy:\n  blocklist: [a.txt]\n", "unknown setting 'policy.blocklist'"},
        {"policy:\n  check_cname_chain: sometimes\n", "policy.check_cname_chain must be true or false"},
        {"policy:\n  rebinding_protection:\n    exempt: home\n", "policy.rebinding_protection.exempt must be a list of domains"},
        {"policy:\n  rebinding_protection:\n    exempt: [a..b]\n", "line 3: policy.rebinding_protection.exempt: invalid domain name 'a..b'"},
        {"policy:\n  rebinding_protection:\n    exempt: [\".\"]\n", "exempting the root exempts everything; use enabled: false"},
        {"policy:\n  rebinding_protection:\n    exempt: [lan, LAN.]\n", "lan. is listed twice"},
        {"policy:\n  rebinding_protection:\n    exempt_tlds: [lan]\n", "unknown setting 'policy.rebinding_protection.exempt_tlds'"},
        {"rate_limit:\n  per_client:\n    burst: 0\n", "rate_limit.per_client.burst must be between 1 and"},
        {"rate_limit:\n  per_client:\n    action: block\n", "rate_limit.per_client.action must be 'refuse' or 'drop'"},
        {"rate_limit:\n  rrl:\n    slip: 11\n", "rate_limit.rrl.slip must be between 0 and 10"},
        {"rate_limit:\n  rrl:\n    ipv4_prefix: 33\n", "rate_limit.rrl.ipv4_prefix must be between 8 and 32"},
        {"rate_limit:\n  rrl:\n    window_seconds: 0\n", "rate_limit.rrl.window_seconds must be between 1 and 3600"},
        {"rate_limit:\n  exempt: [\"10.1.2.3/8\"]\n", "line 2: rate_limit.exempt: '10.1.2.3/8' has host bits set"},
        {"rate_limit:\n  rrl:\n    rate: 5\n", "unknown setting 'rate_limit.rrl.rate'"},
    };
    for (const auto& c : cases) {
        auto config = parse_config(c.yaml);
        ASSERT_FALSE(config.has_value()) << c.yaml;
        EXPECT_NE(config.error().find(c.expected), std::string::npos) << config.error();
    }
}

#ifdef DNSENTINEL_WEAK_MODE
TEST(Config, WeakModeSectionIsParsed) {
    auto c = parse_config(
        "resolver:\n"
        "  weak_mode:\n"
        "    txid_bits: 4\n"
        "    sequential_txid: true\n"
        "    fixed_source_port: 5300\n"
        "    accept_out_of_bailiwick: true\n");
    ASSERT_TRUE(c.has_value()) << c.error();
    EXPECT_TRUE(c->resolver.weak.weaken);
    EXPECT_EQ(c->resolver.weak.txid_bits, 4);
    EXPECT_TRUE(c->resolver.weak.sequential_txid);
    EXPECT_EQ(c->resolver.weak.fixed_source_port, 5300);
    EXPECT_TRUE(c->resolver.weak.accept_out_of_bailiwick);
}

TEST(Config, NoWeakModeSectionMeansFullStrength) {
    auto c = parse_config("");
    ASSERT_TRUE(c.has_value()) << c.error();
    EXPECT_FALSE(c->resolver.weak.weaken);
}
#endif

TEST(Config, MissingFileIsAnError) {
    auto c = load_config("/nonexistent/dnsentinel.yaml");
    ASSERT_FALSE(c.has_value());
    EXPECT_NE(c.error().find("cannot open /nonexistent/dnsentinel.yaml"), std::string::npos);
}
