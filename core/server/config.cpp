/// @file server/config.cpp
/// YAML config loading and validation.
///
/// yaml-cpp reports errors by throwing, so the loader does too, internally;
/// parse_config() turns every error into the std::expected it returns.

#include "dnsentinel/server/config.h"

#include <arpa/inet.h>
#include <yaml-cpp/yaml.h>

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <cstring>
#include <fstream>
#include <limits>
#include <optional>
#include <set>
#include <sstream>

namespace dnsentinel::server {

namespace {

struct ConfigError {
    std::string message;
};

[[noreturn]] void fail(const YAML::Node& at, const std::string& what) {
    const YAML::Mark mark = at.Mark();
    throw ConfigError{mark.line >= 0 ? "line " + std::to_string(mark.line + 1) + ": " + what : what};
}

std::optional<uint64_t> to_uint(std::string_view text) {
    uint64_t value = 0;
    auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (ec != std::errc{} || end != text.data() + text.size()) return std::nullopt;
    return value;
}

std::string scalar_or_empty(const YAML::Node& node) { return node.IsScalar() ? node.Scalar() : ""; }

/// One YAML mapping. Keys are ticked off as they are read, so finish() can
/// reject the ones nothing asked for.
class Section {
public:
    /// `node` absent or null: an empty section, so everything keeps its default.
    Section(std::optional<YAML::Node> node, std::string path) : node_(std::move(node)), path_(std::move(path)) {
        if (!node_ || node_->IsNull()) return;
        if (!node_->IsMap()) fail(*node_, (path_.empty() ? "the configuration" : path_) + " must be a mapping");
        std::set<std::string> keys;
        for (const auto& kv : *node_) {
            if (!kv.first.IsScalar()) fail(kv.first, "setting names must be plain words");
            if (!keys.insert(kv.first.Scalar()).second) fail(kv.first, name(kv.first.Scalar()) + " is set twice");
        }
    }

    [[nodiscard]] std::string name(const std::string& key) const { return path_.empty() ? key : path_ + "." + key; }

    /// The value at `key`, if set, ticking it off.
    std::optional<YAML::Node> take(const std::string& key) {
        used_.insert(key);
        if (!node_ || !node_->IsMap()) return std::nullopt;
        const YAML::Node& map   = *node_;  // const operator[] never inserts
        YAML::Node        value = map[key];
        if (!value.IsDefined()) return std::nullopt;
        return value;
    }

    template <typename T>
    void read_uint(const std::string& key, T& out, uint64_t min = 0, uint64_t max = std::numeric_limits<T>::max()) {
        auto node = take(key);
        if (!node) return;
        auto value = to_uint(scalar_or_empty(*node));
        if (!value) fail(*node, name(key) + " must be a whole number");
        if (*value < min || *value > max) {
            fail(*node, name(key) + " must be between " + std::to_string(min) + " and " + std::to_string(max) +
                            " (got " + node->Scalar() + ")");
        }
        out = static_cast<T>(*value);
    }

    void read_bool(const std::string& key, bool& out) {
        auto node = take(key);
        if (!node) return;
        if (!node->IsScalar() || !YAML::convert<bool>::decode(*node, out)) fail(*node, name(key) + " must be true or false");
    }

    void read_string(const std::string& key, std::string& out) {
        auto node = take(key);
        if (!node) return;
        if (scalar_or_empty(*node).empty()) fail(*node, name(key) + " must be a non-empty string");
        out = node->Scalar();
    }

    /// Reject every key nothing read: most likely a typo.
    void finish() const {
        if (!node_ || !node_->IsMap()) return;
        for (const auto& kv : *node_) {
            if (!used_.contains(kv.first.Scalar())) fail(kv.first, "unknown setting '" + name(kv.first.Scalar()) + "'");
        }
    }

private:
    std::optional<YAML::Node> node_;
    std::string               path_;
    std::set<std::string>     used_;
};

/// "0.0.0.0:53" or "[::]:53".
void read_listen_address(Section& section, const std::string& key, std::string& address, uint16_t& port) {
    auto node = section.take(key);
    if (!node) return;
    const std::string name  = section.name(key);
    const std::string text  = scalar_or_empty(*node);
    const std::string usage = name + " must be \"address:port\", e.g. \"0.0.0.0:53\" or \"[::]:53\"";

    std::string host, port_text;
    int         family = AF_INET;
    if (text.starts_with('[')) {
        const size_t close = text.find(']');
        if (close == std::string::npos || text.compare(close + 1, 1, ":") != 0) fail(*node, usage);
        host      = text.substr(1, close - 1);
        port_text = text.substr(close + 2);
        family    = AF_INET6;
    } else {
        const size_t colon = text.find(':');
        if (colon == std::string::npos || text.find(':', colon + 1) != std::string::npos) fail(*node, usage);
        host      = text.substr(0, colon);
        port_text = text.substr(colon + 1);
    }

    in6_addr buffer{};  // big enough for either family
    if (inet_pton(family, host.c_str(), &buffer) != 1) fail(*node, name + ": invalid IP address '" + host + "'");
    auto number = to_uint(port_text);
    if (!number || *number == 0 || *number > 65535) fail(*node, name + ": port must be between 1 and 65535");
    address = host;
    port    = static_cast<uint16_t>(*number);
}

/// stub_zones: { "lab.": ["10.10.0.2", ...], ... }
void read_stub_zones(Section& section, std::vector<resolver::StubZone>& out) {
    auto node = section.take("stub_zones");
    if (!node || node->IsNull()) return;
    const std::string name = section.name("stub_zones");
    if (!node->IsMap()) fail(*node, name + " must map zone names to lists of server addresses");

    for (const auto& kv : *node) {
        const std::string zone_text = scalar_or_empty(kv.first);
        auto zone = Name::from_string(zone_text);
        if (!zone) fail(kv.first, name + ": invalid zone name '" + zone_text + "'");
        for (const auto& existing : out) {
            if (existing.zone == *zone) fail(kv.first, name + ": " + zone->to_string() + " is listed twice");
        }

        resolver::StubZone stub{*zone, {}};
        const YAML::Node& servers = kv.second;
        if (!servers.IsSequence() || servers.size() == 0) {
            fail(servers, name + ": " + zone->to_string() + " needs a list of server addresses");
        }
        for (const auto& server : servers) {
            const std::string text = scalar_or_empty(server);
            in_addr  v4{};
            in6_addr v6{};
            if (inet_pton(AF_INET, text.c_str(), &v4) == 1) {
                stub.servers.push_back(v4.s_addr);
            } else if (inet_pton(AF_INET6, text.c_str(), &v6) == 1) {
                fail(server, name + ": IPv6 server " + text + " is not supported yet (upstream queries are IPv4 only)");
            } else {
                fail(server, name + ": invalid server address '" + text + "'");
            }
        }
        out.push_back(std::move(stub));
    }
}

/// access: who may use the resolver (plan §5.5).
void read_access(Section& top, policy::AccessConfig& out) {
    Section access(top.take("access"), "access");
    if (auto allow = access.take("allow")) {
        const std::string name = access.name("allow");
        if (!allow->IsSequence()) fail(*allow, name + " must be a list of subnets, like [\"192.168.0.0/16\"]");
        out.allow.clear();
        for (const auto& item : *allow) {
            auto subnet = policy::parse_subnet(scalar_or_empty(item));
            if (!subnet) fail(item, name + ": " + subnet.error());
            out.allow.push_back(*subnet);
        }
        if (out.allow.empty()) fail(*allow, name + " is empty: no client could use the resolver");
    }
    if (auto deny = access.take("deny_action")) {
        const std::string action = scalar_or_empty(*deny);
        if (action == "refuse") {
            out.deny = policy::DenyAction::Refuse;
        } else if (action == "drop") {
            out.deny = policy::DenyAction::Drop;
        } else {
            fail(*deny, access.name("deny_action") + " must be 'refuse' or 'drop'");
        }
    }
    access.finish();
}

/// One path, or a list of them.
void read_paths(Section& section, const std::string& key, std::vector<std::string>& out) {
    auto node = section.take(key);
    if (!node || node->IsNull()) return;
    const std::string name = section.name(key);
    std::vector<YAML::Node> items;
    if (node->IsSequence()) {
        for (const auto& item : *node) items.push_back(item);
    } else {
        items.push_back(*node);
    }
    out.clear();
    for (const auto& item : items) {
        const std::string path = scalar_or_empty(item);
        if (path.empty()) fail(item, name + " must be a file path or a list of them");
        if (std::find(out.begin(), out.end(), path) != out.end()) fail(item, name + ": " + path + " is listed twice");
        out.push_back(path);
    }
}

/// policy: the block and allow lists (plan §5.6), and checks still to come.
void read_policy(Section& top, Config& c) {
    Section              policy(top.take("policy"), "policy");
    policy::ListsConfig& lists = c.lists;
    read_paths(policy, "blocklists", lists.blocklists);
    read_paths(policy, "allowlist", lists.allowlists);
    if (auto response = policy.take("block_response")) {
        const std::string r = scalar_or_empty(*response);
        if (r == "null_ip") {
            lists.response = policy::BlockResponse::NullIp;
        } else if (r == "nxdomain") {
            lists.response = policy::BlockResponse::NxDomain;
        } else {
            fail(*response, policy.name("block_response") + " must be 'null_ip' or 'nxdomain'");
        }
    }
    policy.read_uint("block_ttl", lists.block_ttl, 0, 86400);
    policy.read_uint("reload_check_seconds", lists.reload_check_seconds, 0, 86400);

    bool check_cname_chain = false;
    policy.read_bool("check_cname_chain", check_cname_chain);
    if (check_cname_chain) c.not_implemented.push_back("policy.check_cname_chain");
    if (policy.take("rebinding_protection")) c.not_implemented.push_back("policy.rebinding_protection");
    policy.finish();
}

Config parse(const YAML::Node& document) {
    Config  c;
    Section top(document, "");

    Section listen(top.take("listen"), "listen");
    read_listen_address(listen, "udp", c.udp.address, c.udp.port);
    c.tcp.address = c.udp.address;  // unless listen.tcp says otherwise
    c.tcp.port    = c.udp.port;
    read_listen_address(listen, "tcp", c.tcp.address, c.tcp.port);
    for (const char* key : {"dot", "doh"}) {
        if (listen.take(key)) c.not_implemented.push_back(listen.name(key));
    }
    listen.finish();

    Section                   res(top.take("resolver"), "resolver");
    resolver::ResolverConfig& r = c.resolver;
    if (auto mode = res.take("mode")) {
        const std::string m = scalar_or_empty(*mode);
        if (m == "forward") fail(*mode, "resolver.mode 'forward' is not implemented yet");
        if (m != "recursive") fail(*mode, "resolver.mode must be 'recursive' or 'forward'");
    }
    res.read_string("root_hints", r.root_hints_path);
    res.read_bool("qname_minimisation", r.qname_minimisation);
    res.read_bool("use_0x20", r.use_0x20);
    res.read_uint("edns_buffer", r.edns_buffer, 512, 4096);
    res.read_uint("max_upstream_queries", r.max_upstream_queries, 1);
    res.read_uint("max_referral_depth", r.max_referral_depth, 1);
    res.read_uint("max_cname_chain", r.max_cname_chain);
    res.read_uint("max_glueless_ns", r.max_glueless_ns, 1);
    res.read_uint("query_timeout_ms", r.query_timeout_ms, 1);
    res.read_uint("max_query_timeout_ms", r.max_query_timeout_ms, 1);
    res.read_uint("overall_deadline_ms", r.overall_deadline_ms, 1);
    res.read_uint("spoof_tcp_threshold", r.spoof_tcp_threshold);
    read_stub_zones(res, r.stub_zones);
    res.finish();
    if (r.query_timeout_ms > r.max_query_timeout_ms) {
        throw ConfigError{"resolver.query_timeout_ms (" + std::to_string(r.query_timeout_ms) +
                          ") is above resolver.max_query_timeout_ms (" + std::to_string(r.max_query_timeout_ms) + ")"};
    }
    c.udp.max_response_size = r.edns_buffer;  // one EDNS buffer size, upstream and to clients
    if (r.qname_minimisation) c.not_implemented.push_back("resolver.qname_minimisation");

    Section             cache(top.take("cache"), "cache");
    cache::CacheConfig& k  = c.cache;
    uint64_t            mb = k.max_memory_bytes >> 20;
    cache.read_uint("max_memory_mb", mb, 1, uint64_t{1} << 20);
    k.max_memory_bytes = static_cast<size_t>(mb) << 20;
    cache.read_uint("shards", k.num_shards, 1, 1024);
    cache.read_uint("min_ttl", k.min_ttl);
    cache.read_uint("max_ttl", k.max_ttl);
    Section stale(cache.take("serve_stale"), "cache.serve_stale");
    stale.read_bool("enabled", k.serve_stale);
    stale.read_uint("stale_ttl", k.stale_ttl);
    stale.read_uint("max_stale_age", k.max_stale_age);
    stale.finish();
    Section prefetch(cache.take("prefetch"), "cache.prefetch");
    prefetch.read_bool("enabled", k.prefetch);
    prefetch.read_uint("threshold_pct", k.prefetch_threshold, 0, 100);
    prefetch.finish();
    cache.finish();
    if (k.min_ttl > k.max_ttl) {
        throw ConfigError{"cache.min_ttl (" + std::to_string(k.min_ttl) + ") is above cache.max_ttl (" +
                          std::to_string(k.max_ttl) + ")"};
    }
    if (k.serve_stale) c.not_implemented.push_back("cache.serve_stale");
    if (k.prefetch) c.not_implemented.push_back("cache.prefetch");

    read_access(top, c.access);
    read_policy(top, c);

    // Sections for modules still to come (plan §5-§7).
    for (const char* key : {"rate_limit", "ml", "telemetry"}) {
        if (top.take(key)) c.not_implemented.push_back(key);
    }
    top.finish();
    return c;
}

}  // namespace

std::expected<Config, std::string> parse_config(std::string_view yaml) {
    try {
        return parse(YAML::Load(std::string(yaml)));
    } catch (const ConfigError& e) {
        return std::unexpected(e.message);
    } catch (const YAML::ParserException& e) {
        return std::unexpected("line " + std::to_string(e.mark.line + 1) + ": invalid YAML: " + e.msg);
    } catch (const YAML::Exception& e) {
        return std::unexpected(std::string("invalid configuration: ") + e.what());
    }
}

std::expected<Config, std::string> load_config(const std::string& path) {
    std::ifstream file(path);
    if (!file) return std::unexpected("cannot open " + path + ": " + std::strerror(errno));
    std::ostringstream contents;
    contents << file.rdbuf();
    auto config = parse_config(contents.str());
    if (!config) return std::unexpected(path + ": " + config.error());
    return config;
}

}  // namespace dnsentinel::server
