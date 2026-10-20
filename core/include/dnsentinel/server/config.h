#pragma once
/// @file server/config.h
/// Loading config/dnsentinel.yaml. Everything is validated at startup and
/// errors name the line at fault (plan §10): a bad config must stop the
/// resolver, not quietly fall back to defaults.

#include "dnsentinel/cache/cache.h"
#include "dnsentinel/ml/dga_config.h"
#include "dnsentinel/net/tcp_listener.h"
#include "dnsentinel/net/udp_listener.h"
#include "dnsentinel/policy/acl.h"
#include "dnsentinel/policy/blocklists.h"
#include "dnsentinel/policy/rate_limiter.h"
#include "dnsentinel/policy/rebinding.h"
#include "dnsentinel/security/rrl.h"
#include "dnsentinel/resolver/recursive_resolver.h"

#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace dnsentinel::server {

/// An encrypted listener (listen.dot, listen.doh).
struct TlsListenConfig {
    net::TcpListenerConfig tcp;   // address and port; limits as for plain TCP
    std::string            cert;  // PEM certificate (chain)
    std::string            key;   // its PEM private key, unencrypted
    std::string            path = "/dns-query";  // DoH only: where queries go
};

struct Config {
    net::UdpListenerConfig         udp;
    net::TcpListenerConfig         tcp;  // listen.tcp, else wherever UDP listens
    std::optional<TlsListenConfig> dot;  // listen.dot: DNS over TLS (plan §6.2); none: off
    std::optional<TlsListenConfig> doh;  // listen.doh: DNS over HTTPS (plan §6.3); none: off
    resolver::ResolverConfig resolver;
    cache::CacheConfig       cache;
    policy::AccessConfig     access;  // default: localhost only
    policy::RateLimitConfig  rate_limit;  // default: 100 queries/s per client, burst 200
    security::RrlConfig      rrl;         // default: off
    policy::ListsConfig      lists;   // default: no lists, nothing blocked
    policy::RebindingConfig  rebinding;  // default: on; stub zones are always exempt
    ml::DgaConfig            dga;        // ml.dga, the DGA classifier (plan §7.8.2); default: off

    /// Features the config turns on (in the file, or by default) that this
    /// build doesn't implement yet ("listen.dot", "policy", ...), so startup
    /// can say they are ignored instead of leaving the operator to assume
    /// they work.
    std::vector<std::string> not_implemented;
};

/// Parse config YAML. Missing settings keep their defaults; unknown ones are
/// errors, since a misspelt key would otherwise silently do nothing.
[[nodiscard]] std::expected<Config, std::string> parse_config(std::string_view yaml);

/// Read and parse a config file. Errors start with the path.
[[nodiscard]] std::expected<Config, std::string> load_config(const std::string& path);

}  // namespace dnsentinel::server
