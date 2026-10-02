#pragma once
/// @file server/config.h
/// Loading config/dnsentinel.yaml. Everything is validated at startup and
/// errors name the line at fault (plan §10): a bad config must stop the
/// resolver, not quietly fall back to defaults.

#include "dnsentinel/cache/cache.h"
#include "dnsentinel/net/tcp_listener.h"
#include "dnsentinel/net/udp_listener.h"
#include "dnsentinel/policy/acl.h"
#include "dnsentinel/resolver/recursive_resolver.h"

#include <expected>
#include <string>
#include <string_view>
#include <vector>

namespace dnsentinel::server {

struct Config {
    net::UdpListenerConfig   udp;
    net::TcpListenerConfig   tcp;  // listen.tcp, else wherever UDP listens
    resolver::ResolverConfig resolver;
    cache::CacheConfig       cache;
    policy::AccessConfig     access;  // default: localhost only

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
