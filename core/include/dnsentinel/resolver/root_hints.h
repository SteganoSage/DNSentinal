#pragma once
/// @file resolver/root_hints.h
/// Root hints: the root server names and addresses iterative resolution
/// starts from. Normally IANA's config/named.root; the lab mini-internet
/// uses its own file in the same format.

#include "dnsentinel/types.h"

#include <expected>
#include <string>
#include <string_view>
#include <vector>

namespace dnsentinel::resolver {

struct RootHints {
    std::vector<RR> ns;         // ". NS <server name>"
    std::vector<RR> addresses;  // A / AAAA records for those servers
};

/// Parse root hints in zone-file form: `<owner> [ttl] [IN] <type> <data>`,
/// with `;` comments. Only NS (owned by the root), A and AAAA records are
/// accepted. Errors name the offending line.
[[nodiscard]] std::expected<RootHints, std::string> parse_root_hints(std::string_view text);

/// Read and parse a root hints file.
[[nodiscard]] std::expected<RootHints, std::string> load_root_hints(const std::string& path);

}  // namespace dnsentinel::resolver
