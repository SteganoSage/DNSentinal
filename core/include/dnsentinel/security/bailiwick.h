#pragma once
/// @file security/bailiwick.h
/// Bailiwick checking (plan §5.3): a server may only tell us about names
/// inside the zone we asked it about.

#include "dnsentinel/types.h"

#include <cstddef>

namespace dnsentinel::security {

/// Remove every answer, authority and additional record whose owner name is
/// outside `zone`, the zone the responding server was queried for. Defeats
/// the classic injection of `bank.com A <attacker>` into a response from
/// some other zone's server. Returns the number of records removed.
size_t filter_to_bailiwick(Message& response, const Name& zone);

}  // namespace dnsentinel::security
