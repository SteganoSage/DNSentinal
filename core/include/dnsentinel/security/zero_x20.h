#pragma once
/// @file security/zero_x20.h
/// 0x20 encoding (plan §5.2; Dagon et al., CCS 2008). DNS names compare
/// case-insensitively, but servers echo the question exactly as asked. So we
/// ask with a random mix of upper and lower case and accept only replies
/// that echo that exact pattern: a forger must now guess one extra bit per
/// letter on top of the transaction ID and source port.

#include "dnsentinel/types.h"

#include <cstddef>

namespace dnsentinel::security {

/// `name` with the case of each ASCII letter chosen at random (from a
/// CSPRNG). Only the original case changes: the name still compares equal,
/// and digits, hyphens and other bytes are left alone.
[[nodiscard]] Name randomize_case(const Name& name);

/// The bits of entropy 0x20 adds for `name`: its number of ASCII letters.
[[nodiscard]] size_t case_entropy_bits(const Name& name);

/// True if `a` and `b` are the same name with the same letter case.
[[nodiscard]] bool same_case(const Name& a, const Name& b);

}  // namespace dnsentinel::security
