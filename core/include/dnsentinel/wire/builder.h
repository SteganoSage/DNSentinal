#pragma once
/// @file wire/builder.h
/// DNS wire-format builder. Converts Message → raw bytes.
/// Supports name compression and respects client buffer size limits.

#include "dnsentinel/types.h"

#include <cstdint>
#include <vector>

namespace dnsentinel::wire {

struct BuildOptions {
    uint16_t max_size = 512;   // max response size (512 or EDNS advertised)
    bool     compress = true;  // enable name compression
};

/// Build a complete DNS message into wire-format bytes.
/// If the message exceeds max_size, it is truncated at a record-set boundary
/// and the TC bit is set.
[[nodiscard]]
std::vector<uint8_t> build(const Message& msg, const BuildOptions& opts = {});

/// Build a message for TCP transport (2-byte length prefix + message).
[[nodiscard]]
std::vector<uint8_t> build_tcp(const Message& msg, const BuildOptions& opts = {});

}  // namespace dnsentinel::wire
