#pragma once
/// @file wire/builder.h
/// DNS wire-format builder. Converts Message → raw bytes.
/// Supports name compression and respects client buffer size limits.

#include "dnsentinel/types.h"

#include <cstdint>
#include <vector>

namespace dnsentinel::wire {

struct BuildOptions {
    uint16_t max_size = 512;   // max response size (512 or EDNS advertised); values below 512 are raised to 512
    bool     compress = true;  // enable name compression
};

/// Build a complete DNS message into wire-format bytes.
///
/// Header counts are computed from the sections; msg.header's counts are
/// ignored. If msg.edns is set, an OPT record is appended (and still fits
/// when the message is truncated).
///
/// Truncation works on RRsets (runs of consecutive records with the same
/// name, type and class): if an answer or authority RRset does not fit,
/// it and everything after it are left out and TC is set. Additional
/// records that do not fit are dropped without setting TC (RFC 2181 §9).
///
/// Precondition: names hold 1-63 byte labels and are at most 255 bytes on
/// the wire, and TXT strings are at most 255 bytes. Names from the parser
/// and Name::from_string always satisfy this.
[[nodiscard]]
std::vector<uint8_t> build(const Message& msg, const BuildOptions& opts = {});

/// Build a message for TCP transport (2-byte length prefix + message).
/// opts.max_size is ignored; the message may use up to 65535 bytes.
[[nodiscard]]
std::vector<uint8_t> build_tcp(const Message& msg, const BuildOptions& opts = {});

}  // namespace dnsentinel::wire
