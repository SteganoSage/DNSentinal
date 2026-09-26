#pragma once
/// @file wire/parser.h
/// DNS wire-format parser. Converts raw bytes → Message.
/// Security-critical: all input is untrusted network data.

#include "dnsentinel/types.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>

namespace dnsentinel::wire {

enum class ParseError {
    BufferTooShort,
    InvalidHeader,
    LabelTooLong,          // > 63 bytes
    NameTooLong,           // > 255 bytes on wire
    CompressionLoop,       // pointer cycle or too many jumps
    InvalidLabelType,      // reserved 01/10 label types
    SectionOverflow,       // more records claimed than bytes available
    RDataLengthMismatch,   // declared RDLENGTH vs actual parsed content
    MalformedRData,
    InvalidOpt,            // OPT outside additional, non-root owner, or duplicated
};

[[nodiscard]] std::string parse_error_to_string(ParseError e);

/// Parse a complete DNS message from raw wire bytes.
/// Returns the parsed Message or a ParseError.
///
/// - Header counts are as they appeared on the wire, so arcount includes
///   the OPT record even though it is moved into Message::edns.
/// - Every RR gets TrustRank::Additional (the lowest). Ranking needs the AA
///   flag and bailiwick, which the resolver applies.
/// - Bytes after the last record are ignored.
[[nodiscard]]
std::expected<Message, ParseError> parse(std::span<const uint8_t> data);

/// Parse just the header (first 12 bytes). Useful for quick ID extraction.
[[nodiscard]]
std::expected<Header, ParseError> parse_header(std::span<const uint8_t> data);

}  // namespace dnsentinel::wire
