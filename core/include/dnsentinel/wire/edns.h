#pragma once
/// @file wire/edns.h
/// EDNS0 (RFC 6891): the OPT pseudo-record and UDP response sizing.

#include "dnsentinel/types.h"
#include "dnsentinel/wire/parser.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <vector>

namespace dnsentinel::wire {

/// UDP payload size we advertise, upstream and to clients. DNS Flag Day 2020
/// value: avoids IP fragmentation on virtually all paths.
inline constexpr uint16_t kEdnsUdpPayloadSize = 1232;

/// Response size limit for clients that sent no OPT (RFC 1035 §4.2.1).
inline constexpr uint16_t kClassicUdpSize = 512;

/// Size of the OPT record write_opt() emits (root owner, no options).
inline constexpr size_t kOptRecordSize = 11;

/// Decode an OPT record's fields (RFC 6891 §6.1.3). The CLASS field carries
/// the UDP payload size and TTL carries extended-rcode / version / DO.
/// Options in RDATA are validated for structure but not stored.
/// The version is returned as-is; answering BADVERS is the caller's job.
[[nodiscard]]
std::expected<EdnsInfo, ParseError> parse_opt(uint16_t cls, uint32_t ttl,
                                              std::span<const uint8_t> rdata);

/// Append an OPT record carrying `edns` (no options) to `out`.
void write_opt(std::vector<uint8_t>& out, const EdnsInfo& edns);

/// Largest UDP response we may send to a client whose query carried
/// `client_edns`: 512 without EDNS, otherwise the client's advertised size
/// clamped to [512, our_limit] (RFC 6891 §6.2.5).
[[nodiscard]]
uint16_t max_udp_response_size(const std::optional<EdnsInfo>& client_edns,
                               uint16_t our_limit = kEdnsUdpPayloadSize);

}  // namespace dnsentinel::wire
