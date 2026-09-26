/// @file wire/edns.cpp
/// EDNS0 OPT record decoding/encoding and UDP response sizing.

#include "dnsentinel/wire/edns.h"

#include "byte_io.h"

#include <algorithm>

namespace dnsentinel::wire {

using detail::load_u16;
using detail::put_u16;
using detail::put_u32;

std::expected<EdnsInfo, ParseError> parse_opt(uint16_t cls, uint32_t ttl,
                                              std::span<const uint8_t> rdata) {
    // Options are {code:16, length:16, data:length} back to back.
    size_t pos = 0;
    while (pos < rdata.size()) {
        if (rdata.size() - pos < 4) return std::unexpected(ParseError::MalformedRData);
        uint16_t opt_len = load_u16(rdata, pos + 2);
        pos += 4;
        if (rdata.size() - pos < opt_len) return std::unexpected(ParseError::MalformedRData);
        pos += opt_len;
    }

    EdnsInfo info;
    info.udp_payload_size = cls;
    info.extended_rcode   = static_cast<uint8_t>(ttl >> 24);
    info.version          = static_cast<uint8_t>(ttl >> 16);
    info.dnssec_ok        = (ttl & 0x8000) != 0;
    return info;
}

void write_opt(std::vector<uint8_t>& out, const EdnsInfo& edns) {
    uint32_t ttl = (uint32_t{edns.extended_rcode} << 24) |
                   (uint32_t{edns.version} << 16) |
                   (edns.dnssec_ok ? 0x8000u : 0u);
    out.push_back(0);  // owner: root
    put_u16(out, static_cast<uint16_t>(RRType::OPT));
    put_u16(out, edns.udp_payload_size);
    put_u32(out, ttl);
    put_u16(out, 0);   // rdlength: no options
}

uint16_t max_udp_response_size(const std::optional<EdnsInfo>& client_edns,
                               uint16_t our_limit) {
    if (!client_edns) return kClassicUdpSize;
    uint16_t upper = std::max(our_limit, kClassicUdpSize);
    return std::clamp(client_edns->udp_payload_size, kClassicUdpSize, upper);
}

}  // namespace dnsentinel::wire
