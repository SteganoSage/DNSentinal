#pragma once
/// Helpers shared by the wire-format tests.

#include "dnsentinel/types.h"

#include <arpa/inet.h>

#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace dnsentinel::test {

inline std::vector<uint8_t> from_hex(std::string_view hex) {
    std::vector<uint8_t> out;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        out.push_back(static_cast<uint8_t>(std::stoi(std::string(hex.substr(i, 2)), nullptr, 16)));
    }
    return out;
}

inline Name name(std::string_view text) { return Name::from_string(text).value(); }

inline RDataA ipv4(const char* text) {
    RDataA a;
    if (inet_pton(AF_INET, text, &a.addr) != 1) throw std::invalid_argument(text);
    return a;
}

inline RDataAAAA ipv6(const char* text) {
    RDataAAAA a;
    if (inet_pton(AF_INET6, text, a.addr) != 1) throw std::invalid_argument(text);
    return a;
}

inline RR make_rr(std::string_view owner, RRType type, RData rdata, uint32_t ttl = 300) {
    RR rr;
    rr.name  = name(owner);
    rr.type  = type;
    rr.ttl   = ttl;
    rr.rdata = std::move(rdata);
    return rr;
}

/// Sets header counts to what the wire will carry, so a built message can be
/// compared with its parsed form using ==.
inline Message with_wire_counts(Message m) {
    m.header.qdcount = static_cast<uint16_t>(m.questions.size());
    m.header.ancount = static_cast<uint16_t>(m.answers.size());
    m.header.nscount = static_cast<uint16_t>(m.authority.size());
    m.header.arcount = static_cast<uint16_t>(m.additional.size() + (m.edns ? 1 : 0));
    return m;
}

/// Hand-assembles wire bytes, mainly for crafting malformed packets.
struct Packet {
    std::vector<uint8_t> bytes;

    Packet& u8(uint8_t v) {
        bytes.push_back(v);
        return *this;
    }
    Packet& u16(uint16_t v) { return u8(static_cast<uint8_t>(v >> 8)).u8(static_cast<uint8_t>(v)); }
    Packet& u32(uint32_t v) { return u16(static_cast<uint16_t>(v >> 16)).u16(static_cast<uint16_t>(v)); }
    Packet& raw(std::string_view s) {
        bytes.insert(bytes.end(), s.begin(), s.end());
        return *this;
    }
    /// Uncompressed name: "www.example.com" → 03www07example03com00
    Packet& name(std::string_view dotted) {
        while (!dotted.empty()) {
            size_t dot = dotted.find('.');
            auto label = dotted.substr(0, dot);
            u8(static_cast<uint8_t>(label.size())).raw(label);
            dotted = dot == std::string_view::npos ? "" : dotted.substr(dot + 1);
        }
        return u8(0);
    }
    Packet& ptr(uint16_t offset) { return u16(static_cast<uint16_t>(0xC000 | offset)); }
    Packet& header(uint16_t qd, uint16_t an = 0, uint16_t ns = 0, uint16_t ar = 0,
                   uint16_t id = 0x1234, uint16_t flags = 0x8180) {
        return u16(id).u16(flags).u16(qd).u16(an).u16(ns).u16(ar);
    }
    /// Record header: type, class, ttl, rdlength (RDATA appended separately).
    Packet& rr(uint16_t type, uint16_t rdlen, uint16_t cls = 1, uint32_t ttl = 300) {
        return u16(type).u16(cls).u32(ttl).u16(rdlen);
    }
    [[nodiscard]] size_t size() const { return bytes.size(); }
};

}  // namespace dnsentinel::test
