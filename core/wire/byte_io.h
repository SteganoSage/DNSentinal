#pragma once
/// @file wire/byte_io.h
/// Big-endian (network order) integer helpers shared by parser, builder and
/// EDNS code. Private to core/wire. Readers assume the caller already
/// bounds-checked the offset.

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace dnsentinel::wire::detail {

inline uint16_t load_u16(std::span<const uint8_t> buf, size_t off) {
    return static_cast<uint16_t>((buf[off] << 8) | buf[off + 1]);
}

inline uint32_t load_u32(std::span<const uint8_t> buf, size_t off) {
    return (uint32_t{buf[off]} << 24) | (uint32_t{buf[off + 1]} << 16) |
           (uint32_t{buf[off + 2]} << 8) | uint32_t{buf[off + 3]};
}

inline void put_u16(std::vector<uint8_t>& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>(v >> 8));
    out.push_back(static_cast<uint8_t>(v));
}

inline void put_u32(std::vector<uint8_t>& out, uint32_t v) {
    put_u16(out, static_cast<uint16_t>(v >> 16));
    put_u16(out, static_cast<uint16_t>(v));
}

inline void store_u16(std::vector<uint8_t>& out, size_t off, uint16_t v) {
    out[off]     = static_cast<uint8_t>(v >> 8);
    out[off + 1] = static_cast<uint8_t>(v);
}

}  // namespace dnsentinel::wire::detail
