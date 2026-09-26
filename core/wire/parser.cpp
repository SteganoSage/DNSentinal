/// @file wire/parser.cpp
/// DNS wire-format parser. Input is untrusted: every read is bounds-checked
/// and compression pointers are constrained so parsing always terminates.

#include "dnsentinel/wire/parser.h"

#include "dnsentinel/wire/edns.h"

#include "byte_io.h"

#include <cstring>
#include <string_view>
#include <utility>

namespace dnsentinel::wire {

using detail::load_u16;
using detail::load_u32;

namespace {

constexpr size_t   kHeaderSize      = 12;
constexpr size_t   kMinQuestionSize = 5;    // root name + qtype + qclass
constexpr size_t   kMinRRSize       = 11;   // root name + type/class/ttl/rdlength
constexpr size_t   kRRFixedSize     = 10;   // type/class/ttl/rdlength
constexpr int      kMaxPointerJumps = 128;
constexpr uint16_t kClassIN         = 1;

template <typename T>
using Result = std::expected<T, ParseError>;

std::unexpected<ParseError> fail(ParseError e) { return std::unexpected(e); }

/// Read a possibly-compressed name starting at `pos`. On success, `pos` is
/// advanced past the name's in-place bytes (through the first pointer).
Result<Name> read_name(std::span<const uint8_t> msg, size_t& pos) {
    Name name;
    size_t cur = pos;
    // A pointer must target strictly before the start of the segment it
    // was read from, so targets strictly decrease and no cycle can exist.
    // The jump cap is an independent second guard.
    size_t segment_start = pos;
    size_t wire_len = 1;  // trailing root label
    int jumps = 0;
    bool jumped = false;

    while (true) {
        if (cur >= msg.size()) return fail(ParseError::BufferTooShort);
        uint8_t len = msg[cur];

        switch (len & 0xC0) {
            case 0x00: {
                if (len == 0) {
                    if (!jumped) pos = cur + 1;
                    return name;
                }
                if (msg.size() - cur - 1 < len) return fail(ParseError::BufferTooShort);
                wire_len += 1 + len;
                if (wire_len > kMaxNameWireLength) return fail(ParseError::NameTooLong);
                name.append_label(std::string_view(
                    reinterpret_cast<const char*>(msg.data() + cur + 1), len));
                cur += 1 + len;
                break;
            }
            case 0xC0: {
                if (msg.size() - cur < 2) return fail(ParseError::BufferTooShort);
                size_t target = load_u16(msg, cur) & 0x3FFF;
                if (target >= segment_start || ++jumps > kMaxPointerJumps) {
                    return fail(ParseError::CompressionLoop);
                }
                if (!jumped) {
                    pos = cur + 2;
                    jumped = true;
                }
                cur = segment_start = target;
                break;
            }
            default:  // 0x40 and 0x80 label types are reserved/obsolete
                return fail(ParseError::InvalidLabelType);
        }
    }
}

Result<Question> read_question(std::span<const uint8_t> msg, size_t& pos) {
    auto qname = read_name(msg, pos);
    if (!qname) return fail(qname.error());
    if (msg.size() - pos < 4) return fail(ParseError::BufferTooShort);
    Question q{std::move(*qname), load_u16(msg, pos), load_u16(msg, pos + 2)};
    pos += 4;
    return q;
}

/// Decode RDATA occupying msg[pos, pos + rdlen). The caller has checked that
/// range is in bounds. Names are read against the whole message so that
/// compression pointers resolve, and must end exactly at the RDATA end.
Result<RData> read_rdata(std::span<const uint8_t> msg, size_t pos, uint16_t rdlen,
                         RRType type, uint16_t cls) {
    const size_t end = pos + rdlen;
    auto rdata = msg.subspan(pos, rdlen);

    auto name_rdata = [&]<typename T>(std::in_place_type_t<T>) -> Result<RData> {
        auto n = read_name(msg, pos);
        if (!n) return fail(n.error());
        if (pos != end) return fail(ParseError::RDataLengthMismatch);
        return T{std::move(*n)};
    };

    switch (type) {
        case RRType::A: {
            if (cls != kClassIN) break;  // A/AAAA layouts are class-specific
            if (rdlen != 4) return fail(ParseError::RDataLengthMismatch);
            RDataA a;
            std::memcpy(&a.addr, rdata.data(), 4);
            return a;
        }
        case RRType::AAAA: {
            if (cls != kClassIN) break;
            if (rdlen != 16) return fail(ParseError::RDataLengthMismatch);
            RDataAAAA aaaa;
            std::memcpy(aaaa.addr, rdata.data(), 16);
            return aaaa;
        }
        case RRType::NS:    return name_rdata(std::in_place_type<RDataNS>);
        case RRType::CNAME: return name_rdata(std::in_place_type<RDataCNAME>);
        case RRType::PTR:   return name_rdata(std::in_place_type<RDataPTR>);
        case RRType::MX: {
            if (rdlen < 2) return fail(ParseError::RDataLengthMismatch);
            uint16_t preference = load_u16(msg, pos);
            pos += 2;
            auto exchange = read_name(msg, pos);
            if (!exchange) return fail(exchange.error());
            if (pos != end) return fail(ParseError::RDataLengthMismatch);
            return RDataMX{preference, std::move(*exchange)};
        }
        case RRType::SOA: {
            auto mname = read_name(msg, pos);
            if (!mname) return fail(mname.error());
            auto rname = read_name(msg, pos);
            if (!rname) return fail(rname.error());
            if (pos > end || end - pos != 20) return fail(ParseError::RDataLengthMismatch);
            return RDataSOA{std::move(*mname), std::move(*rname),
                            load_u32(msg, pos),      load_u32(msg, pos + 4),
                            load_u32(msg, pos + 8),  load_u32(msg, pos + 12),
                            load_u32(msg, pos + 16)};
        }
        case RRType::TXT: {
            // One or more <length><bytes> character-strings.
            RDataTXT txt;
            size_t p = 0;
            while (p < rdata.size()) {
                uint8_t n = rdata[p++];
                if (rdata.size() - p < n) return fail(ParseError::MalformedRData);
                txt.strings.emplace_back(reinterpret_cast<const char*>(rdata.data() + p), n);
                p += n;
            }
            return txt;
        }
        default:
            break;
    }
    return RDataRaw{{rdata.begin(), rdata.end()}};
}

/// Parse `count` records into `out`. An OPT record is only accepted in the
/// additional section, once, with the root as owner; it goes to `edns`.
std::expected<void, ParseError> read_section(std::span<const uint8_t> msg, size_t& pos,
                                             uint16_t count, bool is_additional,
                                             std::vector<RR>& out,
                                             std::optional<EdnsInfo>& edns) {
    out.reserve(count);
    for (uint16_t i = 0; i < count; ++i) {
        auto owner = read_name(msg, pos);
        if (!owner) return fail(owner.error());
        if (msg.size() - pos < kRRFixedSize) return fail(ParseError::BufferTooShort);

        uint16_t type  = load_u16(msg, pos);
        uint16_t cls   = load_u16(msg, pos + 2);
        uint32_t ttl   = load_u32(msg, pos + 4);
        uint16_t rdlen = load_u16(msg, pos + 8);
        pos += kRRFixedSize;
        if (msg.size() - pos < rdlen) return fail(ParseError::BufferTooShort);

        if (type == static_cast<uint16_t>(RRType::OPT)) {
            if (!is_additional || edns || owner->label_count() != 0) {
                return fail(ParseError::InvalidOpt);
            }
            auto info = parse_opt(cls, ttl, msg.subspan(pos, rdlen));
            if (!info) return fail(info.error());
            edns = *info;
            pos += rdlen;
            continue;
        }

        auto rdata = read_rdata(msg, pos, rdlen, static_cast<RRType>(type), cls);
        if (!rdata) return fail(rdata.error());
        pos += rdlen;

        // RFC 2181 §8: a TTL with the top bit set is treated as zero.
        if (ttl & 0x80000000u) ttl = 0;
        out.push_back(RR{std::move(*owner), static_cast<RRType>(type), cls, ttl,
                         std::move(*rdata)});
    }
    return {};
}

}  // namespace

std::string parse_error_to_string(ParseError e) {
    switch (e) {
        case ParseError::BufferTooShort:      return "buffer too short";
        case ParseError::InvalidHeader:       return "invalid header";
        case ParseError::LabelTooLong:        return "label too long";
        case ParseError::NameTooLong:         return "name too long";
        case ParseError::CompressionLoop:     return "compression loop";
        case ParseError::InvalidLabelType:    return "invalid label type";
        case ParseError::SectionOverflow:     return "section counts exceed message size";
        case ParseError::RDataLengthMismatch: return "rdata length mismatch";
        case ParseError::MalformedRData:      return "malformed rdata";
        case ParseError::InvalidOpt:          return "invalid OPT record";
    }
    return "unknown parse error";
}

std::expected<Header, ParseError> parse_header(std::span<const uint8_t> data) {
    if (data.size() < kHeaderSize) return fail(ParseError::BufferTooShort);

    // RFC 1035 §4.1.1:
    //   byte 2: QR | Opcode(4) | AA | TC | RD
    //   byte 3: RA | Z | AD | CD | RCODE(4)
    const uint8_t b2 = data[2];
    const uint8_t b3 = data[3];

    Header h;
    h.id      = load_u16(data, 0);
    h.qr      = (b2 & 0x80) != 0;
    h.opcode  = (b2 >> 3) & 0x0F;
    h.aa      = (b2 & 0x04) != 0;
    h.tc      = (b2 & 0x02) != 0;
    h.rd      = (b2 & 0x01) != 0;
    h.ra      = (b3 & 0x80) != 0;
    h.ad      = (b3 & 0x20) != 0;  // 0x40 is Z: must be zero, ignored
    h.cd      = (b3 & 0x10) != 0;
    h.rcode   = b3 & 0x0F;
    h.qdcount = load_u16(data, 4);
    h.ancount = load_u16(data, 6);
    h.nscount = load_u16(data, 8);
    h.arcount = load_u16(data, 10);
    return h;
}

std::expected<Message, ParseError> parse(std::span<const uint8_t> data) {
    auto header = parse_header(data);
    if (!header) return fail(header.error());
    const Header& h = *header;

    // Cheap rejection of headers that claim far more records than the
    // packet could hold, before allocating anything for them.
    size_t min_needed = size_t{h.qdcount} * kMinQuestionSize +
                        (size_t{h.ancount} + h.nscount + h.arcount) * kMinRRSize;
    if (min_needed > data.size() - kHeaderSize) return fail(ParseError::SectionOverflow);

    Message msg;
    msg.header = h;
    size_t pos = kHeaderSize;

    msg.questions.reserve(h.qdcount);
    for (uint16_t i = 0; i < h.qdcount; ++i) {
        auto q = read_question(data, pos);
        if (!q) return fail(q.error());
        msg.questions.push_back(std::move(*q));
    }

    if (auto r = read_section(data, pos, h.ancount, false, msg.answers, msg.edns); !r) {
        return fail(r.error());
    }
    if (auto r = read_section(data, pos, h.nscount, false, msg.authority, msg.edns); !r) {
        return fail(r.error());
    }
    if (auto r = read_section(data, pos, h.arcount, true, msg.additional, msg.edns); !r) {
        return fail(r.error());
    }
    return msg;
}

}  // namespace dnsentinel::wire
