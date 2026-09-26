/// @file wire/builder.cpp
/// DNS wire-format builder with suffix compression and RRset-boundary
/// truncation.

#include "dnsentinel/wire/builder.h"

#include "dnsentinel/wire/edns.h"

#include "byte_io.h"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <string>
#include <unordered_map>

namespace dnsentinel::wire {

using detail::put_u16;
using detail::put_u32;
using detail::store_u16;

namespace {

constexpr size_t kHeaderSize       = 12;
constexpr size_t kMaxPointerOffset = 0x3FFF;  // pointers carry 14 bits
constexpr size_t kMaxTcpMessage    = 0xFFFF;

class Writer {
public:
    explicit Writer(bool compress) : compress_(compress) {}

    std::vector<uint8_t> out;

    [[nodiscard]] size_t size() const { return out.size(); }

    /// Discard everything written from `mark` on, including compression
    /// targets that pointed into the discarded bytes.
    void rollback(size_t mark) {
        out.resize(mark);
        std::erase_if(suffixes_, [mark](const auto& entry) { return entry.second >= mark; });
    }

    void name(const Name& n);
    void question(const Question& q);
    void rr(const RR& rr);

private:
    bool compress_;
    // Canonical wire form of a name suffix → offset where it was written.
    std::unordered_map<std::string, uint16_t> suffixes_;
};

void Writer::name(const Name& n) {
    assert(n.wire_length() <= kMaxNameWireLength);

    // Labels are written in original case (0x20 must survive the trip) but
    // suffixes are matched on canonical labels, since names compare
    // case-insensitively.
    const auto& text = n.original_case.size() == n.labels.size() ? n.original_case : n.labels;
    const size_t count = n.labels.size();

    // keys[i] = canonical wire form of labels[i..]
    std::vector<std::string> keys(compress_ ? count : 0);
    for (size_t i = keys.size(); i-- > 0;) {
        const std::string& label = n.labels[i];
        keys[i].reserve(1 + label.size() + (i + 1 < count ? keys[i + 1].size() : 0));
        keys[i] += static_cast<char>(label.size());
        keys[i] += label;
        if (i + 1 < count) keys[i] += keys[i + 1];
    }

    for (size_t i = 0; i < count; ++i) {
        assert(!text[i].empty() && text[i].size() <= kMaxLabelLength);
        if (compress_) {
            if (auto it = suffixes_.find(keys[i]); it != suffixes_.end()) {
                put_u16(out, static_cast<uint16_t>(0xC000 | it->second));
                return;
            }
            if (out.size() <= kMaxPointerOffset) {
                suffixes_.emplace(std::move(keys[i]), static_cast<uint16_t>(out.size()));
            }
        }
        out.push_back(static_cast<uint8_t>(text[i].size()));
        out.insert(out.end(), text[i].begin(), text[i].end());
    }
    out.push_back(0);
}

void Writer::question(const Question& q) {
    name(q.qname);
    put_u16(out, q.qtype);
    put_u16(out, q.qclass);
}

void Writer::rr(const RR& rr) {
    name(rr.name);
    put_u16(out, static_cast<uint16_t>(rr.type));
    put_u16(out, rr.cls);
    put_u32(out, rr.ttl);
    const size_t rdlen_at = out.size();
    put_u16(out, 0);  // patched below

    // Names inside NS/CNAME/PTR/MX/SOA may be compressed (RFC 3597 §4).
    struct RDataWriter {
        Writer& w;
        void operator()(const RDataA& d) {
            const auto* p = reinterpret_cast<const uint8_t*>(&d.addr);
            w.out.insert(w.out.end(), p, p + 4);
        }
        void operator()(const RDataAAAA& d) {
            w.out.insert(w.out.end(), d.addr, d.addr + 16);
        }
        void operator()(const RDataNS& d)    { w.name(d.nsdname); }
        void operator()(const RDataCNAME& d) { w.name(d.target); }
        void operator()(const RDataPTR& d)   { w.name(d.ptrdname); }
        void operator()(const RDataMX& d) {
            put_u16(w.out, d.preference);
            w.name(d.exchange);
        }
        void operator()(const RDataSOA& d) {
            w.name(d.mname);
            w.name(d.rname);
            for (uint32_t v : {d.serial, d.refresh, d.retry, d.expire, d.minimum}) {
                put_u32(w.out, v);
            }
        }
        void operator()(const RDataTXT& d) {
            for (const auto& s : d.strings) {
                assert(s.size() <= 255);
                w.out.push_back(static_cast<uint8_t>(s.size()));
                w.out.insert(w.out.end(), s.begin(), s.end());
            }
        }
        void operator()(const RDataRaw& d) {
            w.out.insert(w.out.end(), d.data.begin(), d.data.end());
        }
    };
    std::visit(RDataWriter{*this}, rr.rdata);

    const size_t rdlen = out.size() - rdlen_at - 2;
    assert(rdlen <= 0xFFFF);
    store_u16(out, rdlen_at, static_cast<uint16_t>(rdlen));
}

bool same_rrset(const RR& a, const RR& b) {
    return a.type == b.type && a.cls == b.cls && a.name == b.name;
}

void write_header(std::vector<uint8_t>& out, const Header& h) {
    // RFC 1035 §4.1.1:
    //   byte 2: QR | Opcode(4) | AA | TC | RD
    //   byte 3: RA | Z | AD | CD | RCODE(4)
    store_u16(out, 0, h.id);
    out[2] = static_cast<uint8_t>((h.qr ? 0x80 : 0) | ((h.opcode & 0x0F) << 3) |
                                  (h.aa ? 0x04 : 0) | (h.tc ? 0x02 : 0) | (h.rd ? 0x01 : 0));
    out[3] = static_cast<uint8_t>((h.ra ? 0x80 : 0) | (h.ad ? 0x20 : 0) |
                                  (h.cd ? 0x10 : 0) | (h.rcode & 0x0F));
    store_u16(out, 4, h.qdcount);
    store_u16(out, 6, h.ancount);
    store_u16(out, 8, h.nscount);
    store_u16(out, 10, h.arcount);
}

std::vector<uint8_t> build_message(const Message& msg, size_t max_size, bool compress) {
    Writer w(compress);
    w.out.reserve(std::min<size_t>(max_size, 1232));
    w.out.resize(kHeaderSize);  // filled in last, once counts are known

    // Reserve room for OPT so a truncated response still carries EDNS.
    const size_t limit = max_size - (msg.edns ? kOptRecordSize : 0);

    Header h = msg.header;
    h.qdcount = h.ancount = h.nscount = h.arcount = 0;
    bool truncated = false;

    for (const auto& q : msg.questions) {
        const size_t mark = w.size();
        w.question(q);
        if (w.size() > limit) {
            w.rollback(mark);
            truncated = true;
            break;
        }
        ++h.qdcount;
    }

    // Writes whole RRsets until one doesn't fit. Returns false if it stopped early.
    auto write_section = [&](const std::vector<RR>& rrs, uint16_t& count) {
        for (size_t i = 0; i < rrs.size();) {
            size_t j = i + 1;
            while (j < rrs.size() && same_rrset(rrs[i], rrs[j])) ++j;

            const size_t mark = w.size();
            for (size_t k = i; k < j; ++k) w.rr(rrs[k]);
            if (w.size() > limit) {
                w.rollback(mark);
                return false;
            }
            count = static_cast<uint16_t>(count + (j - i));
            i = j;
        }
        return true;
    };

    if (!truncated) truncated = !write_section(msg.answers, h.ancount);
    if (!truncated) truncated = !write_section(msg.authority, h.nscount);
    if (!truncated) write_section(msg.additional, h.arcount);  // overflow here is not TC

    if (msg.edns) {
        write_opt(w.out, *msg.edns);
        ++h.arcount;
    }

    h.tc = h.tc || truncated;
    write_header(w.out, h);
    return std::move(w.out);
}

}  // namespace

std::vector<uint8_t> build(const Message& msg, const BuildOptions& opts) {
    const size_t max_size = std::max(opts.max_size, kClassicUdpSize);
    return build_message(msg, max_size, opts.compress);
}

std::vector<uint8_t> build_tcp(const Message& msg, const BuildOptions& opts) {
    std::vector<uint8_t> out = build_message(msg, kMaxTcpMessage, opts.compress);
    const auto len = static_cast<uint16_t>(out.size());
    out.insert(out.begin(), {static_cast<uint8_t>(len >> 8), static_cast<uint8_t>(len)});
    return out;
}

}  // namespace dnsentinel::wire
