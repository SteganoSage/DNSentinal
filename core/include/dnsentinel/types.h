#pragma once
/// @file types.h
/// Core DNS data types used throughout DNSentinel.
/// RFC 1035 §4 wire format structures.

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace dnsentinel {

// ─── Name ────────────────────────────────────────────────────────────────────

/// RFC 1035 §2.3.4 size limits. Enforced wherever untrusted input is parsed
/// (wire parser, Name::from_string), not when a Name is assembled in code.
inline constexpr size_t kMaxLabelLength    = 63;
inline constexpr size_t kMaxNameWireLength = 255;

/// A DNS name stored as a sequence of labels.
/// Keeps both canonical (lowercased) form for comparison and original-case
/// form for 0x20 echo verification.
///
/// Invariant: labels.size() == original_case.size(), and labels[i] is the
/// ASCII-lowercased original_case[i]. append_label() maintains this.
/// The root name has no labels.
struct Name {
    std::vector<std::string> labels;        // canonical (lower-case)
    std::vector<std::string> original_case; // as received / as randomised

    /// Parse presentation format: "www.example.com" or "www.example.com.";
    /// "." is the root. Accepts RFC 1035 §5.1 escapes (\. and \DDD).
    /// Returns nullopt on empty labels, bad escapes, or size limit violations.
    [[nodiscard]] static std::optional<Name> from_string(std::string_view text);

    /// Append one label (raw bytes), recording both case forms.
    void append_label(std::string_view raw);

    /// Full dot-joined string, e.g. "www.example.com."
    /// Uses canonical labels. Special and non-printable bytes are escaped
    /// (\. \\ \DDD) so the output is unambiguous and safe to log.
    [[nodiscard]] std::string to_string() const;

    /// Number of labels (excluding root)
    [[nodiscard]] size_t label_count() const { return labels.size(); }

    /// Wire-format length (sum of 1+len per label, plus trailing 0x00)
    [[nodiscard]] size_t wire_length() const;

    /// Hash of the canonical form; consistent with operator==.
    [[nodiscard]] size_t hash() const noexcept;

    bool operator==(const Name& o) const { return labels == o.labels; }
};

// ─── Header ──────────────────────────────────────────────────────────────────

struct Header {
    uint16_t id       = 0;
    bool     qr       = false;  // 0=query, 1=response
    uint8_t  opcode   = 0;      // 4 bits
    bool     aa       = false;  // authoritative answer
    bool     tc       = false;  // truncated
    bool     rd       = false;  // recursion desired
    bool     ra       = false;  // recursion available
    bool     ad       = false;  // authenticated data (DNSSEC)
    bool     cd       = false;  // checking disabled
    uint8_t  rcode    = 0;      // 4 bits: 0=NOERROR, 2=SERVFAIL, 3=NXDOMAIN, 5=REFUSED
    uint16_t qdcount  = 0;
    uint16_t ancount  = 0;
    uint16_t nscount  = 0;
    uint16_t arcount  = 0;

    bool operator==(const Header&) const = default;
};

// ─── RCODE constants ─────────────────────────────────────────────────────────

enum class RCode : uint8_t {
    NoError  = 0,
    FormErr  = 1,
    ServFail = 2,
    NXDomain = 3,
    NotImp   = 4,
    Refused  = 5,
};

// ─── Record types ────────────────────────────────────────────────────────────

enum class RRType : uint16_t {
    A      = 1,
    NS     = 2,
    CNAME  = 5,
    SOA    = 6,
    PTR    = 12,
    MX     = 15,
    TXT    = 16,
    AAAA   = 28,
    OPT    = 41,
    DS     = 43,
    RRSIG  = 46,
    NSEC   = 47,
    DNSKEY = 48,
};

// ─── RDATA variants ─────────────────────────────────────────────────────────

struct RDataA {
    uint32_t addr = 0;  // IPv4, network byte order
    bool operator==(const RDataA&) const = default;
};

struct RDataAAAA {
    uint8_t addr[16] = {};  // IPv6
    bool operator==(const RDataAAAA&) const = default;
};

struct RDataNS {
    Name nsdname;
    bool operator==(const RDataNS&) const = default;
};

struct RDataCNAME {
    Name target;
    bool operator==(const RDataCNAME&) const = default;
};

struct RDataSOA {
    Name     mname;
    Name     rname;
    uint32_t serial = 0, refresh = 0, retry = 0, expire = 0, minimum = 0;
    bool operator==(const RDataSOA&) const = default;
};

struct RDataMX {
    uint16_t preference = 0;
    Name     exchange;
    bool operator==(const RDataMX&) const = default;
};

struct RDataTXT {
    std::vector<std::string> strings;
    bool operator==(const RDataTXT&) const = default;
};

struct RDataPTR {
    Name ptrdname;
    bool operator==(const RDataPTR&) const = default;
};

struct RDataRaw {  // fallback for types we don't parse
    std::vector<uint8_t> data;
    bool operator==(const RDataRaw&) const = default;
};

using RData = std::variant<
    RDataA, RDataAAAA, RDataNS, RDataCNAME, RDataSOA,
    RDataMX, RDataTXT, RDataPTR, RDataRaw
>;

// ─── Resource Record ─────────────────────────────────────────────────────────

/// Trust rank per RFC 2181 §5.4.1 (higher = more trustworthy)
enum class TrustRank : uint8_t {
    Additional  = 1,  // additional section, out of bailiwick
    Glue        = 2,  // glue in referral
    Authority   = 3,  // authority section
    Answer      = 4,  // answer section from authoritative server
};

struct RR {
    Name      name;
    RRType    type    = RRType::A;
    uint16_t  cls     = 1;     // IN = 1
    uint32_t  ttl     = 0;
    RData     rdata;
    TrustRank trust   = TrustRank::Additional;

    /// Compares the record as it appears on the wire. `trust` is local
    /// metadata about where we learned the record, so it is not compared.
    bool operator==(const RR& o) const {
        return name == o.name && type == o.type && cls == o.cls &&
               ttl == o.ttl && rdata == o.rdata;
    }
};

// ─── Question ────────────────────────────────────────────────────────────────

struct Question {
    Name     qname;
    uint16_t qtype  = 0;
    uint16_t qclass = 1;  // IN

    bool operator==(const Question&) const = default;
};

// ─── EDNS0 info (extracted from OPT pseudo-record) ──────────────────────────

struct EdnsInfo {
    uint16_t udp_payload_size = 512;
    uint8_t  extended_rcode   = 0;
    uint8_t  version          = 0;
    bool     dnssec_ok        = false;
    // EDNS options can be added here later

    bool operator==(const EdnsInfo&) const = default;
};

// ─── Complete DNS Message ────────────────────────────────────────────────────

struct Message {
    Header                header;
    std::vector<Question> questions;
    std::vector<RR>       answers;
    std::vector<RR>       authority;
    std::vector<RR>       additional;
    std::optional<EdnsInfo> edns;  // parsed from OPT in additional

    /// Convenience: is this a response?
    [[nodiscard]] bool is_response() const { return header.qr; }

    /// Convenience: first question's qname (most messages have exactly one)
    [[nodiscard]] const Name& qname() const { return questions.at(0).qname; }

    bool operator==(const Message&) const = default;
};

}  // namespace dnsentinel

/// Lets Name be used directly as an unordered_map / unordered_set key.
template <>
struct std::hash<dnsentinel::Name> {
    size_t operator()(const dnsentinel::Name& n) const noexcept { return n.hash(); }
};
