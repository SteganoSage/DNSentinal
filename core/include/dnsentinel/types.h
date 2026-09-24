#pragma once
/// @file types.h
/// Core DNS data types used throughout DNSentinel.
/// RFC 1035 §4 wire format structures.

#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace dnsentinel {

// ─── Name ────────────────────────────────────────────────────────────────────

/// A DNS name stored as a sequence of labels.
/// Keeps both canonical (lowercased) form for comparison and original-case
/// form for 0x20 echo verification.
struct Name {
    std::vector<std::string> labels;        // canonical (lower-case)
    std::vector<std::string> original_case; // as received / as randomised

    /// Full dot-joined string, e.g. "www.example.com."
    [[nodiscard]] std::string to_string() const;

    /// Number of labels (excluding root)
    [[nodiscard]] size_t label_count() const { return labels.size(); }

    /// Wire-format length (sum of 1+len per label, plus trailing 0x00)
    [[nodiscard]] size_t wire_length() const;

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

struct RDataA     { uint32_t addr; };                          // IPv4
struct RDataAAAA  { uint8_t  addr[16]; };                      // IPv6
struct RDataNS    { Name     nsdname; };
struct RDataCNAME { Name     target; };
struct RDataSOA   { Name mname; Name rname;
                    uint32_t serial, refresh, retry, expire, minimum; };
struct RDataMX    { uint16_t preference; Name exchange; };
struct RDataTXT   { std::vector<std::string> strings; };
struct RDataPTR   { Name     ptrdname; };
struct RDataRaw   { std::vector<uint8_t> data; };              // fallback

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
};

// ─── Question ────────────────────────────────────────────────────────────────

struct Question {
    Name     qname;
    uint16_t qtype  = 0;
    uint16_t qclass = 1;  // IN
};

// ─── EDNS0 info (extracted from OPT pseudo-record) ──────────────────────────

struct EdnsInfo {
    uint16_t udp_payload_size = 512;
    uint8_t  extended_rcode   = 0;
    uint8_t  version          = 0;
    bool     dnssec_ok        = false;
    // EDNS options can be added here later
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
};

}  // namespace dnsentinel
