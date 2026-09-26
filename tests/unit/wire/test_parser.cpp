#include "dnsentinel/wire/parser.h"

#include "dnsentinel/wire/builder.h"
#include "wire_test_util.h"

#include <gtest/gtest.h>

#include <set>
#include <string>
#include <vector>

using namespace dnsentinel;
using namespace dnsentinel::wire;
using namespace dnsentinel::test;

namespace {

// Real responses captured from a recursive resolver (queries sent with RD=1
// and an OPT advertising 1232 bytes). Expected values were cross-checked
// with dnspython.
const char* const kExampleA =
    "500781800001000200000001076578616d706c6503636f6d0000010001c00c000100010000"
    "009800046814179ac00c00010001000000980004ac4293f300002904d0000000000000";

const char* const kMicrosoftCnameChain =
    "3e898180000100030000000103777777096d6963726f736f667403636f6d0000010001c00c"
    "0005000100000458002303777777096d6963726f736f667407636f6d2d632d330765646765"
    "6b6579036e657400c02f000500010000013900190665313336373804647363620a616b616d"
    "616965646765c04dc05e00010001000001000004173c6e2a00002904d0000000000000";

const char* const kGmailMx =
    "0bc38180000100050000000105676d61696c03636f6d00000f0001c00c000f00010000004e"
    "0020000a04616c74310d676d61696c2d736d74702d696e016c06676f6f676c65c012c00c00"
    "0f00010000004e0009002804616c7434c02ec00c000f00010000004e00040005c02ec00c00"
    "0f00010000004e0009001404616c7432c02ec00c000f00010000004e0009001e04616c7433"
    "c02e00002904d0000000000000";

const char* const kNoDataSoa =
    "239381800001000000010001166e6f6e6578697374656e742d646e73656e74696e656c0765"
    "78616d706c6503636f6d0000010001c0230006000100000708003207656c6c696f7474026e"
    "730a636c6f7564666c617265c02b03646e73c04b8ffd197e000027100000096000093a8000"
    "00070800002904d0000000000000";

const char* const kExampleAAAA =
    "06d681800001000200000001076578616d706c6503636f6d00001c0001c00c001c00010000"
    "012c00102606470000100000000000006814179ac00c001c00010000012c00102606470000"
    "10000000000000ac4293f300002904d0000000000000";

const std::vector<const char*> kAllCaptures = {
    kExampleA, kMicrosoftCnameChain, kGmailMx, kNoDataSoa, kExampleAAAA};

Message must_parse(const std::vector<uint8_t>& bytes) {
    auto m = parse(bytes);
    EXPECT_TRUE(m.has_value()) << parse_error_to_string(m.error());
    return m.value_or(Message{});
}

ParseError parse_error(const std::vector<uint8_t>& bytes) {
    auto m = parse(bytes);
    EXPECT_FALSE(m.has_value());
    return m ? ParseError::InvalidHeader : m.error();
}

}  // namespace

// ─── Header ─────────────────────────────────────────────────────────────────

TEST(Parser, HeaderFlagBitLayout) {
    struct Case {
        const char* flag;
        uint8_t b2, b3;
        bool Header::*field;
    };
    const Case cases[] = {
        {"qr", 0x80, 0, &Header::qr}, {"aa", 0x04, 0, &Header::aa},
        {"tc", 0x02, 0, &Header::tc}, {"rd", 0x01, 0, &Header::rd},
        {"ra", 0, 0x80, &Header::ra}, {"ad", 0, 0x20, &Header::ad},
        {"cd", 0, 0x10, &Header::cd},
    };
    for (const auto& c : cases) {
        std::vector<uint8_t> bytes(12, 0);
        bytes[2] = c.b2;
        bytes[3] = c.b3;
        auto h = parse_header(bytes);
        ASSERT_TRUE(h.has_value());
        for (const auto& other : cases) {
            EXPECT_EQ((*h).*other.field, &other == &c) << "set " << c.flag << ", read " << other.flag;
        }
        EXPECT_EQ(h->opcode, 0);
        EXPECT_EQ(h->rcode, 0);
    }
}

TEST(Parser, HeaderOpcodeRcodeAndZ) {
    std::vector<uint8_t> bytes(12, 0);
    bytes[2] = 0x78;  // opcode 15
    bytes[3] = 0x4F;  // Z bit + rcode 15
    auto h = parse_header(bytes);
    ASSERT_TRUE(h.has_value());
    EXPECT_EQ(h->opcode, 15);
    EXPECT_EQ(h->rcode, 15);
    EXPECT_FALSE(h->qr || h->aa || h->tc || h->rd || h->ra || h->ad || h->cd);
}

TEST(Parser, HeaderIdAndCounts) {
    auto h = parse_header(Packet{}.header(1, 2, 3, 4, 0xBEEF).bytes);
    ASSERT_TRUE(h.has_value());
    EXPECT_EQ(h->id, 0xBEEF);
    EXPECT_EQ(h->qdcount, 1);
    EXPECT_EQ(h->ancount, 2);
    EXPECT_EQ(h->nscount, 3);
    EXPECT_EQ(h->arcount, 4);
}

TEST(Parser, RejectsShortHeader) {
    std::vector<uint8_t> bytes(11, 0);
    EXPECT_EQ(parse_header(bytes).error(), ParseError::BufferTooShort);
    EXPECT_EQ(parse_error(bytes), ParseError::BufferTooShort);
}

// ─── Real traffic ───────────────────────────────────────────────────────────

TEST(Parser, RealAResponse) {
    Message m = must_parse(from_hex(kExampleA));
    EXPECT_EQ(m.header.id, 0x5007);
    EXPECT_TRUE(m.header.qr && m.header.rd && m.header.ra);
    EXPECT_EQ(m.header.rcode, 0);
    ASSERT_EQ(m.questions.size(), 1u);
    EXPECT_EQ(m.questions[0], (Question{name("example.com"), 1, 1}));
    ASSERT_EQ(m.answers.size(), 2u);
    EXPECT_EQ(m.answers[0], make_rr("example.com", RRType::A, ipv4("104.20.23.154"), 152));
    EXPECT_EQ(m.answers[1], make_rr("example.com", RRType::A, ipv4("172.66.147.243"), 152));
    EXPECT_TRUE(m.authority.empty());
    // OPT is lifted into edns; arcount still reflects the wire.
    EXPECT_TRUE(m.additional.empty());
    EXPECT_EQ(m.header.arcount, 1);
    ASSERT_TRUE(m.edns.has_value());
    EXPECT_EQ(m.edns->udp_payload_size, 1232);
    EXPECT_EQ(m.edns->version, 0);
    EXPECT_FALSE(m.edns->dnssec_ok);
}

TEST(Parser, RealCnameChainWithNestedPointers) {
    Message m = must_parse(from_hex(kMicrosoftCnameChain));
    ASSERT_EQ(m.answers.size(), 3u);
    EXPECT_EQ(m.answers[0], make_rr("www.microsoft.com", RRType::CNAME,
                                    RDataCNAME{name("www.microsoft.com-c-3.edgekey.net")}, 1112));
    EXPECT_EQ(m.answers[1], make_rr("www.microsoft.com-c-3.edgekey.net", RRType::CNAME,
                                    RDataCNAME{name("e13678.dscb.akamaiedge.net")}, 313));
    EXPECT_EQ(m.answers[2], make_rr("e13678.dscb.akamaiedge.net", RRType::A,
                                    ipv4("23.60.110.42"), 256));
}

TEST(Parser, RealMxResponse) {
    Message m = must_parse(from_hex(kGmailMx));
    ASSERT_EQ(m.answers.size(), 5u);
    const std::pair<uint16_t, const char*> expected[] = {
        {10, "alt1.gmail-smtp-in.l.google.com"}, {40, "alt4.gmail-smtp-in.l.google.com"},
        {5, "gmail-smtp-in.l.google.com"},       {20, "alt2.gmail-smtp-in.l.google.com"},
        {30, "alt3.gmail-smtp-in.l.google.com"},
    };
    for (size_t i = 0; i < 5; ++i) {
        EXPECT_EQ(m.answers[i], make_rr("gmail.com", RRType::MX,
                                        RDataMX{expected[i].first, name(expected[i].second)}, 78));
    }
}

TEST(Parser, RealSoaInAuthority) {
    Message m = must_parse(from_hex(kNoDataSoa));
    EXPECT_TRUE(m.answers.empty());
    ASSERT_EQ(m.authority.size(), 1u);
    RDataSOA soa{name("elliott.ns.cloudflare.com"), name("dns.cloudflare.com"),
                 2415729022u, 10000, 2400, 604800, 1800};
    EXPECT_EQ(m.authority[0], make_rr("example.com", RRType::SOA, soa, 1800));
}

TEST(Parser, RealAAAAResponse) {
    Message m = must_parse(from_hex(kExampleAAAA));
    ASSERT_EQ(m.answers.size(), 2u);
    EXPECT_EQ(m.answers[0], make_rr("example.com", RRType::AAAA, ipv6("2606:4700:10::6814:179a")));
    EXPECT_EQ(m.answers[1], make_rr("example.com", RRType::AAAA, ipv6("2606:4700:10::ac42:93f3")));
}

TEST(Parser, RealTrafficRoundTrips) {
    for (const char* hex : kAllCaptures) {
        Message original = must_parse(from_hex(hex));
        for (bool compress : {true, false}) {
            auto rebuilt = parse(build(original, {.max_size = 1232, .compress = compress}));
            ASSERT_TRUE(rebuilt.has_value()) << parse_error_to_string(rebuilt.error());
            EXPECT_EQ(*rebuilt, original);
        }
    }
}

TEST(Parser, EveryTruncationOfRealTrafficIsRejected) {
    for (const char* hex : kAllCaptures) {
        auto bytes = from_hex(hex);
        for (size_t len = 0; len < bytes.size(); ++len) {
            std::vector<uint8_t> prefix(bytes.begin(), bytes.begin() + len);
            EXPECT_FALSE(parse(prefix).has_value()) << "prefix length " << len;
        }
    }
}

TEST(Parser, PreservesOriginalCase) {
    auto bytes = Packet{}.header(1).name("wWw.ExAmPlE.cOm").u16(1).u16(1).bytes;
    Message m = must_parse(bytes);
    EXPECT_EQ(m.qname().original_case, (std::vector<std::string>{"wWw", "ExAmPlE", "cOm"}));
    EXPECT_EQ(m.qname(), name("www.example.com"));
}

TEST(Parser, IgnoresTrailingBytes) {
    auto bytes = Packet{}.header(1).name("example.com").u16(1).u16(1).raw("junk").bytes;
    EXPECT_TRUE(parse(bytes).has_value());
}

// ─── Compression pointer attacks ────────────────────────────────────────────

TEST(Parser, RejectsSelfPointer) {
    // Offset 12: C0 0C, a pointer to itself.
    auto bytes = Packet{}.header(1).ptr(12).u16(1).u16(1).bytes;
    EXPECT_EQ(parse_error(bytes), ParseError::CompressionLoop);
}

TEST(Parser, RejectsMutualPointers) {
    // Offset 12 → 14, offset 14 → 12.
    auto bytes = Packet{}.header(1).ptr(14).ptr(12).u16(1).u16(1).bytes;
    EXPECT_EQ(parse_error(bytes), ParseError::CompressionLoop);
}

TEST(Parser, RejectsForwardPointerEvenToValidName) {
    // Question name points forward to a well-formed name at offset 18.
    auto bytes = Packet{}.header(1).ptr(18).u16(1).u16(1).name("example.com").bytes;
    EXPECT_EQ(parse_error(bytes), ParseError::CompressionLoop);
}

TEST(Parser, RejectsPointerBackIntoOwnLabels) {
    // Answer owner at offset 29: "a" then a pointer back to offset 29 itself.
    Packet p;
    p.header(1, 1).name("example.com").u16(1).u16(1);
    ASSERT_EQ(p.size(), 29u);
    p.u8(1).raw("a").ptr(29).rr(1, 4).u32(0);
    EXPECT_EQ(parse_error(p.bytes), ParseError::CompressionLoop);
}

namespace {

/// A packet whose second answer owner name takes exactly `jumps` pointer
/// jumps to resolve: a chain of backward pointers stored in the first
/// answer's (unknown-type) RDATA, ending at a root label.
std::vector<uint8_t> pointer_chain(int jumps) {
    const int chain = jumps - 1;  // the owner's own pointer is one jump
    Packet p;
    p.header(0, 2);
    p.u8(0).rr(0xFF00, static_cast<uint16_t>(1 + 2 * chain));
    size_t prev = p.size();
    p.u8(0);  // root label
    for (int i = 0; i < chain; ++i) {
        size_t here = p.size();
        p.ptr(static_cast<uint16_t>(prev));
        prev = here;
    }
    p.ptr(static_cast<uint16_t>(prev)).rr(0xFF00, 0);
    return p.bytes;
}

}  // namespace

TEST(Parser, PointerJumpLimit) {
    EXPECT_TRUE(parse(pointer_chain(128)).has_value());
    EXPECT_EQ(parse_error(pointer_chain(129)), ParseError::CompressionLoop);
}

TEST(Parser, NameLengthLimitSpansPointers) {
    // First answer's RDATA holds a 193-byte name (3 × 63-byte labels).
    // The second owner adds one more label and points at it.
    auto build = [](size_t extra_label) {
        Packet p;
        p.header(0, 2);
        p.u8(0).rr(0xFF00, 193);
        const size_t target = p.size();
        std::string l63(63, 'x');
        p.name(l63 + "." + l63 + "." + l63);
        p.u8(static_cast<uint8_t>(extra_label)).raw(std::string(extra_label, 'y'));
        p.ptr(static_cast<uint16_t>(target)).rr(0xFF00, 0);
        return p.bytes;
    };
    EXPECT_TRUE(parse(build(61)).has_value());  // 62 + 193 = 255
    EXPECT_EQ(parse_error(build(62)), ParseError::NameTooLong);
}

TEST(Parser, RejectsReservedLabelTypes) {
    for (uint8_t type : {uint8_t{0x40}, uint8_t{0x80}}) {
        auto bytes = Packet{}.header(1).u8(type).u8(0).u16(1).u16(1).bytes;
        EXPECT_EQ(parse_error(bytes), ParseError::InvalidLabelType);
    }
}

TEST(Parser, RejectsLabelRunningPastEnd) {
    auto bytes = Packet{}.header(1).u8(20).raw("short").bytes;
    EXPECT_EQ(parse_error(bytes), ParseError::BufferTooShort);
}

// ─── Section and RDATA validation ───────────────────────────────────────────

TEST(Parser, RejectsInflatedCounts) {
    Packet p;
    p.header(1, 0xFFFF).name("example.com").u16(1).u16(1);
    p.bytes.resize(40);
    EXPECT_EQ(parse_error(p.bytes), ParseError::SectionOverflow);
}

TEST(Parser, RejectsRdataRunningPastEnd) {
    auto bytes = Packet{}.header(0, 1).u8(0).rr(1, 4).u16(0).bytes;
    EXPECT_EQ(parse_error(bytes), ParseError::BufferTooShort);
}

TEST(Parser, RDataLengthMustMatchContent) {
    // A with 5 bytes
    auto a = Packet{}.header(0, 1).u8(0).rr(1, 5).u32(0x01020304).u8(0).bytes;
    EXPECT_EQ(parse_error(a), ParseError::RDataLengthMismatch);

    // AAAA with 4 bytes
    auto aaaa = Packet{}.header(0, 1).u8(0).rr(28, 4).u32(0).bytes;
    EXPECT_EQ(parse_error(aaaa), ParseError::RDataLengthMismatch);

    // CNAME whose name (13 bytes) is shorter than rdlength
    auto cname = Packet{}.header(0, 1).u8(0).rr(5, 15).name("example.com").u16(0).bytes;
    EXPECT_EQ(parse_error(cname), ParseError::RDataLengthMismatch);

    // MX with only a preference
    auto mx = Packet{}.header(0, 1).u8(0).rr(15, 1).u8(0).bytes;
    EXPECT_EQ(parse_error(mx), ParseError::RDataLengthMismatch);

    // SOA missing one of its five integers
    auto soa = Packet{}.header(0, 1).u8(0).rr(6, 18).u8(0).u8(0)
                   .u32(1).u32(2).u32(3).u32(4).bytes;
    EXPECT_EQ(parse_error(soa), ParseError::RDataLengthMismatch);
}

TEST(Parser, TxtStrings) {
    auto bytes = Packet{}.header(0, 1).u8(0).rr(16, 9)
                     .u8(3).raw("abc").u8(0).u8(3).raw("xyz").bytes;
    Message m = must_parse(bytes);
    ASSERT_EQ(m.answers.size(), 1u);
    EXPECT_EQ(std::get<RDataTXT>(m.answers[0].rdata).strings,
              (std::vector<std::string>{"abc", "", "xyz"}));

    auto overrun = Packet{}.header(0, 1).u8(0).rr(16, 4).u8(5).raw("abc").bytes;
    EXPECT_EQ(parse_error(overrun), ParseError::MalformedRData);
}

TEST(Parser, UnknownTypeKeptRaw) {
    auto bytes = Packet{}.header(0, 1).u8(0).rr(99, 3).raw("\x01\x02\x03").bytes;
    Message m = must_parse(bytes);
    ASSERT_EQ(m.answers.size(), 1u);
    EXPECT_EQ(static_cast<uint16_t>(m.answers[0].type), 99);
    EXPECT_EQ(std::get<RDataRaw>(m.answers[0].rdata).data, (std::vector<uint8_t>{1, 2, 3}));
}

TEST(Parser, NonInternetAIsKeptRaw) {
    // A-record RDATA layout is class-specific; CHAOS A is not 4 bytes.
    auto bytes = Packet{}.header(0, 1).u8(0).rr(1, 6, /*cls=*/3).raw("abcdef").bytes;
    Message m = must_parse(bytes);
    EXPECT_TRUE(std::holds_alternative<RDataRaw>(m.answers.at(0).rdata));
}

TEST(Parser, TtlWithHighBitIsZero) {
    auto bytes = Packet{}.header(0, 1).u8(0).rr(1, 4, 1, 0x80000001).u32(0).bytes;
    EXPECT_EQ(must_parse(bytes).answers.at(0).ttl, 0u);
}

// ─── OPT / EDNS ─────────────────────────────────────────────────────────────

TEST(Parser, OptBecomesEdnsInfo) {
    // class = 4096, ttl = ext-rcode 1 | version 0 | DO
    auto bytes = Packet{}.header(1, 0, 0, 1).name("example.com").u16(1).u16(1)
                     .u8(0).rr(41, 0, 4096, 0x01008000).bytes;
    Message m = must_parse(bytes);
    ASSERT_TRUE(m.edns.has_value());
    EXPECT_EQ(*m.edns, (EdnsInfo{4096, 1, 0, true}));
    EXPECT_TRUE(m.additional.empty());
}

TEST(Parser, RejectsMisplacedOrDuplicateOpt) {
    auto opt = [](Packet& p) -> Packet& { return p.u8(0).rr(41, 0, 1232); };

    Packet in_answer;
    in_answer.header(0, 1);
    opt(in_answer);
    EXPECT_EQ(parse_error(in_answer.bytes), ParseError::InvalidOpt);

    Packet duplicate;
    duplicate.header(0, 0, 0, 2);
    opt(opt(duplicate));
    EXPECT_EQ(parse_error(duplicate.bytes), ParseError::InvalidOpt);

    auto non_root = Packet{}.header(0, 0, 0, 1).name("example.com").rr(41, 0, 1232).bytes;
    EXPECT_EQ(parse_error(non_root), ParseError::InvalidOpt);
}

TEST(Parser, OptOptionsAreValidated) {
    // One well-formed option (code 10, 8 bytes), then one that overruns.
    auto good = Packet{}.header(0, 0, 0, 1).u8(0).rr(41, 12, 1232)
                    .u16(10).u16(8).raw("12345678").bytes;
    EXPECT_TRUE(parse(good).has_value());

    auto bad = Packet{}.header(0, 0, 0, 1).u8(0).rr(41, 6, 1232)
                   .u16(10).u16(8).raw("12").bytes;
    EXPECT_EQ(parse_error(bad), ParseError::MalformedRData);
}

TEST(Parser, ErrorStringsAreDistinct) {
    std::set<std::string> seen;
    for (int e = 0; e <= static_cast<int>(ParseError::InvalidOpt); ++e) {
        seen.insert(parse_error_to_string(static_cast<ParseError>(e)));
    }
    EXPECT_EQ(seen.size(), static_cast<size_t>(ParseError::InvalidOpt) + 1);
}
