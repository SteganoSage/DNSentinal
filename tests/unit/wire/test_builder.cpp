#include "dnsentinel/wire/builder.h"

#include "dnsentinel/wire/edns.h"
#include "dnsentinel/wire/parser.h"
#include "wire_test_util.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <span>
#include <string>
#include <vector>

using namespace dnsentinel;
using namespace dnsentinel::wire;
using namespace dnsentinel::test;

namespace {

Message response_for(std::string_view qname, uint16_t qtype = 1) {
    Message m;
    m.header.id = 0x1234;
    m.header.qr = m.header.rd = m.header.ra = true;
    m.questions.push_back({name(qname), qtype, 1});
    return m;
}

Message must_parse(std::span<const uint8_t> bytes) {
    auto m = parse(bytes);
    EXPECT_TRUE(m.has_value()) << parse_error_to_string(m.error());
    return m.value_or(Message{});
}

void add_a_records(std::vector<RR>& section, std::string_view owner, int count) {
    for (int i = 0; i < count; ++i) {
        section.push_back(make_rr(owner, RRType::A, RDataA{static_cast<uint32_t>(i)}));
    }
}

Message every_rdata_type() {
    Message m = response_for("www.example.com");
    m.header.aa = true;
    m.answers = {
        make_rr("www.example.com", RRType::CNAME, RDataCNAME{name("web.example.com")}),
        make_rr("web.example.com", RRType::A, ipv4("192.0.2.1")),
        make_rr("web.example.com", RRType::AAAA, ipv6("2001:db8::1")),
        make_rr("example.com", RRType::MX, RDataMX{10, name("mail.example.com")}),
        make_rr("example.com", RRType::TXT, RDataTXT{{"v=spf1 -all", "", std::string(255, 't')}}),
        make_rr("1.2.0.192.in-addr.arpa", RRType::PTR, RDataPTR{name("web.example.com")}),
    };
    m.authority = {
        make_rr("example.com", RRType::NS, RDataNS{name("ns1.example.com")}),
        make_rr("example.com", RRType::SOA,
                RDataSOA{name("ns1.example.com"), name("hostmaster.example.com"),
                         2024010101, 7200, 3600, 1209600, 300}),
    };
    m.additional = {
        make_rr("ns1.example.com", RRType::A, ipv4("192.0.2.53")),
        make_rr("example.com", static_cast<RRType>(99), RDataRaw{{0xde, 0xad, 0xbe, 0xef}}),
    };
    m.edns = EdnsInfo{.udp_payload_size = 1232, .dnssec_ok = true};
    return m;
}

}  // namespace

// ─── Round trips ────────────────────────────────────────────────────────────

TEST(Builder, RoundTripsEveryRDataType) {
    const Message m = every_rdata_type();
    for (bool compress : {true, false}) {
        auto bytes = build(m, {.max_size = 1232, .compress = compress});
        EXPECT_EQ(must_parse(bytes), with_wire_counts(m)) << "compress=" << compress;
    }
}

TEST(Builder, CompressionShrinksOutput) {
    const Message m = every_rdata_type();
    auto compressed = build(m, {.max_size = 1232, .compress = true});
    auto plain      = build(m, {.max_size = 1232, .compress = false});
    EXPECT_LT(compressed.size(), plain.size());
}

TEST(Builder, EmptyMessageIsJustAHeader) {
    EXPECT_EQ(build(Message{}).size(), 12u);
}

TEST(Builder, HeaderFlagsRoundTrip) {
    bool Header::*flags[] = {&Header::qr, &Header::aa, &Header::tc, &Header::rd,
                             &Header::ra, &Header::ad, &Header::cd};
    for (auto flag : flags) {
        Message m;
        m.header.*flag = true;
        auto h = parse_header(build(m));
        ASSERT_TRUE(h.has_value());
        EXPECT_EQ(*h, m.header);
    }
    Message m;
    m.header.opcode = 15;
    m.header.rcode  = 15;
    auto h = parse_header(build(m));
    ASSERT_TRUE(h.has_value());
    EXPECT_EQ(h->opcode, 15);
    EXPECT_EQ(h->rcode, 15);
}

// ─── Compression ────────────────────────────────────────────────────────────

TEST(Builder, CompressesSuffixes) {
    // The example from the implementation plan: "www.example.com" at offset
    // 12 puts example.com at 16, so "mail.example.com" becomes 04 mail C0 10.
    Message m = response_for("www.example.com");
    m.answers.push_back(make_rr("www.example.com", RRType::CNAME, RDataCNAME{name("mail.example.com")}));

    auto expected = Packet{}.header(1, 1, 0, 0, 0x1234, 0x8180)
                        .name("www.example.com").u16(1).u16(1)
                        .ptr(12).rr(5, 7).u8(4).raw("mail").ptr(16)
                        .bytes;
    EXPECT_EQ(build(m), expected);
}

TEST(Builder, KeepsOriginalCaseForZeroX20) {
    Message m = response_for("wWw.ExAmPlE.cOm");
    m.answers.push_back(make_rr("WWW.EXAMPLE.COM", RRType::A, ipv4("192.0.2.1")));
    auto bytes = build(m);

    auto question = Packet{}.name("wWw.ExAmPlE.cOm").bytes;
    EXPECT_TRUE(std::equal(question.begin(), question.end(), bytes.begin() + 12));
    // The answer owner matches case-insensitively and points at the question.
    EXPECT_EQ(bytes[33], 0xC0);
    EXPECT_EQ(bytes[34], 12);

    Message parsed = must_parse(bytes);
    EXPECT_EQ(parsed.qname().original_case, (std::vector<std::string>{"wWw", "ExAmPlE", "cOm"}));
}

TEST(Builder, NeverPointsPastFourteenBits) {
    // ~19 KB of TXT records, then names first written beyond offset 0x3FFF
    // (unreachable by a pointer) and repeated.
    Message m = response_for("example.com", 16);
    for (int i = 0; i < 70; ++i) {
        m.answers.push_back(make_rr("big.example.com", RRType::TXT, RDataTXT{{std::string(255, 'x')}}));
    }
    m.answers.push_back(make_rr("late.example.org", RRType::A, ipv4("192.0.2.1")));
    m.answers.push_back(make_rr("late.example.org", RRType::A, ipv4("192.0.2.2")));
    m.answers.push_back(make_rr("mx.late.example.org", RRType::MX, RDataMX{1, name("late.example.org")}));

    auto framed = build_tcp(m);
    ASSERT_GT(framed.size(), 0x4000u + 2);
    auto body = std::span<const uint8_t>(framed).subspan(2);
    EXPECT_EQ(must_parse(body), with_wire_counts(m));
}

// ─── Truncation ─────────────────────────────────────────────────────────────

TEST(Builder, TruncatesAtRRsetBoundary) {
    Message m = response_for("small.example.com");
    add_a_records(m.answers, "small.example.com", 10);  // fits
    add_a_records(m.answers, "big.example.com", 40);    // does not

    auto bytes = build(m);
    EXPECT_LE(bytes.size(), 512u);
    Message parsed = must_parse(bytes);
    EXPECT_TRUE(parsed.header.tc);
    ASSERT_EQ(parsed.answers.size(), 10u);
    for (const auto& rr : parsed.answers) EXPECT_EQ(rr.name, name("small.example.com"));
}

TEST(Builder, NeverEmitsPartialRRset) {
    Message m = response_for("example.com");
    add_a_records(m.answers, "example.com", 40);  // ~30 would fit
    Message parsed = must_parse(build(m));
    EXPECT_TRUE(parsed.header.tc);
    EXPECT_TRUE(parsed.answers.empty());
}

TEST(Builder, AuthorityOverflowSetsTC) {
    Message m = response_for("example.com");
    add_a_records(m.authority, "example.com", 40);
    EXPECT_TRUE(must_parse(build(m)).header.tc);
}

TEST(Builder, AdditionalOverflowIsDroppedWithoutTC) {
    // RFC 2181 §9: running out of room for additional data is not truncation.
    Message m = response_for("example.com", 15);
    m.answers.push_back(make_rr("example.com", RRType::MX, RDataMX{10, name("mx.example.com")}));
    add_a_records(m.additional, "mx.example.com", 40);

    Message parsed = must_parse(build(m));
    EXPECT_FALSE(parsed.header.tc);
    EXPECT_EQ(parsed.answers.size(), 1u);
    EXPECT_TRUE(parsed.additional.empty());
}

TEST(Builder, OptSurvivesTruncationAtEverySize) {
    // Sweep answer counts across the 512-byte boundary with the size landing
    // at every possible remainder; OPT must always be present and fit.
    for (int n = 1; n <= 40; ++n) {
        Message m = response_for("example.com");
        m.edns = EdnsInfo{.udp_payload_size = kEdnsUdpPayloadSize};
        for (int i = 0; i < n; ++i) {
            std::string owner = "r" + std::string(static_cast<size_t>(i % 7), 'x') + ".example.com";
            m.answers.push_back(make_rr(owner, RRType::A, RDataA{static_cast<uint32_t>(i)}));
        }
        auto bytes = build(m);
        EXPECT_LE(bytes.size(), 512u) << n;
        Message parsed = must_parse(bytes);
        EXPECT_TRUE(parsed.edns.has_value()) << n;
    }
}

TEST(Builder, LargerLimitAvoidsTruncation) {
    Message m = response_for("example.com");
    add_a_records(m.answers, "example.com", 50);
    Message parsed = must_parse(build(m, {.max_size = kEdnsUdpPayloadSize}));
    EXPECT_FALSE(parsed.header.tc);
    EXPECT_EQ(parsed.answers.size(), 50u);
}

TEST(Builder, LimitsBelow512AreRaised) {
    Message m = response_for("example.com");
    add_a_records(m.answers, "example.com", 20);
    EXPECT_EQ(build(m, {.max_size = 100}), build(m, {.max_size = 512}));
}

TEST(Builder, PreservesCallerTC) {
    Message m = response_for("example.com");
    m.header.tc = true;
    EXPECT_TRUE(must_parse(build(m)).header.tc);
}

// ─── TCP ────────────────────────────────────────────────────────────────────

TEST(Builder, TcpFramingAndNoUdpLimit) {
    Message m = response_for("example.com");
    add_a_records(m.answers, "example.com", 100);

    auto framed = build_tcp(m);
    ASSERT_GE(framed.size(), 2u);
    size_t declared = (size_t{framed[0]} << 8) | framed[1];
    EXPECT_EQ(declared, framed.size() - 2);
    EXPECT_GT(declared, 512u);

    Message parsed = must_parse(std::span<const uint8_t>(framed).subspan(2));
    EXPECT_FALSE(parsed.header.tc);
    EXPECT_EQ(parsed.answers.size(), 100u);
}

// ─── make_response ──────────────────────────────────────────────────────────

TEST(MakeResponse, EchoesQueryIdentity) {
    Message query;
    query.header.id = 0xBEEF;
    query.header.rd = true;
    query.header.cd = true;
    query.questions.push_back({name("wWw.Example.com"), 28, 1});

    Message r = make_response(query, RCode::NXDomain);
    EXPECT_EQ(r.header.id, 0xBEEF);
    EXPECT_TRUE(r.header.qr && r.header.ra && r.header.rd && r.header.cd);
    EXPECT_FALSE(r.header.aa || r.header.tc || r.header.ad);
    EXPECT_EQ(r.header.rcode, static_cast<uint8_t>(RCode::NXDomain));
    EXPECT_EQ(r.questions, query.questions);
    EXPECT_EQ(r.qname().original_case, query.qname().original_case);  // 0x20 echo
    EXPECT_FALSE(r.edns.has_value());
}

TEST(MakeResponse, AnswersEdnsWithOurBufferAndDoBit) {
    Message query;
    query.questions.push_back({name("example.com"), 1, 1});
    query.edns = EdnsInfo{.udp_payload_size = 4096, .dnssec_ok = true};

    Message r = make_response(query);
    ASSERT_TRUE(r.edns.has_value());
    EXPECT_EQ(*r.edns, (EdnsInfo{.udp_payload_size = kEdnsUdpPayloadSize, .dnssec_ok = true}));
}
