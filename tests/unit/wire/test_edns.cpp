#include "dnsentinel/wire/edns.h"

#include "wire_test_util.h"

#include <gtest/gtest.h>

using namespace dnsentinel;
using namespace dnsentinel::wire;
using namespace dnsentinel::test;

TEST(Edns, DecodesOptFields) {
    // TTL: extended-rcode 1 | version 0 | DO
    auto info = parse_opt(4096, 0x01008000, {});
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->udp_payload_size, 4096);
    EXPECT_EQ(info->extended_rcode, 1);
    EXPECT_EQ(info->version, 0);
    EXPECT_TRUE(info->dnssec_ok);

    // Non-zero version is reported, not rejected: the caller answers BADVERS.
    EXPECT_EQ(parse_opt(1232, 0x00010000, {})->version, 1);
}

TEST(Edns, ValidatesOptionFraming) {
    auto good = Packet{}.u16(10).u16(8).raw("12345678").u16(12).u16(0).bytes;
    EXPECT_TRUE(parse_opt(1232, 0, good).has_value());

    auto short_header = Packet{}.u16(10).u8(0).bytes;
    EXPECT_EQ(parse_opt(1232, 0, short_header).error(), ParseError::MalformedRData);

    auto overrun = Packet{}.u16(10).u16(8).raw("1234").bytes;
    EXPECT_EQ(parse_opt(1232, 0, overrun).error(), ParseError::MalformedRData);
}

TEST(Edns, WriteOptRoundTrips) {
    const EdnsInfo edns{.udp_payload_size = 1232, .extended_rcode = 1, .version = 0, .dnssec_ok = true};
    std::vector<uint8_t> out;
    write_opt(out, edns);
    ASSERT_EQ(out.size(), kOptRecordSize);

    auto expected = Packet{}.u8(0).rr(41, 0, 1232, 0x01008000).bytes;
    EXPECT_EQ(out, expected);
    EXPECT_EQ(parse_opt(1232, 0x01008000, {}).value(), edns);
}

TEST(Edns, ResponseSizeLimit) {
    auto with_size = [](uint16_t size) { return std::optional(EdnsInfo{.udp_payload_size = size}); };

    EXPECT_EQ(max_udp_response_size(std::nullopt), 512);
    EXPECT_EQ(max_udp_response_size(with_size(4096)), 1232);  // capped at our buffer
    EXPECT_EQ(max_udp_response_size(with_size(800)), 800);
    EXPECT_EQ(max_udp_response_size(with_size(100)), 512);    // RFC 6891 §6.2.5
    EXPECT_EQ(max_udp_response_size(with_size(4096), 4096), 4096);
    EXPECT_EQ(max_udp_response_size(with_size(4096), 256), 512);
}
