#include "dnsentinel/security/zero_x20.h"

#include "../wire/wire_test_util.h"

#include <gtest/gtest.h>

#include <string>

using namespace dnsentinel;
using namespace dnsentinel::security;
using namespace dnsentinel::test;

namespace {

bool is_upper(char c) { return c >= 'A' && c <= 'Z'; }
bool is_lower(char c) { return c >= 'a' && c <= 'z'; }

}  // namespace

TEST(ZeroX20, OnlyLetterCaseChanges) {
    const Name original = name("Www.Ex-4mple.com");
    for (int i = 0; i < 50; ++i) {
        Name r = randomize_case(original);
        EXPECT_EQ(r, original);  // still the same name
        EXPECT_EQ(r.labels, original.labels);
        ASSERT_EQ(r.original_case.size(), original.labels.size());
        for (size_t l = 0; l < r.labels.size(); ++l) {
            ASSERT_EQ(r.original_case[l].size(), r.labels[l].size());
            for (size_t c = 0; c < r.labels[l].size(); ++c) {
                const char canonical = r.labels[l][c];
                const char written   = r.original_case[l][c];
                if (is_lower(canonical)) {
                    EXPECT_TRUE(written == canonical || written == canonical - 'a' + 'A');
                } else {
                    EXPECT_EQ(written, canonical);  // '-' and '4' never change
                }
            }
        }
    }
}

TEST(ZeroX20, NonAsciiBytesAreLeftAlone) {
    Name n;
    n.append_label(std::string("\xC9\x00z", 3));
    Name r = randomize_case(n);
    EXPECT_EQ(r.original_case[0][0], '\xC9');
    EXPECT_EQ(r.original_case[0][1], '\x00');
}

TEST(ZeroX20, EveryLetterTakesBothCases) {
    // Each position is a fair coin: in 64 tries it lands both ways
    // (chance of a false failure per position: 2^-63).
    const Name n = name("abcdefghijklmnopqrstuvwxyz.abcdefghij");
    std::vector<std::vector<bool>> upper(2), lower(2);
    for (size_t l = 0; l < 2; ++l) {
        upper[l].assign(n.labels[l].size(), false);
        lower[l].assign(n.labels[l].size(), false);
    }
    for (int i = 0; i < 64; ++i) {
        Name r = randomize_case(n);
        for (size_t l = 0; l < 2; ++l) {
            for (size_t c = 0; c < r.original_case[l].size(); ++c) {
                upper[l][c] = upper[l][c] || is_upper(r.original_case[l][c]);
                lower[l][c] = lower[l][c] || is_lower(r.original_case[l][c]);
            }
        }
    }
    for (size_t l = 0; l < 2; ++l) {
        for (size_t c = 0; c < upper[l].size(); ++c) {
            EXPECT_TRUE(upper[l][c] && lower[l][c]) << "label " << l << " char " << c;
        }
    }
}

TEST(ZeroX20, EntropyIsOneBitPerLetter) {
    EXPECT_EQ(case_entropy_bits(name("www.example.com")), 13u);
    EXPECT_EQ(case_entropy_bits(name("a1-b2.c3")), 3u);
    EXPECT_EQ(case_entropy_bits(name(".")), 0u);
}

TEST(ZeroX20, SameCaseComparesExactly) {
    EXPECT_TRUE(same_case(name("wWw.ExAmPlE.com"), name("wWw.ExAmPlE.com")));
    EXPECT_FALSE(same_case(name("wWw.ExAmPlE.com"), name("www.example.com")));  // equal names, different case
    EXPECT_FALSE(same_case(name("www.example.com"), name("www.example.org")));
}
