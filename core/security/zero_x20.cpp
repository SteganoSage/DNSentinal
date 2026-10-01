/// @file security/zero_x20.cpp
/// Random letter case for query names, and exact-case comparison.

#include "dnsentinel/security/zero_x20.h"

#include <cstdint>
#include <cstdlib>

namespace dnsentinel::security {

namespace {

bool is_letter(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }

/// Labels in the case they would be written on the wire.
const std::vector<std::string>& as_written(const Name& n) {
    return n.original_case.size() == n.labels.size() ? n.original_case : n.labels;
}

}  // namespace

Name randomize_case(const Name& name) {
    Name out = name;
    out.original_case = name.labels;  // start from lower case, then flip
    uint32_t bits = 0;
    int      left = 0;
    for (auto& label : out.original_case) {
        for (char& c : label) {
            if (!is_letter(c)) continue;
            if (left == 0) {
                bits = arc4random();  // CSPRNG, like the transaction ID
                left = 32;
            }
            if (bits & 1) c = static_cast<char>(c - 'a' + 'A');  // labels are lower case
            bits >>= 1;
            --left;
        }
    }
    return out;
}

size_t case_entropy_bits(const Name& name) {
    size_t letters = 0;
    for (const auto& label : name.labels) {
        for (char c : label) letters += is_letter(c);
    }
    return letters;
}

bool same_case(const Name& a, const Name& b) { return as_written(a) == as_written(b); }

}  // namespace dnsentinel::security
