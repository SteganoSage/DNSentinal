/// @file fuzz/fuzz_parser.cpp
/// libFuzzer target for the wire parser.
///
/// Besides "never crash or hang", it checks that anything the parser accepts
/// can be rebuilt and re-parsed, and that rebuilding loses records only
/// through truncation.
///
/// Build (clang 19+: clang 18 can't see std::expected in GCC 13's libstdc++):
///   sudo apt install clang-19 libclang-rt-19-dev
///   cmake -S . -B build/fuzz -DCMAKE_C_COMPILER=clang-19 -DCMAKE_CXX_COMPILER=clang++-19 \
///         -DDNSENTINEL_ENABLE_FUZZ=ON -DDNSENTINEL_ENABLE_TESTS=OFF
///   cmake --build build/fuzz --target fuzz_parser
/// Run (new inputs go to corpus/, crashes to crashes/; seeds/ is read-only):
///   mkdir -p tests/fuzz/corpus tests/fuzz/crashes
///   build/fuzz/fuzz_parser tests/fuzz/corpus tests/fuzz/seeds \
///       -artifact_prefix=tests/fuzz/crashes/ -max_len=4096 -timeout=2 \
///       -fork=8 -max_total_time=600
/// Replay one input (e.g. a crash) with: build/fuzz/fuzz_parser <file>

#include "dnsentinel/wire/builder.h"
#include "dnsentinel/wire/parser.h"

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <span>
#include <vector>

using namespace dnsentinel;
using namespace dnsentinel::wire;

namespace {

void check(bool ok) {
    if (!ok) std::abort();
}

template <typename T>
bool is_prefix(const std::vector<T>& part, const std::vector<T>& whole) {
    return part.size() <= whole.size() && std::equal(part.begin(), part.end(), whole.begin());
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    auto msg = parse(std::span<const uint8_t>(data, size));
    if (!msg) return 0;

    // UDP: the size limit always holds.
    auto udp = build(*msg);
    check(udp.size() <= 512);
    check(parse(udp).has_value());

    // TCP: everything should survive unless the 64 KB limit forced truncation.
    auto tcp = build_tcp(*msg);
    auto again = parse(std::span<const uint8_t>(tcp).subspan(2));
    check(again.has_value());

    Header expected = msg->header;
    Header actual   = again->header;
    const bool newly_truncated = actual.tc && !expected.tc;
    expected.tc = actual.tc;
    expected.qdcount = actual.qdcount;
    expected.ancount = actual.ancount;
    expected.nscount = actual.nscount;
    expected.arcount = actual.arcount;
    check(actual == expected);
    check(again->edns == msg->edns);

    check(is_prefix(again->questions, msg->questions));
    check(is_prefix(again->answers, msg->answers));
    check(is_prefix(again->authority, msg->authority));
    check(is_prefix(again->additional, msg->additional));  // may drop without TC
    if (!newly_truncated) {
        check(again->questions == msg->questions);
        check(again->answers == msg->answers);
        check(again->authority == msg->authority);
    }
    return 0;
}
