#include "dnsentinel/resolver/server_selection.h"

#include <gtest/gtest.h>

#include <deque>
#include <vector>

using namespace dnsentinel::resolver;
using namespace std::chrono_literals;
using Address = ServerSelection::Address;
using std::chrono::microseconds;

namespace {

constexpr Address A = 1, B = 2, C = 3;

/// Selection with a clock and a random source the test controls.
class ServerSelectionTest : public ::testing::Test {
protected:
    ServerSelection::Clock::time_point now = ServerSelection::Clock::time_point{} + 24h;
    std::deque<uint32_t>               rolls;  // next random results; when empty, n - 1
    std::vector<uint32_t>              asked;  // the n of every random draw

    ServerSelection make(uint32_t explore_one_in = 0) {
        return ServerSelection(
            explore_one_in, [this] { return now; },
            [this](uint32_t n) {
                asked.push_back(n);
                uint32_t roll = n - 1;
                if (!rolls.empty()) {
                    roll = rolls.front() % n;
                    rolls.pop_front();
                }
                return roll;
            });
    }
};

}  // namespace

TEST_F(ServerSelectionTest, UnmeasuredServersTieAndOneIsDrawnAtRandom) {
    auto sel = make();
    rolls    = {1};
    EXPECT_EQ(sel.pick(std::vector<Address>{A, B, C}), B);
    EXPECT_EQ(asked, (std::vector<uint32_t>{3}));
}

TEST_F(ServerSelectionTest, FastestMeasuredServerWins) {
    auto sel = make();
    sel.record_answer(A, 50ms);
    sel.record_answer(B, 10ms);
    sel.record_answer(C, 30ms);
    EXPECT_EQ(sel.pick(std::vector<Address>{A, B, C}), B);
}

TEST_F(ServerSelectionTest, UnmeasuredServerBeatsSlowOnesButNotFastOnes) {
    auto sel = make();
    sel.record_answer(A, 500ms);
    EXPECT_EQ(sel.pick(std::vector<Address>{A, B}), B);  // B is assumed to take 400 ms
    sel.record_answer(C, 20ms);
    EXPECT_EQ(sel.pick(std::vector<Address>{B, C}), C);
}

TEST_F(ServerSelectionTest, FirstSampleIsTakenAsIsThenSmoothed) {
    auto sel = make();
    sel.record_answer(A, 100ms);
    auto info = sel.info(A);
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->srtt, 100ms);
    EXPECT_EQ(info->rttvar, 50ms);

    sel.record_answer(A, 20ms);
    info = sel.info(A);
    EXPECT_EQ(info->rttvar, microseconds(57'500));  // 3/4 * 50 + 1/4 * |100 - 20|
    EXPECT_EQ(info->srtt, 90ms);                    // 7/8 * 100 + 1/8 * 20
}

TEST_F(ServerSelectionTest, TcpAnswersResetFailuresButAreNotSamples) {
    auto sel = make();
    sel.record_unusable(A);
    sel.record_answer(A, std::nullopt);
    auto info = sel.info(A);
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->failures, 0u);
    EXPECT_FALSE(info->measured);
}

TEST_F(ServerSelectionTest, TimeoutAddsAPenaltyUpToACap) {
    auto sel = make();
    sel.record_answer(A, 10ms);
    sel.record_failure(A);
    EXPECT_EQ(sel.info(A)->srtt, 2010ms);
    EXPECT_EQ(sel.info(A)->failures, 1u);
    EXPECT_EQ(sel.pick(std::vector<Address>{A, B}), B);

    sel.record_failure(C);  // never measured: counts from the 400 ms guess
    EXPECT_EQ(sel.info(C)->srtt, 2400ms);
    for (int i = 0; i < 5; ++i) sel.record_failure(C);
    EXPECT_EQ(sel.info(C)->srtt, ServerSelection::kMaxSrtt);
}

TEST_F(ServerSelectionTest, FiveFailuresInARowDeprioritise) {
    auto sel = make();
    sel.record_answer(B, 1s);  // slow, but it works
    for (int i = 0; i < 4; ++i) sel.record_unusable(A);
    EXPECT_EQ(sel.pick(std::vector<Address>{A, B}), A);  // still the 400 ms guess
    sel.record_unusable(A);
    EXPECT_EQ(sel.pick(std::vector<Address>{A, B}), B);
    sel.record_answer(A, std::nullopt);  // a good answer ends the streak
    EXPECT_EQ(sel.pick(std::vector<Address>{A, B}), A);
}

TEST_F(ServerSelectionTest, ExploresARandomServerOnceInN) {
    auto sel = make(20);
    sel.record_answer(A, 10ms);
    sel.record_answer(B, 500ms);

    rolls = {0, 1};  // explore, and draw the second candidate
    EXPECT_EQ(sel.pick(std::vector<Address>{A, B}), B);
    EXPECT_EQ(asked, (std::vector<uint32_t>{20, 2}));

    rolls = {5};  // don't explore
    EXPECT_EQ(sel.pick(std::vector<Address>{A, B}), A);

    asked.clear();
    EXPECT_EQ(sel.pick(std::vector<Address>{B}), B);  // nothing to choose from: no draws
    EXPECT_TRUE(asked.empty());
}

TEST_F(ServerSelectionTest, TimeoutIsSrttPlusFourDeviationsWithinBounds) {
    auto sel = make();
    sel.record_answer(A, 100ms);  // srtt 100, rttvar 50
    EXPECT_EQ(sel.timeout(A, 800ms), 300ms);
    EXPECT_EQ(sel.timeout(A, 200ms), 200ms);  // never above the ceiling
    EXPECT_EQ(sel.timeout(B, 800ms), 800ms);  // unmeasured: the ceiling

    sel.record_answer(C, 1ms);
    EXPECT_EQ(sel.timeout(C, 800ms), ServerSelection::kMinTimeout);  // floor, against jitter
    EXPECT_EQ(sel.timeout(C, 50ms), 50ms);                           // unless the ceiling is lower

    sel.record_failure(B);  // penalised: 2.4 s
    EXPECT_EQ(sel.timeout(B, 800ms), 800ms);
}

TEST_F(ServerSelectionTest, ServersAreForgottenAfterFifteenIdleMinutes) {
    auto sel = make();
    sel.record_answer(A, 10ms);
    sel.record_failure(B);
    now += 16min;
    EXPECT_FALSE(sel.info(A).has_value());
    EXPECT_EQ(sel.timeout(B, 800ms), 800ms);

    sel.record_answer(A, 50ms);  // measured afresh, not smoothed with the old 10 ms
    EXPECT_EQ(sel.info(A)->srtt, 50ms);
}

TEST_F(ServerSelectionTest, ForgottenServersArePruned) {
    auto sel = make();
    for (Address a = 1000; a < 2000; ++a) sel.record_answer(a, 10ms);
    EXPECT_EQ(sel.size(), 1000u);
    now += 16min;
    for (Address a = 5000; a < 5024; ++a) sel.record_answer(a, 10ms);  // the 1024th update sweeps
    EXPECT_EQ(sel.size(), 24u);
}
