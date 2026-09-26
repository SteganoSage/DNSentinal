#include "dnsentinel/net/event_loop.h"

#include <gtest/gtest.h>

#include <fcntl.h>
#include <unistd.h>

#include <chrono>
#include <functional>
#include <optional>
#include <thread>
#include <vector>

using namespace dnsentinel::net;
using namespace std::chrono_literals;
using Clock = EventLoop::Clock;

namespace {

/// A non-blocking pipe, closed on destruction.
struct Pipe {
    int read_fd  = -1;
    int write_fd = -1;

    Pipe() {
        int fds[2];
        if (pipe2(fds, O_NONBLOCK | O_CLOEXEC) == 0) {
            read_fd  = fds[0];
            write_fd = fds[1];
        }
    }
    ~Pipe() { close_all(); }
    Pipe(const Pipe&)            = delete;
    Pipe& operator=(const Pipe&) = delete;

    void write_byte() const { ASSERT_EQ(write(write_fd, "x", 1), 1); }
    void close_write() {
        if (write_fd >= 0) close(write_fd);
        write_fd = -1;
    }
    void close_all() {
        close_write();
        if (read_fd >= 0) close(read_fd);
        read_fd = -1;
    }
};

std::unique_ptr<EventLoop> make_loop() { return EventLoop::create().value(); }

/// Runs `loop` until something calls stop(), or `timeout` passes.
/// Returns true if it timed out.
bool run_with_timeout(EventLoop& loop, Clock::duration timeout) {
    bool timed_out = false;
    auto id        = loop.add_timer(timeout, [&] {
        timed_out = true;
        loop.stop();
    });
    loop.run();
    loop.cancel_timer(id);
    return timed_out;
}

}  // namespace

// ─── Timers ─────────────────────────────────────────────────────────────────

TEST(EventLoop, TimersFireInDeadlineOrder) {
    auto loop = make_loop();
    std::vector<int> order;
    loop->add_timer(30ms, [&] {
        order.push_back(4);
        loop->stop();
    });
    loop->add_timer(10ms, [&] { order.push_back(1); });
    loop->add_timer(20ms, [&] { order.push_back(3); });
    loop->add_timer(10ms, [&] { order.push_back(2); });  // same delay: after the first

    const auto start = Clock::now();
    EXPECT_FALSE(run_with_timeout(*loop, 2s));
    EXPECT_EQ(order, (std::vector<int>{1, 2, 3, 4}));
    EXPECT_GE(Clock::now() - start, 30ms);
}

TEST(EventLoop, TimerNeverFiresEarly) {
    auto loop = make_loop();
    const auto added = Clock::now();
    Clock::time_point fired;
    loop->add_timer(15ms, [&] {
        fired = Clock::now();
        loop->stop();
    });
    EXPECT_FALSE(run_with_timeout(*loop, 2s));
    EXPECT_GE(fired - added, 15ms);
}

TEST(EventLoop, CancelledTimerDoesNotFire) {
    auto loop  = make_loop();
    bool fired = false;
    auto id    = loop->add_timer(5ms, [&] { fired = true; });
    EXPECT_TRUE(loop->cancel_timer(id));
    EXPECT_FALSE(loop->cancel_timer(id));
    EXPECT_TRUE(run_with_timeout(*loop, 30ms));
    EXPECT_FALSE(fired);
}

TEST(EventLoop, TimerCanCancelAnotherDueTimer) {
    auto loop = make_loop();
    bool second_fired = false;
    EventLoop::TimerId second = 0;
    loop->add_timer(1ms, [&] { loop->cancel_timer(second); });
    second = loop->add_timer(1ms, [&] { second_fired = true; });
    std::this_thread::sleep_for(10ms);  // both are due on the first iteration
    EXPECT_TRUE(run_with_timeout(*loop, 20ms));
    EXPECT_FALSE(second_fired);
}

TEST(EventLoop, ZeroDelayTimersCannotStarveIo) {
    auto loop = make_loop();
    Pipe p;
    p.write_byte();
    bool io_ran = false;
    int  ticks  = 0;
    std::function<void()> tick = [&] {
        ++ticks;
        if (!io_ran) loop->add_timer(0ms, tick);  // re-arms forever until I/O runs
    };
    loop->add_timer(0ms, tick);
    ASSERT_FALSE(loop->add_fd(p.read_fd, kReadable, [&](uint32_t) {
        io_ran = true;
        loop->stop();
    }));
    EXPECT_FALSE(run_with_timeout(*loop, 2s));
    EXPECT_TRUE(io_ran);
    EXPECT_LE(ticks, 3);
}

// ─── File descriptors ───────────────────────────────────────────────────────

TEST(EventLoop, ReadableCallback) {
    auto loop = make_loop();
    Pipe p;
    uint32_t seen = 0;
    ASSERT_FALSE(loop->add_fd(p.read_fd, kReadable, [&](uint32_t events) {
        seen = events;
        loop->stop();
    }));
    p.write_byte();
    EXPECT_FALSE(run_with_timeout(*loop, 2s));
    EXPECT_TRUE(seen & kReadable);
}

TEST(EventLoop, HangupIsReported) {
    auto loop = make_loop();
    Pipe p;
    uint32_t seen = 0;
    ASSERT_FALSE(loop->add_fd(p.read_fd, kReadable, [&](uint32_t events) {
        seen = events;
        loop->stop();
    }));
    p.close_write();
    EXPECT_FALSE(run_with_timeout(*loop, 2s));
    EXPECT_TRUE(seen & EPOLLHUP);
}

TEST(EventLoop, ModifyFdChangesInterest) {
    auto loop     = make_loop();
    Pipe p;
    int  writable = 0;
    ASSERT_FALSE(loop->add_fd(p.write_fd, kWritable, [&](uint32_t events) {
        ++writable;
        EXPECT_TRUE(events & kWritable);
        EXPECT_FALSE(loop->modify_fd(p.write_fd, 0));  // no more interest
    }));
    EXPECT_TRUE(run_with_timeout(*loop, 30ms));
    EXPECT_EQ(writable, 1);
}

TEST(EventLoop, RegistrationErrors) {
    auto loop = make_loop();
    Pipe p;
    ASSERT_FALSE(loop->add_fd(p.read_fd, kReadable, [](uint32_t) {}));
    EXPECT_EQ(loop->add_fd(p.read_fd, kReadable, [](uint32_t) {}), std::errc::file_exists);
    EXPECT_EQ(loop->add_fd(-1, kReadable, [](uint32_t) {}), std::errc::bad_file_descriptor);
    EXPECT_EQ(loop->modify_fd(p.write_fd, kWritable), std::errc::no_such_file_or_directory);
    loop->remove_fd(p.write_fd);  // unknown fd: no-op
}

TEST(EventLoop, EventsForRemovedFdsAreDiscarded) {
    // Both pipes are readable in the same epoll batch; whichever callback
    // runs first removes the other, so exactly one may run.
    auto loop = make_loop();
    Pipe a, b;
    a.write_byte();
    b.write_byte();
    int runs = 0;
    auto remove_both = [&] {
        ++runs;
        loop->remove_fd(a.read_fd);
        loop->remove_fd(b.read_fd);
    };
    ASSERT_FALSE(loop->add_fd(a.read_fd, kReadable, [&](uint32_t) { remove_both(); }));
    ASSERT_FALSE(loop->add_fd(b.read_fd, kReadable, [&](uint32_t) { remove_both(); }));
    EXPECT_TRUE(run_with_timeout(*loop, 30ms));
    EXPECT_EQ(runs, 1);
}

TEST(EventLoop, StaleEventNeverReachesReusedFdNumber) {
    // The first callback closes the other pipe and opens a new one, which
    // reuses the closed fd number. The closed pipe's pending event must not
    // be delivered to the new registration (it has no data to read).
    auto loop = make_loop();
    Pipe a, b;
    a.write_byte();
    b.write_byte();
    std::optional<Pipe> fresh;
    bool fresh_called = false;
    int  replaced     = 0;

    auto replace = [&](Pipe& self, Pipe& other) {
        ++replaced;
        const int old_fd = other.read_fd;
        loop->remove_fd(other.read_fd);
        other.close_all();
        fresh.emplace();
        EXPECT_EQ(fresh->read_fd, old_fd) << "fd number was not reused; test is weaker";
        EXPECT_FALSE(loop->add_fd(fresh->read_fd, kReadable, [&](uint32_t) { fresh_called = true; }));
        loop->remove_fd(self.read_fd);
    };
    ASSERT_FALSE(loop->add_fd(a.read_fd, kReadable, [&](uint32_t) { replace(a, b); }));
    ASSERT_FALSE(loop->add_fd(b.read_fd, kReadable, [&](uint32_t) { replace(b, a); }));

    EXPECT_TRUE(run_with_timeout(*loop, 30ms));
    EXPECT_EQ(replaced, 1);
    EXPECT_FALSE(fresh_called);
}

// ─── Stopping ───────────────────────────────────────────────────────────────

TEST(EventLoop, StopFromAnotherThreadWakesBlockedLoop) {
    auto loop = make_loop();
    const auto start = Clock::now();
    std::thread stopper([&] {
        std::this_thread::sleep_for(20ms);
        loop->stop();
    });
    const bool timed_out = run_with_timeout(*loop, 5s);
    stopper.join();
    EXPECT_FALSE(timed_out);
    EXPECT_LT(Clock::now() - start, 1s);
}

TEST(EventLoop, StopBeforeRunIsNotLostAndLoopRestarts) {
    auto loop = make_loop();
    loop->stop();
    EXPECT_FALSE(run_with_timeout(*loop, 2s));  // returns right away

    bool fired = false;
    loop->add_timer(5ms, [&] {
        fired = true;
        loop->stop();
    });
    EXPECT_FALSE(run_with_timeout(*loop, 2s));
    EXPECT_TRUE(fired);
}
