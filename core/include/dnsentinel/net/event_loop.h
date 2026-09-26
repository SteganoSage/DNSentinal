#pragma once
/// @file net/event_loop.h
/// Single-threaded epoll event loop with fd callbacks and timers.
///
/// Everything except stop() must be called on the thread running the loop.
/// Callbacks may freely add or remove fds and timers, including their own.

#include <sys/epoll.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <expected>
#include <functional>
#include <map>
#include <memory>
#include <system_error>
#include <unordered_map>
#include <utility>

namespace dnsentinel::net {

/// Interest bits for add_fd/modify_fd. Callbacks receive the raw epoll event
/// mask; EPOLLERR and EPOLLHUP are always reported.
inline constexpr uint32_t kReadable = EPOLLIN;
inline constexpr uint32_t kWritable = EPOLLOUT;

class EventLoop {
public:
    using Clock         = std::chrono::steady_clock;
    using IoCallback    = std::function<void(uint32_t events)>;
    using TimerCallback = std::function<void()>;
    using TimerId       = uint64_t;

    [[nodiscard]] static std::expected<std::unique_ptr<EventLoop>, std::error_code> create();
    ~EventLoop();
    EventLoop(const EventLoop&)            = delete;
    EventLoop& operator=(const EventLoop&) = delete;

    /// Dispatch I/O and timers until stop() is called. A stop() that arrives
    /// before run() is not lost: run() returns immediately. The loop can be
    /// run again afterwards.
    void run();

    /// Make run() return after the current iteration. Safe to call from any
    /// thread and from a signal handler.
    void stop();

    /// Watch `fd` (level-triggered). The loop does not own the fd; call
    /// remove_fd() before closing it.
    [[nodiscard]] std::error_code add_fd(int fd, uint32_t events, IoCallback cb);
    [[nodiscard]] std::error_code modify_fd(int fd, uint32_t events);

    /// Stop watching `fd`. Events already collected for it in the current
    /// iteration are discarded, even if the fd number is reused meanwhile.
    void remove_fd(int fd);

    /// Run `cb` once, `delay` from now. Timers with equal deadlines fire in
    /// the order they were added. A timer added by a callback fires no
    /// earlier than the next iteration, so zero-delay timers can't starve I/O.
    TimerId add_timer(Clock::duration delay, TimerCallback cb);

    /// Returns false if the timer already fired or was cancelled.
    bool cancel_timer(TimerId id);

private:
    EventLoop(int epoll_fd, int wake_fd);

    [[nodiscard]] int next_timeout_ms() const;
    void dispatch_io(int timeout_ms);
    void run_due_timers();

    struct Watch {
        int        fd;
        IoCallback cb;
    };

    int               epoll_fd_;
    int               wake_fd_;  // eventfd written by stop()
    std::atomic<bool> stop_requested_{false};

    // epoll_event.data carries a per-registration token rather than the fd,
    // so a stale event can never reach a newer registration of the same fd.
    uint64_t                                               next_token_ = 1;  // 0 = wake_fd_
    std::unordered_map<uint64_t, std::shared_ptr<Watch>>   watches_;  // token → watch
    std::unordered_map<int, uint64_t>                      tokens_;   // fd → token

    using TimerKey = std::pair<Clock::time_point, TimerId>;
    TimerId                                          next_timer_id_ = 1;
    std::map<TimerKey, TimerCallback>                timers_;  // ordered by deadline, then id
    std::unordered_map<TimerId, Clock::time_point>   timer_deadlines_;
};

}  // namespace dnsentinel::net
