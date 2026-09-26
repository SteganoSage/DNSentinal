/// @file net/event_loop.cpp
/// epoll-based event loop.

#include "dnsentinel/net/event_loop.h"

#include <sys/eventfd.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <climits>
#include <cstdlib>

namespace dnsentinel::net {

namespace {

constexpr uint64_t kWakeToken      = 0;
constexpr int      kMaxEventsPerWait = 64;

std::error_code last_error() { return {errno, std::system_category()}; }

}  // namespace

std::expected<std::unique_ptr<EventLoop>, std::error_code> EventLoop::create() {
    int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd < 0) return std::unexpected(last_error());

    int wake_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (wake_fd < 0) {
        auto err = last_error();
        close(epoll_fd);
        return std::unexpected(err);
    }

    epoll_event ev{};
    ev.events   = EPOLLIN;
    ev.data.u64 = kWakeToken;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, wake_fd, &ev) < 0) {
        auto err = last_error();
        close(wake_fd);
        close(epoll_fd);
        return std::unexpected(err);
    }
    return std::unique_ptr<EventLoop>(new EventLoop(epoll_fd, wake_fd));
}

EventLoop::EventLoop(int epoll_fd, int wake_fd) : epoll_fd_(epoll_fd), wake_fd_(wake_fd) {}

EventLoop::~EventLoop() {
    close(wake_fd_);
    close(epoll_fd_);
}

void EventLoop::run() {
    while (!stop_requested_.load(std::memory_order_acquire)) {
        dispatch_io(next_timeout_ms());
        run_due_timers();
    }
    stop_requested_.store(false, std::memory_order_release);
}

void EventLoop::stop() {
    // Both operations are async-signal-safe.
    stop_requested_.store(true, std::memory_order_release);
    uint64_t one = 1;
    [[maybe_unused]] ssize_t n = write(wake_fd_, &one, sizeof one);  // EAGAIN: already awake
}

std::error_code EventLoop::add_fd(int fd, uint32_t events, IoCallback cb) {
    if (tokens_.contains(fd)) return std::make_error_code(std::errc::file_exists);

    const uint64_t token = next_token_++;
    epoll_event ev{};
    ev.events   = events;
    ev.data.u64 = token;
    if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, fd, &ev) < 0) return last_error();

    watches_.emplace(token, std::make_shared<Watch>(fd, std::move(cb)));
    tokens_.emplace(fd, token);
    return {};
}

std::error_code EventLoop::modify_fd(int fd, uint32_t events) {
    auto it = tokens_.find(fd);
    if (it == tokens_.end()) return std::make_error_code(std::errc::no_such_file_or_directory);

    epoll_event ev{};
    ev.events   = events;
    ev.data.u64 = it->second;
    if (epoll_ctl(epoll_fd_, EPOLL_CTL_MOD, fd, &ev) < 0) return last_error();
    return {};
}

void EventLoop::remove_fd(int fd) {
    auto it = tokens_.find(fd);
    if (it == tokens_.end()) return;
    // Fails harmlessly if the fd was already closed: closing deregisters it.
    epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, nullptr);
    watches_.erase(it->second);
    tokens_.erase(it);
}

EventLoop::TimerId EventLoop::add_timer(Clock::duration delay, TimerCallback cb) {
    const TimerId id       = next_timer_id_++;
    const auto    deadline = Clock::now() + delay;
    timers_.emplace(TimerKey{deadline, id}, std::move(cb));
    timer_deadlines_.emplace(id, deadline);
    return id;
}

bool EventLoop::cancel_timer(TimerId id) {
    auto it = timer_deadlines_.find(id);
    if (it == timer_deadlines_.end()) return false;
    timers_.erase(TimerKey{it->second, id});
    timer_deadlines_.erase(it);
    return true;
}

int EventLoop::next_timeout_ms() const {
    if (timers_.empty()) return -1;  // block until I/O or stop()
    const auto delay = timers_.begin()->first.first - Clock::now();
    if (delay <= Clock::duration::zero()) return 0;
    // Round up: waking before the deadline would just spin until it passes.
    const auto ms = std::chrono::ceil<std::chrono::milliseconds>(delay).count();
    return static_cast<int>(std::min<int64_t>(ms, INT_MAX));
}

void EventLoop::dispatch_io(int timeout_ms) {
    std::array<epoll_event, kMaxEventsPerWait> events;
    const int n = epoll_wait(epoll_fd_, events.data(), kMaxEventsPerWait, timeout_ms);
    if (n < 0) {
        // EINTR (a signal arrived) is the only error possible with a valid
        // epoll fd and buffer; anything else means memory corruption.
        if (errno == EINTR) return;
        std::abort();
    }

    for (int i = 0; i < n; ++i) {
        const uint64_t token = events[i].data.u64;
        if (token == kWakeToken) {
            uint64_t count;
            [[maybe_unused]] ssize_t r = read(wake_fd_, &count, sizeof count);
            continue;
        }
        auto it = watches_.find(token);
        if (it == watches_.end()) continue;  // removed earlier in this batch
        auto watch = it->second;             // keeps the callback alive if it removes itself
        watch->cb(events[i].events);
    }
}

void EventLoop::run_due_timers() {
    const auto    now    = Clock::now();
    const TimerId newest = next_timer_id_;  // timers added below wait for the next iteration

    while (!timers_.empty()) {
        auto it = timers_.begin();
        const auto [deadline, id] = it->first;
        // Map order is (deadline, id), and new timers have deadline >= now,
        // so the first new or not-yet-due entry ends this round.
        if (deadline > now || id >= newest) break;

        TimerCallback cb = std::move(it->second);
        timers_.erase(it);
        timer_deadlines_.erase(id);
        cb();
    }
}

}  // namespace dnsentinel::net
