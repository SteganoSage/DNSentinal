/// @file net/tcp_listener.cpp
/// TCP listener: accept → read length-prefixed queries → handler → write
/// length-prefixed responses.
///
/// Each connection is a small state machine driven by epoll. It stops
/// reading, so the kernel pushes back on the client, while too many of its
/// queries are unanswered or too much of its output is unread. It is closed
/// idle_timeout_ms after its last complete query or response, unless we still
/// owe it answers; partial messages don't count, so trickling bytes can't
/// hold a connection open.

#include "dnsentinel/net/tcp_listener.h"

#include "socket_address.h"
#include "dnsentinel/wire/builder.h"
#include "dnsentinel/wire/parser.h"

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <span>
#include <vector>

namespace dnsentinel::net {

namespace {

constexpr int    kBacklog             = 128;
constexpr int    kMaxAcceptsPerWakeup = 64;  // then give other fds a turn
constexpr size_t kReadChunk           = 16 * 1024;
constexpr size_t kMaxPipelined        = 32;          // unanswered queries before reading pauses
constexpr size_t kMaxUnsent           = 256 * 1024;  // unread response bytes before reading pauses
constexpr auto   kAcceptRetry         = std::chrono::milliseconds(100);

std::error_code last_error() { return {errno, std::system_category()}; }

}  // namespace

struct TcpListener::Connection {
    uint64_t             id = 0;
    int                  fd = -1;  // -1 once closed
    sockaddr_storage     peer{};
    std::string          client;   // peer IP, for max_per_client
    std::vector<uint8_t> in;       // received bytes not yet forming a whole message
    std::vector<uint8_t> out;      // framed responses not yet written
    size_t               pending    = 0;      // queries handed to the handler, not yet answered
    bool                 peer_done  = false;  // the client shut down its side: no more queries
    bool                 processing = false;  // process_messages() is on the stack
    uint32_t             interest   = kReadable;
    EventLoop::TimerId   idle_timer = 0;
};

// ─── Setup and teardown ─────────────────────────────────────────────────────

std::expected<std::unique_ptr<TcpListener>, std::error_code>
TcpListener::create(EventLoop& loop, const TcpListenerConfig& config, QueryHandler handler) {
    auto addr = detail::make_address(config.address, config.port);
    if (!addr) return std::unexpected(std::make_error_code(std::errc::invalid_argument));

    const int fd = ::socket(addr->ss_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return std::unexpected(last_error());
    auto fail = [fd] {
        const std::error_code err = last_error();
        ::close(fd);
        return std::unexpected(err);
    };

    const int on     = 1;
    auto      enable = [&](int level, int option) { return setsockopt(fd, level, option, &on, sizeof on) == 0; };
    // SO_REUSEPORT: one listening socket per event loop, as for UDP.
    bool ok = enable(SOL_SOCKET, SO_REUSEADDR) && enable(SOL_SOCKET, SO_REUSEPORT);
    if (addr->ss_family == AF_INET6) ok = ok && enable(IPPROTO_IPV6, IPV6_V6ONLY);
    if (!ok) return fail();
    if (bind(fd, reinterpret_cast<const sockaddr*>(&*addr), detail::address_length(*addr)) < 0) return fail();
    if (listen(fd, kBacklog) < 0) return fail();

    sockaddr_storage bound{};
    socklen_t        bound_len = sizeof bound;
    if (getsockname(fd, reinterpret_cast<sockaddr*>(&bound), &bound_len) < 0) return fail();

    std::unique_ptr<TcpListener> listener(
        new TcpListener(loop, fd, detail::port_of(bound), config, std::move(handler)));
    TcpListener* self = listener.get();
    if (auto err = loop.add_fd(fd, kReadable, [self](uint32_t) { self->on_acceptable(); })) {
        return std::unexpected(err);
    }
    return listener;
}

TcpListener::TcpListener(EventLoop& loop, int fd, uint16_t port, const TcpListenerConfig& config,
                         QueryHandler handler)
    : loop_(loop), fd_(fd), port_(port), config_(config), handler_(std::move(handler)) {}

TcpListener::~TcpListener() {
    loop_.remove_fd(fd_);
    ::close(fd_);
    if (accept_retry_) loop_.cancel_timer(accept_retry_);
    for (auto& [id, c] : connections_) {
        loop_.remove_fd(c->fd);
        ::close(c->fd);
        c->fd = -1;
        if (c->idle_timer) loop_.cancel_timer(c->idle_timer);
    }
    // Responders hold only weak references: they see every connection gone.
}

void TcpListener::on_acceptable() {
    for (int i = 0; i < kMaxAcceptsPerWakeup; ++i) {
        sockaddr_storage peer{};
        socklen_t        len = sizeof peer;
        const int fd = accept4(fd_, reinterpret_cast<sockaddr*>(&peer), &len, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            if (errno == EMFILE || errno == ENFILE || errno == ENOBUFS || errno == ENOMEM) {
                // The connection stays queued and would wake us again at once:
                // stop watching for a moment instead of spinning.
                (void)loop_.modify_fd(fd_, 0);
                accept_retry_ = loop_.add_timer(kAcceptRetry, [this] {
                    accept_retry_ = 0;
                    (void)loop_.modify_fd(fd_, kReadable);
                });
                return;
            }
            continue;  // ECONNABORTED, EINTR, ...: that connection is gone, take the next
        }

        std::string client      = detail::ip_key(peer);
        auto        from_client = per_client_.find(client);
        if (connections_.size() >= config_.max_connections ||
            (from_client != per_client_.end() && from_client->second >= config_.max_per_client)) {
            ++stats_.rejected;
            ::close(fd);
            continue;
        }
        const int on = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on);  // don't hold small answers back

        auto c    = std::make_shared<Connection>();
        c->id     = next_id_++;
        c->fd     = fd;
        c->peer   = peer;
        c->client = std::move(client);
        const uint64_t id = c->id;
        if (loop_.add_fd(fd, kReadable, [this, id](uint32_t events) { on_event(id, events); })) {
            ::close(fd);
            continue;
        }
        ++per_client_[c->client];
        connections_.emplace(id, c);
        ++stats_.accepted;
        arm_idle_timer(*c);
    }
}

void TcpListener::close(Connection& c) {
    loop_.remove_fd(c.fd);
    ::close(c.fd);
    c.fd = -1;
    if (c.idle_timer) loop_.cancel_timer(c.idle_timer);
    c.idle_timer = 0;
    if (auto it = per_client_.find(c.client); it != per_client_.end() && --it->second == 0) per_client_.erase(it);
    const uint64_t id = c.id;
    connections_.erase(id);  // last: may destroy `c`
}

// ─── One connection ─────────────────────────────────────────────────────────

void TcpListener::on_event(uint64_t id, uint32_t events) {
    auto it = connections_.find(id);
    if (it == connections_.end()) return;
    const std::shared_ptr<Connection> c = it->second;  // alive while the handler runs

    if (events & (EPOLLERR | EPOLLHUP)) {  // reset, or both directions closed
        close(*c);
        return;
    }
    if (events & EPOLLIN) read_from(c);
    if (c->fd >= 0 && (events & EPOLLOUT)) flush(c);
    if (c->fd >= 0) update(c);
}

void TcpListener::read_from(const std::shared_ptr<Connection>& c) {
    // One chunk per wakeup: level-triggered epoll calls again while more waits.
    const size_t have = c->in.size();
    c->in.resize(have + kReadChunk);
    ssize_t n;
    do {
        n = recv(c->fd, c->in.data() + have, kReadChunk, 0);
    } while (n < 0 && errno == EINTR);
    c->in.resize(have + static_cast<size_t>(std::max<ssize_t>(n, 0)));

    if (n < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) close(*c);
        return;
    }
    if (n == 0) {
        c->peer_done = true;  // update() closes once we owe it nothing
        return;
    }
    process_messages(c);
}

void TcpListener::process_messages(const std::shared_ptr<Connection>& c) {
    // A handler that answers at once re-enters through respond(); the loop
    // below picks up where that call would have.
    if (c->processing) return;
    c->processing = true;

    size_t used = 0;
    while (c->fd >= 0 && c->pending < kMaxPipelined && c->in.size() - used >= 2) {
        const size_t length = (size_t{c->in[used]} << 8) | c->in[used + 1];
        if (c->in.size() - used - 2 < length) break;  // the rest hasn't arrived

        auto query = wire::parse(std::span<const uint8_t>(c->in.data() + used + 2, length));
        used += 2 + length;
        if (!query || query->header.qr) {
            // A broken or hostile client. Over UDP we stay silent to avoid
            // being an amplifier; here the connection can simply end.
            ++stats_.dropped_malformed;
            close(*c);
            break;
        }

        ++stats_.queries;
        ++c->pending;
        arm_idle_timer(*c);
        handler_(std::move(*query), ClientInfo{c->peer, Transport::Tcp},
                 [this, weak = std::weak_ptr<Connection>(c)](const Message& response) {
                     if (auto conn = weak.lock()) respond(conn, response);
                 });
    }
    if (c->fd >= 0) c->in.erase(c->in.begin(), c->in.begin() + static_cast<ptrdiff_t>(used));
    c->processing = false;
}

void TcpListener::respond(const std::shared_ptr<Connection>& c, const Message& response) {
    if (c->fd < 0) return;
    --c->pending;
    const std::vector<uint8_t> bytes = wire::build_tcp(response);
    c->out.insert(c->out.end(), bytes.begin(), bytes.end());
    ++stats_.responses_sent;

    flush(c);
    if (c->fd < 0) return;
    process_messages(c);  // whole queries may be waiting behind kMaxPipelined
    if (c->fd >= 0) update(c);
}

void TcpListener::flush(const std::shared_ptr<Connection>& c) {
    size_t sent = 0;
    while (sent < c->out.size()) {
        const ssize_t n = send(c->fd, c->out.data() + sent, c->out.size() - sent, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;  // update() watches for writable
            close(*c);  // EPIPE, ECONNRESET: the client is gone
            return;
        }
        sent += static_cast<size_t>(n);
    }
    if (sent > 0) {
        c->out.erase(c->out.begin(), c->out.begin() + static_cast<ptrdiff_t>(sent));
        arm_idle_timer(*c);  // the client is still taking our answers
    }
}

/// Close the connection once it's done; otherwise watch for what it needs.
void TcpListener::update(const std::shared_ptr<Connection>& c) {
    if (c->peer_done && c->pending == 0 && c->out.empty()) {
        close(*c);
        return;
    }
    uint32_t want = 0;
    if (!c->peer_done && c->pending < kMaxPipelined && c->out.size() < kMaxUnsent) want |= kReadable;
    if (!c->out.empty()) want |= kWritable;
    if (want != c->interest && !loop_.modify_fd(c->fd, want)) c->interest = want;
}

void TcpListener::arm_idle_timer(Connection& c) {
    if (c.idle_timer) loop_.cancel_timer(c.idle_timer);
    const uint64_t id = c.id;
    c.idle_timer = loop_.add_timer(std::chrono::milliseconds(config_.idle_timeout_ms), [this, id] {
        auto it = connections_.find(id);
        if (it == connections_.end()) return;
        const std::shared_ptr<Connection> conn = it->second;
        conn->idle_timer = 0;
        if (conn->pending > 0) {  // still resolving: we are the slow one
            arm_idle_timer(*conn);
            return;
        }
        ++stats_.idle_closed;
        close(*conn);
    });
}

}  // namespace dnsentinel::net
