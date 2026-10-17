/// @file net/tcp_listener.cpp
/// TCP listener: accept → (TLS) → framing → handler → framing → (TLS) → write.
///
/// Each connection is a small state machine driven by epoll. It stops
/// reading, so the kernel pushes back on the client, while too many of its
/// queries are unanswered, too much of its output is unread, or too much of
/// its input is waiting. It is closed idle_timeout_ms after its last
/// complete query or response, unless we still owe it answers; partial
/// messages (or a TLS handshake that never finishes) don't count, so
/// trickling bytes can't hold a connection open.

#include "dnsentinel/net/tcp_listener.h"

#include "framing.h"
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
constexpr size_t kMaxBuffered         = 128 * 1024;  // unprocessed input before reading pauses
constexpr auto   kAcceptRetry         = std::chrono::milliseconds(100);

std::error_code last_error() { return {errno, std::system_category()}; }

/// What reading or writing a connection's bytes came to, TLS or not.
enum class Io { Ok, WantRead, WantWrite, Closed, Broken, TlsFailed };

struct IoResult {
    Io     status = Io::Ok;
    size_t bytes  = 0;
};

IoResult from_tls(TlsSession::Result r) {
    switch (r.status) {
        case TlsSession::Status::Ok:        return {Io::Ok, r.bytes};
        case TlsSession::Status::WantRead:  return {Io::WantRead, 0};
        case TlsSession::Status::WantWrite: return {Io::WantWrite, 0};
        case TlsSession::Status::Closed:    return {Io::Closed, 0};
        case TlsSession::Status::Error:     return {Io::TlsFailed, 0};
    }
    return {Io::TlsFailed, 0};
}

// ─── DNS framing (RFC 7766 §8) ──────────────────────────────────────────────

class DnsFraming final : public detail::Framing {
public:
    explicit DnsFraming(detail::FramingHost host) : host_(std::move(host)) {}

    void feed(std::span<const uint8_t> bytes) override { in_.insert(in_.end(), bytes.begin(), bytes.end()); }

    bool process(size_t budget) override {
        size_t used = 0;
        bool   ok   = true;
        while (budget > 0 && in_.size() - used >= 2) {
            const size_t length = (size_t{in_[used]} << 8) | in_[used + 1];
            if (in_.size() - used - 2 < length) break;  // the rest hasn't arrived

            auto query = wire::parse(std::span<const uint8_t>(in_.data() + used + 2, length));
            used += 2 + length;
            if (!query || query->header.qr) {
                // A broken or hostile client. Over UDP we stay silent to avoid
                // being an amplifier; here the connection can simply end.
                ok = false;
                break;
            }
            --budget;
            host_.query(std::move(*query), 0);
        }
        in_.erase(in_.begin(), in_.begin() + static_cast<ptrdiff_t>(used));
        return ok;
    }

    void answer(uint64_t, const Message& response) override { host_.send(wire::build_tcp(response)); }

    [[nodiscard]] size_t buffered() const override { return in_.size(); }

private:
    detail::FramingHost  host_;
    std::vector<uint8_t> in_;
};

}  // namespace

std::unique_ptr<detail::Framing> detail::make_dns_framing(FramingHost host) {
    return std::make_unique<DnsFraming>(std::move(host));
}

struct TcpListener::Connection : std::enable_shared_from_this<Connection> {
    uint64_t                         id = 0;
    int                              fd = -1;  // -1 once closed
    sockaddr_storage                 peer{};
    std::string                      client;   // peer IP, for max_per_client
    std::unique_ptr<TlsSession>      tls;      // DoT and DoH only
    std::unique_ptr<detail::Framing> framing;
    std::vector<uint8_t>             out;      // bytes not yet written
    size_t                           pending    = 0;  // queries handed to the handler, not yet answered
    uint64_t                         dispatched = 0;  // queries handed to the handler, ever
    bool                             peer_done  = false;  // the client shut down its side: no more queries
    bool                             processing = false;  // process() is on the stack
    bool                             read_wants_write = false;  // TLS: retry the read once writable
    bool                             write_wants_read = false;  // TLS: retry the write once readable
    uint32_t                         interest   = kReadable;
    EventLoop::TimerId               idle_timer = 0;
    EventLoop::TimerId               kick_timer = 0;  // TLS holds input no socket event will announce

    [[nodiscard]] bool may_read() const {
        return !peer_done && pending < kMaxPipelined && out.size() < kMaxUnsent && framing->buffered() < kMaxBuffered;
    }

    IoResult read(uint8_t* buffer, size_t size) const {
        if (tls) return from_tls(tls->read(buffer, size));
        while (true) {
            const ssize_t n = recv(fd, buffer, size, 0);
            if (n > 0) return {Io::Ok, static_cast<size_t>(n)};
            if (n == 0) return {Io::Closed, 0};
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return {Io::WantRead, 0};
            return {Io::Broken, 0};
        }
    }

    IoResult write(const uint8_t* data, size_t size) const {
        if (tls) return from_tls(tls->write(data, size));
        while (true) {
            const ssize_t n = send(fd, data, size, MSG_NOSIGNAL);
            if (n >= 0) return {Io::Ok, static_cast<size_t>(n)};
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return {Io::WantWrite, 0};
            return {Io::Broken, 0};  // EPIPE, ECONNRESET: the client is gone
        }
    }
};

// ─── Setup and teardown ─────────────────────────────────────────────────────

std::expected<std::unique_ptr<TcpListener>, std::error_code>
TcpListener::create(EventLoop& loop, const TcpListenerConfig& config, QueryHandler handler, StreamOptions options) {
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
        new TcpListener(loop, fd, detail::port_of(bound), config, std::move(handler), std::move(options)));
    TcpListener* self = listener.get();
    if (auto err = loop.add_fd(fd, kReadable, [self](uint32_t) { self->on_acceptable(); })) {
        return std::unexpected(err);
    }
    return listener;
}

TcpListener::TcpListener(EventLoop& loop, int fd, uint16_t port, const TcpListenerConfig& config,
                         QueryHandler handler, StreamOptions options)
    : loop_(loop),
      fd_(fd),
      port_(port),
      config_(config),
      handler_(std::move(handler)),
      options_(std::move(options)),
      transport_(options_.doh_path ? Transport::Doh : options_.tls ? Transport::Dot : Transport::Tcp),
      read_buffer_(kReadChunk) {}

TcpListener::~TcpListener() {
    loop_.remove_fd(fd_);
    ::close(fd_);
    if (accept_retry_) loop_.cancel_timer(accept_retry_);
    for (auto& [id, c] : connections_) {
        loop_.remove_fd(c->fd);
        if (c->tls) c->tls->shutdown();
        ::close(c->fd);
        c->fd = -1;
        if (c->idle_timer) loop_.cancel_timer(c->idle_timer);
        if (c->kick_timer) loop_.cancel_timer(c->kick_timer);
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
        if (options_.tls) c->tls = std::make_unique<TlsSession>(*options_.tls, fd);
        Connection*         raw = c.get();  // the framing lives inside the connection
        detail::FramingHost host{
            .send  = [raw](std::vector<uint8_t> bytes) { raw->out.insert(raw->out.end(), bytes.begin(), bytes.end()); },
            .query = [this, raw](Message query, uint64_t tag) { dispatch(*raw, std::move(query), tag); },
            .stats = &stats_,
        };
        c->framing = options_.doh_path ? detail::make_http_framing(std::move(host), *options_.doh_path)
                                       : detail::make_dns_framing(std::move(host));

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
    if (c.tls) c.tls->shutdown();  // close_notify, best effort
    ::close(c.fd);
    c.fd = -1;
    if (c.idle_timer) loop_.cancel_timer(c.idle_timer);
    if (c.kick_timer) loop_.cancel_timer(c.kick_timer);
    c.idle_timer = c.kick_timer = 0;
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
    if (events & EPOLLIN) {
        if (c->write_wants_read) {
            c->write_wants_read = false;
            flush(c);
        }
        if (c->fd >= 0 && c->may_read()) read_from(c);
    }
    if (c->fd >= 0 && (events & EPOLLOUT)) {
        if (c->read_wants_write) {
            c->read_wants_write = false;
            read_from(c);
        }
        if (c->fd >= 0) flush(c);
    }
    if (c->fd >= 0) update(c);
}

void TcpListener::read_from(const std::shared_ptr<Connection>& c) {
    while (true) {  // never re-entered: read_buffer_ is free to use
        const IoResult r = c->read(read_buffer_.data(), read_buffer_.size());
        if (r.status == Io::Ok) {
            c->framing->feed(std::span(read_buffer_).first(r.bytes));
            // Plain TCP: one chunk per wakeup, level-triggered epoll calls
            // again while more waits. TLS: read on, since what TLS has
            // already decrypted raises no event; update() catches the rest.
            if (!c->tls || !c->may_read()) break;
            continue;
        }
        if (r.status == Io::WantWrite) c->read_wants_write = true;
        if (r.status == Io::Closed) c->peer_done = true;  // update() closes once we owe it nothing
        if (r.status == Io::Broken || r.status == Io::TlsFailed) {
            if (r.status == Io::TlsFailed) ++stats_.tls_failed;
            close(*c);
            return;
        }
        break;  // WantRead, WantWrite, Closed
    }
    process(c);
}

void TcpListener::process(const std::shared_ptr<Connection>& c) {
    // An answer given at once re-enters through respond(); the loop below
    // picks up where that call would have.
    if (c->processing || c->fd < 0) return;
    c->processing = true;
    bool ok = true;
    while (ok && c->fd >= 0 && c->pending < kMaxPipelined) {
        const uint64_t before = c->dispatched;
        ok = c->framing->process(kMaxPipelined - c->pending);
        if (c->dispatched == before) break;  // nothing more to do yet
    }
    c->processing = false;
    if (c->fd < 0) return;
    if (!ok) {
        ++stats_.dropped_malformed;
        close(*c);
        return;
    }
    flush(c);  // the framing may have queued output of its own
}

void TcpListener::dispatch(Connection& c, Message query, uint64_t tag) {
    if (c.fd < 0) return;
    ++stats_.queries;
    ++c.pending;
    ++c.dispatched;
    arm_idle_timer(c);
    handler_(std::move(query), ClientInfo{c.peer, transport_},
             [this, weak = c.weak_from_this(), tag](const Message& response) {
                 if (auto conn = weak.lock()) respond(conn, tag, response);
             });
}

void TcpListener::respond(const std::shared_ptr<Connection>& c, uint64_t tag, const Message& response) {
    if (c->fd < 0) return;
    --c->pending;
    ++stats_.responses_sent;
    c->framing->answer(tag, response);
    flush(c);
    if (c->fd < 0) return;
    process(c);  // whole queries may be waiting behind kMaxPipelined
    if (c->fd >= 0) update(c);
}

void TcpListener::flush(const std::shared_ptr<Connection>& c) {
    size_t sent = 0;
    while (sent < c->out.size()) {
        const IoResult r = c->write(c->out.data() + sent, c->out.size() - sent);
        if (r.status == Io::Ok) {
            sent += r.bytes;
            continue;
        }
        if (r.status == Io::WantWrite) break;  // update() watches for writable
        if (r.status == Io::WantRead) {
            c->write_wants_read = true;
            break;
        }
        if (r.status == Io::TlsFailed) ++stats_.tls_failed;
        close(*c);  // the client is gone
        return;
    }
    if (sent > 0) {
        c->out.erase(c->out.begin(), c->out.begin() + static_cast<ptrdiff_t>(sent));
        arm_idle_timer(*c);  // the client is still taking our answers
    }
}

/// Close the connection once it's done; otherwise watch for what it needs.
void TcpListener::update(const std::shared_ptr<Connection>& c) {
    if ((c->peer_done || c->framing->done()) && c->pending == 0 && c->out.empty()) {
        close(*c);
        return;
    }
    uint32_t want = 0;
    if (c->may_read() || c->write_wants_read) want |= kReadable;
    if (!c->out.empty() || c->read_wants_write) want |= kWritable;
    if (want != c->interest && !loop_.modify_fd(c->fd, want)) c->interest = want;

    // Input TLS has already decrypted raises no socket event: go and get it.
    if (c->tls && c->may_read() && c->tls->has_buffered() && !c->kick_timer) {
        const uint64_t id = c->id;
        c->kick_timer     = loop_.add_timer(std::chrono::milliseconds(0), [this, id] {
            auto it = connections_.find(id);
            if (it == connections_.end()) return;
            it->second->kick_timer = 0;
            on_event(id, EPOLLIN);
        });
    }
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
