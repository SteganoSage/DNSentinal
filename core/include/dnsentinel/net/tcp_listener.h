#pragma once
/// @file net/tcp_listener.h
/// DNS over TCP (RFC 7766), and over TLS on top of it (DoT, RFC 7858):
/// every message is preceded by a 2-byte length. Clients may pipeline
/// queries on one connection; each response goes back as soon as it is
/// ready, possibly out of order (clients match them by ID). Clients retry
/// here when a UDP response came back truncated (TC).
///
/// The same listener serves DNS over HTTPS (DoH, RFC 8484) when given a
/// path: HTTP/1.1 requests instead of length-prefixed messages, with the
/// same connection limits, timeouts and back-pressure.

#include "dnsentinel/net/event_loop.h"
#include "dnsentinel/net/query_handler.h"
#include "dnsentinel/net/tls.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <system_error>
#include <unordered_map>
#include <vector>

namespace dnsentinel::net {

namespace detail {
class Framing;
}

struct TcpListenerConfig {
    std::string address = "0.0.0.0";  // IPv4 or IPv6 literal ("::" for all IPv6)
    uint16_t    port    = 53;         // 0 picks an ephemeral port
    uint32_t    idle_timeout_ms = 10000;  // close a connection that sends no complete query for this long
    size_t      max_connections = 200;
    size_t      max_per_client  = 10;     // connections from one IP address
};

/// What runs on top of TCP. Nothing: plain DNS over TCP.
struct StreamOptions {
    std::shared_ptr<const TlsContext> tls      = nullptr;       // set: TLS first (DoT, or DoH with doh_path)
    std::optional<std::string>        doh_path = std::nullopt;  // set: DNS over HTTP at this path (DoH); plain HTTP without tls
};

struct TcpListenerStats {
    uint64_t accepted          = 0;
    uint64_t rejected          = 0;  // over a connection limit: closed at once
    uint64_t queries           = 0;  // handed to the handler
    uint64_t dropped_malformed = 0;  // unparseable, or a response: connection closed
    uint64_t responses_sent    = 0;
    uint64_t idle_closed       = 0;
    uint64_t tls_failed        = 0;  // TLS handshake or record errors: connection closed
    uint64_t http_errors       = 0;  // DoH requests answered with an HTTP error status
};

class TcpListener {
public:
    /// Bind, listen and start accepting on `loop`. The listener must be
    /// destroyed before the loop. With `options.tls`, every connection
    /// starts with a TLS handshake, and handlers see Transport::Dot; with
    /// `options.doh_path` they see Transport::Doh.
    ///
    /// TLS writes go through write(2), so a client that resets its
    /// connection can raise SIGPIPE: a process using TLS must ignore it.
    [[nodiscard]] static std::expected<std::unique_ptr<TcpListener>, std::error_code>
    create(EventLoop& loop, const TcpListenerConfig& config, QueryHandler handler, StreamOptions options = {});

    /// Closes every connection. Responders still held by the handler become
    /// no-ops.
    ~TcpListener();
    TcpListener(const TcpListener&)            = delete;
    TcpListener& operator=(const TcpListener&) = delete;

    /// The bound port (useful when config.port was 0).
    [[nodiscard]] uint16_t port() const { return port_; }

    [[nodiscard]] size_t connections() const { return connections_.size(); }

    [[nodiscard]] const TcpListenerStats& stats() const { return stats_; }

private:
    struct Connection;

    TcpListener(EventLoop& loop, int fd, uint16_t port, const TcpListenerConfig& config, QueryHandler handler,
                StreamOptions options);

    void on_acceptable();
    void on_event(uint64_t id, uint32_t events);
    void read_from(const std::shared_ptr<Connection>& c);
    void process(const std::shared_ptr<Connection>& c);
    void dispatch(Connection& c, Message query, uint64_t tag);
    void respond(const std::shared_ptr<Connection>& c, uint64_t tag, const Message& response);
    void flush(const std::shared_ptr<Connection>& c);
    void update(const std::shared_ptr<Connection>& c);
    void arm_idle_timer(Connection& c);
    void close(Connection& c);

    EventLoop&         loop_;
    int                fd_;
    uint16_t           port_;
    TcpListenerConfig  config_;
    QueryHandler       handler_;
    StreamOptions      options_;
    Transport          transport_;
    EventLoop::TimerId accept_retry_ = 0;  // accepting paused: out of file descriptors

    uint64_t                                                  next_id_ = 1;
    std::unordered_map<uint64_t, std::shared_ptr<Connection>> connections_;
    std::unordered_map<std::string, size_t>                   per_client_;  // IP → open connections
    std::vector<uint8_t>                                      read_buffer_;
    TcpListenerStats                                          stats_;
};

}  // namespace dnsentinel::net
