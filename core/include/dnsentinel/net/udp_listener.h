#pragma once
/// @file net/udp_listener.h
/// UDP DNS listener: receives queries, hands them to a QueryHandler, and
/// sends each response sized to the client's EDNS buffer, from the local
/// address the query arrived on.

#include "dnsentinel/net/event_loop.h"
#include "dnsentinel/net/query_handler.h"
#include "dnsentinel/wire/edns.h"

#include <cstdint>
#include <expected>
#include <memory>
#include <string>
#include <system_error>
#include <vector>

namespace dnsentinel::net {

struct UdpListenerConfig {
    std::string address = "0.0.0.0";  // IPv4 or IPv6 literal ("::" for all IPv6)
    uint16_t    port    = 53;         // 0 picks an ephemeral port
    uint16_t    max_response_size = wire::kEdnsUdpPayloadSize;  // our EDNS buffer
};

struct UdpListenerStats {
    uint64_t queries           = 0;  // handed to the handler
    uint64_t dropped_malformed = 0;  // failed to parse
    uint64_t dropped_responses = 0;  // QR=1: never answer a response
    uint64_t responses_sent    = 0;
    uint64_t send_errors       = 0;
};

class UdpListener {
public:
    /// Bind the socket and start receiving on `loop`. The listener must be
    /// destroyed before the loop.
    [[nodiscard]] static std::expected<std::unique_ptr<UdpListener>, std::error_code>
    create(EventLoop& loop, const UdpListenerConfig& config, QueryHandler handler);

    ~UdpListener();
    UdpListener(const UdpListener&)            = delete;
    UdpListener& operator=(const UdpListener&) = delete;

    /// The bound port (useful when config.port was 0).
    [[nodiscard]] uint16_t port() const { return port_; }

    [[nodiscard]] const UdpListenerStats& stats() const;

private:
    struct Socket;  // shared with outstanding Responders

    UdpListener(EventLoop& loop, std::shared_ptr<Socket> socket, uint16_t port,
                uint16_t max_response_size, QueryHandler handler);

    void on_readable();

    EventLoop&              loop_;
    std::shared_ptr<Socket> socket_;
    uint16_t                port_;
    uint16_t                max_response_size_;
    QueryHandler            handler_;
    std::vector<uint8_t>    buffer_;  // one datagram
};

}  // namespace dnsentinel::net
