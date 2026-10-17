#pragma once
/// @file net/framing.h
/// How a stream connection's bytes become DNS queries and answers become
/// bytes: DNS's 2-byte length prefix (TCP, DoT) or HTTP (DoH). The listener
/// owns the socket, TLS, limits and timeouts; a framing only translates.
/// Private to core/net.

#include "dnsentinel/net/tcp_listener.h"
#include "dnsentinel/types.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace dnsentinel::net::detail {

/// What a framing may do to its connection.
struct FramingHost {
    std::function<void(std::vector<uint8_t>)> send;   // queue bytes for the peer
    std::function<void(Message, uint64_t)>    query;  // a query; its answer comes back with this tag
    TcpListenerStats*                         stats = nullptr;
};

class Framing {
public:
    virtual ~Framing() = default;

    /// Take bytes that have arrived.
    virtual void feed(std::span<const uint8_t> bytes) = 0;

    /// Turn buffered input into queries, at most `budget` of them: the rest
    /// waits for the next call. False if the peer broke the protocol, so the
    /// connection should close.
    virtual bool process(size_t budget) = 0;

    /// The answer to the query that had `tag`.
    virtual void answer(uint64_t tag, const Message& response) = 0;

    /// The peer asked to end the connection once everything owed is sent.
    [[nodiscard]] virtual bool done() const { return false; }

    /// Input fed but not yet processed.
    [[nodiscard]] virtual size_t buffered() const = 0;
};

/// DNS over TCP and TLS: 2-byte big-endian length, then the message (RFC 7766).
std::unique_ptr<Framing> make_dns_framing(FramingHost host);

/// DNS over HTTPS (RFC 8484), HTTP/1.1: GET ?dns=<base64url> or POST with
/// an application/dns-message body, at `path`.
std::unique_ptr<Framing> make_http_framing(FramingHost host, std::string path);

}  // namespace dnsentinel::net::detail
