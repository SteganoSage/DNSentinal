#pragma once
/// @file net/query_handler.h
/// The interface between transports (UDP, TCP, DoT, DoH) and query
/// processing. Transports parse and frame; the handler decides the answer.

#include "dnsentinel/types.h"

#include <sys/socket.h>

#include <cstdint>
#include <functional>

namespace dnsentinel::net {

enum class Transport : uint8_t { Udp, Tcp, Dot, Doh };

/// Who sent a query and how.
struct ClientInfo {
    sockaddr_storage addr{};  // client IP and port (AF_INET or AF_INET6)
    Transport        transport = Transport::Udp;
};

/// Sends the response to one query. Call it at most once, on the event
/// loop's thread. It may be called after the handler returns (e.g. when
/// upstream resolution finishes); if it is never called, nothing is sent.
/// Calling it after the transport has shut down is a harmless no-op.
using Responder = std::function<void(const Message& response)>;

/// Processes one well-formed query (QR=0). Transports silently drop input
/// that fails to parse, and responses (QR=1), before it gets here.
using QueryHandler =
    std::function<void(Message query, const ClientInfo& client, Responder respond)>;

}  // namespace dnsentinel::net
