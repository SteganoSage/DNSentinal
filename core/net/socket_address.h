#pragma once
/// @file net/socket_address.h
/// sockaddr helpers shared by the listeners. Private to core/net.

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <cstdint>
#include <optional>
#include <string>

namespace dnsentinel::net::detail {

/// An IPv4 or IPv6 literal plus port; nullopt if `ip` is neither.
inline std::optional<sockaddr_storage> make_address(const std::string& ip, uint16_t port) {
    sockaddr_storage addr{};
    auto* v4 = reinterpret_cast<sockaddr_in*>(&addr);
    if (inet_pton(AF_INET, ip.c_str(), &v4->sin_addr) == 1) {
        v4->sin_family = AF_INET;
        v4->sin_port   = htons(port);
        return addr;
    }
    addr     = {};
    auto* v6 = reinterpret_cast<sockaddr_in6*>(&addr);
    if (inet_pton(AF_INET6, ip.c_str(), &v6->sin6_addr) == 1) {
        v6->sin6_family = AF_INET6;
        v6->sin6_port   = htons(port);
        return addr;
    }
    return std::nullopt;
}

inline socklen_t address_length(const sockaddr_storage& addr) {
    return addr.ss_family == AF_INET6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in);
}

inline uint16_t port_of(const sockaddr_storage& addr) {
    return ntohs(addr.ss_family == AF_INET6 ? reinterpret_cast<const sockaddr_in6&>(addr).sin6_port
                                            : reinterpret_cast<const sockaddr_in&>(addr).sin_port);
}

/// The IP address alone, as raw bytes: a map key for per-client limits.
inline std::string ip_key(const sockaddr_storage& addr) {
    if (addr.ss_family == AF_INET6) {
        const auto& a = reinterpret_cast<const sockaddr_in6&>(addr).sin6_addr;
        return {reinterpret_cast<const char*>(&a), sizeof a};
    }
    const auto& a = reinterpret_cast<const sockaddr_in&>(addr).sin_addr;
    return {reinterpret_cast<const char*>(&a), sizeof a};
}

}  // namespace dnsentinel::net::detail
