/// @file net/udp_listener.cpp
/// UDP listener: recvmsg → parse → handler → build → sendmsg.

#include "dnsentinel/net/udp_listener.h"

#include "socket_address.h"
#include "dnsentinel/wire/builder.h"
#include "dnsentinel/wire/parser.h"

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <span>
#include <variant>

namespace dnsentinel::net {

namespace {

constexpr size_t kMaxDatagram         = 65535;
constexpr int    kMaxPacketsPerWakeup = 64;  // then give other fds a turn

std::error_code last_error() { return {errno, std::system_category()}; }

/// The local address a query arrived on (IP_PKTINFO / IPV6_PKTINFO). When
/// the host has several addresses, the reply must come from the one the
/// client asked, or the client will ignore it.
using LocalAddress = std::variant<std::monostate, in_pktinfo, in6_pktinfo>;

constexpr size_t kControlSize = CMSG_SPACE(sizeof(in6_pktinfo));  // fits either

LocalAddress read_local_address(msghdr& msg) {
    for (cmsghdr* c = CMSG_FIRSTHDR(&msg); c != nullptr; c = CMSG_NXTHDR(&msg, c)) {
        if (c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_PKTINFO) {
            in_pktinfo info;
            std::memcpy(&info, CMSG_DATA(c), sizeof info);
            return info;
        }
        if (c->cmsg_level == IPPROTO_IPV6 && c->cmsg_type == IPV6_PKTINFO) {
            in6_pktinfo info;
            std::memcpy(&info, CMSG_DATA(c), sizeof info);
            return info;
        }
    }
    return std::monostate{};
}

}  // namespace

using detail::address_length;

// ─── Socket (outlives the listener only as a weak reference) ────────────────

struct UdpListener::Socket {
    int              fd = -1;
    UdpListenerStats stats;

    Socket() = default;
    Socket(const Socket&)            = delete;
    Socket& operator=(const Socket&) = delete;
    ~Socket() {
        if (fd >= 0) close(fd);
    }

    void send(const Message& response, const sockaddr_storage& peer,
              const LocalAddress& local, uint16_t max_size);
};

void UdpListener::Socket::send(const Message& response, const sockaddr_storage& peer,
                               const LocalAddress& local, uint16_t max_size) {
    std::vector<uint8_t> bytes = wire::build(response, {.max_size = max_size});

    iovec iov{bytes.data(), bytes.size()};
    alignas(cmsghdr) unsigned char control[kControlSize] = {};
    msghdr msg{};
    msg.msg_name    = const_cast<sockaddr_storage*>(&peer);
    msg.msg_namelen = address_length(peer);
    msg.msg_iov     = &iov;
    msg.msg_iovlen  = 1;

    if (const auto* v4 = std::get_if<in_pktinfo>(&local)) {
        msg.msg_control    = control;
        msg.msg_controllen = CMSG_SPACE(sizeof(in_pktinfo));
        cmsghdr* c    = CMSG_FIRSTHDR(&msg);
        c->cmsg_level = IPPROTO_IP;
        c->cmsg_type  = IP_PKTINFO;
        c->cmsg_len   = CMSG_LEN(sizeof(in_pktinfo));
        in_pktinfo info  = *v4;
        info.ipi_ifindex = 0;  // pin the source address (ipi_spec_dst), let routing pick the interface
        std::memcpy(CMSG_DATA(c), &info, sizeof info);
    } else if (const auto* v6 = std::get_if<in6_pktinfo>(&local)) {
        msg.msg_control    = control;
        msg.msg_controllen = CMSG_SPACE(sizeof(in6_pktinfo));
        cmsghdr* c    = CMSG_FIRSTHDR(&msg);
        c->cmsg_level = IPPROTO_IPV6;
        c->cmsg_type  = IPV6_PKTINFO;
        c->cmsg_len   = CMSG_LEN(sizeof(in6_pktinfo));
        std::memcpy(CMSG_DATA(c), v6, sizeof *v6);  // keep ifindex: link-local sources need it
    }

    ssize_t n;
    do {
        n = sendmsg(fd, &msg, 0);
    } while (n < 0 && errno == EINTR);
    // A full send buffer (EAGAIN) loses this response; the client retries.
    if (n < 0) {
        ++stats.send_errors;
    } else {
        ++stats.responses_sent;
    }
}

// ─── UdpListener ────────────────────────────────────────────────────────────

std::expected<std::unique_ptr<UdpListener>, std::error_code>
UdpListener::create(EventLoop& loop, const UdpListenerConfig& config, QueryHandler handler) {
    auto parsed = detail::make_address(config.address, config.port);
    if (!parsed) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    const sockaddr_storage addr   = *parsed;
    const int              family = addr.ss_family;

    auto socket = std::make_shared<Socket>();
    socket->fd  = ::socket(family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (socket->fd < 0) return std::unexpected(last_error());

    const int on = 1;
    auto enable  = [&](int level, int option) {
        return setsockopt(socket->fd, level, option, &on, sizeof on) == 0;
    };
    // SO_REUSEPORT lets one socket per event loop share the port, with the
    // kernel spreading queries across them. Only the same user can join.
    bool ok = enable(SOL_SOCKET, SO_REUSEADDR) && enable(SOL_SOCKET, SO_REUSEPORT);
    if (family == AF_INET) {
        ok = ok && enable(IPPROTO_IP, IP_PKTINFO);
    } else {
        // V6ONLY keeps IPv4 on its own socket, where IP_PKTINFO applies.
        ok = ok && enable(IPPROTO_IPV6, IPV6_V6ONLY) && enable(IPPROTO_IPV6, IPV6_RECVPKTINFO);
    }
    if (!ok) return std::unexpected(last_error());

    if (bind(socket->fd, reinterpret_cast<const sockaddr*>(&addr), address_length(addr)) < 0) {
        return std::unexpected(last_error());
    }

    sockaddr_storage bound{};
    socklen_t        bound_len = sizeof bound;
    if (getsockname(socket->fd, reinterpret_cast<sockaddr*>(&bound), &bound_len) < 0) {
        return std::unexpected(last_error());
    }
    const uint16_t port = detail::port_of(bound);

    std::unique_ptr<UdpListener> listener(new UdpListener(
        loop, std::move(socket), port, config.max_response_size, std::move(handler)));
    UdpListener* self = listener.get();
    if (auto err = loop.add_fd(self->socket_->fd, kReadable, [self](uint32_t) { self->on_readable(); })) {
        return std::unexpected(err);
    }
    return listener;
}

UdpListener::UdpListener(EventLoop& loop, std::shared_ptr<Socket> socket, uint16_t port,
                         uint16_t max_response_size, QueryHandler handler)
    : loop_(loop),
      socket_(std::move(socket)),
      port_(port),
      max_response_size_(max_response_size),
      handler_(std::move(handler)),
      buffer_(kMaxDatagram) {}

UdpListener::~UdpListener() { loop_.remove_fd(socket_->fd); }

const UdpListenerStats& UdpListener::stats() const { return socket_->stats; }

void UdpListener::on_readable() {
    // Level-triggered: anything left after this batch wakes us again.
    for (int i = 0; i < kMaxPacketsPerWakeup; ++i) {
        sockaddr_storage peer{};
        alignas(cmsghdr) unsigned char control[kControlSize];
        iovec  iov{buffer_.data(), buffer_.size()};
        msghdr msg{};
        msg.msg_name       = &peer;
        msg.msg_namelen    = sizeof peer;
        msg.msg_iov        = &iov;
        msg.msg_iovlen     = 1;
        msg.msg_control    = control;
        msg.msg_controllen = sizeof control;

        const ssize_t n = recvmsg(socket_->fd, &msg, 0);
        if (n < 0) {
            // EAGAIN: drained, possibly by another loop sharing the port.
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            continue;  // EINTR, or a one-shot socket error this call cleared
        }

        auto query = wire::parse(std::span<const uint8_t>(buffer_.data(), static_cast<size_t>(n)));
        if (!query) {
            ++socket_->stats.dropped_malformed;  // never answer garbage
            continue;
        }
        if (query->header.qr) {
            ++socket_->stats.dropped_responses;  // answering responses invites loops
            continue;
        }
        ++socket_->stats.queries;

        const uint16_t max_size = wire::max_udp_response_size(query->edns, max_response_size_);
        Responder respond = [socket = std::weak_ptr<Socket>(socket_), peer,
                             local = read_local_address(msg), max_size](const Message& response) {
            if (auto s = socket.lock()) s->send(response, peer, local, max_size);
        };
        handler_(std::move(*query), ClientInfo{peer, Transport::Udp}, std::move(respond));
    }
}

}  // namespace dnsentinel::net
