/// @file telemetry/metrics_server.cpp

#include "dnsentinel/telemetry/metrics_server.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <string_view>
#include <system_error>
#include <utility>

namespace dnsentinel::telemetry {

namespace {

constexpr size_t kMaxRequest     = 8192;  // headers included: a scrape is far smaller
constexpr size_t kMaxConnections = 16;

std::string errno_text() { return std::error_code(errno, std::system_category()).message(); }

std::string response(std::string_view status, std::string_view type, std::string_view body, bool head) {
    std::string out = "HTTP/1.1 " + std::string(status) + "\r\nContent-Type: " + std::string(type) +
                      "\r\nContent-Length: " + std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n";
    if (!head) out.append(body);
    return out;
}

}  // namespace

std::expected<std::unique_ptr<MetricsServer>, std::string> MetricsServer::create(net::EventLoop&     loop,
                                                                                 MetricsServerConfig config,
                                                                                 RenderFn            render) {
    sockaddr_storage address{};
    socklen_t        length = 0;
    if (auto* v4 = reinterpret_cast<sockaddr_in*>(&address); inet_pton(AF_INET, config.address.c_str(), &v4->sin_addr) == 1) {
        v4->sin_family = AF_INET;
        v4->sin_port   = htons(config.port);
        length         = sizeof(sockaddr_in);
    } else if (auto* v6 = reinterpret_cast<sockaddr_in6*>(&address);
               inet_pton(AF_INET6, config.address.c_str(), &v6->sin6_addr) == 1) {
        v6->sin6_family = AF_INET6;
        v6->sin6_port   = htons(config.port);
        length          = sizeof(sockaddr_in6);
    } else {
        return std::unexpected("telemetry.prometheus.addr: not an IP address: " + config.address);
    }
    const int fd = socket(address.ss_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return std::unexpected("cannot create the metrics socket: " + errno_text());
    const int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (bind(fd, reinterpret_cast<const sockaddr*>(&address), length) != 0 || listen(fd, 16) != 0) {
        std::string error = "cannot listen on " + config.address + ":" + std::to_string(config.port) + ": " +
                            errno_text();
        close(fd);
        return std::unexpected(std::move(error));
    }
    sockaddr_storage bound{};
    socklen_t        bound_length = sizeof bound;
    getsockname(fd, reinterpret_cast<sockaddr*>(&bound), &bound_length);
    const uint16_t port = ntohs(bound.ss_family == AF_INET ? reinterpret_cast<sockaddr_in*>(&bound)->sin_port
                                                           : reinterpret_cast<sockaddr_in6*>(&bound)->sin6_port);
    std::unique_ptr<MetricsServer> server(new MetricsServer(loop, std::move(render), fd, port));
    if (auto error = loop.add_fd(fd, net::kReadable, [raw = server.get()](uint32_t) { raw->accept_connections(); })) {
        return std::unexpected("cannot watch the metrics socket: " + error.message());
    }
    return server;
}

MetricsServer::MetricsServer(net::EventLoop& loop, RenderFn render, int fd, uint16_t port)
    : loop_(loop), render_(std::move(render)), listen_fd_(fd), port_(port) {}

MetricsServer::~MetricsServer() {
    while (!connections_.empty()) close_connection(connections_.begin()->first);
    if (listen_fd_ >= 0) {
        loop_.remove_fd(listen_fd_);
        close(listen_fd_);
    }
}

void MetricsServer::accept_connections() {
    for (;;) {
        const int fd = accept4(listen_fd_, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) return;
        if (connections_.size() >= kMaxConnections ||
            loop_.add_fd(fd, net::kReadable, [this, fd](uint32_t events) { on_connection(fd, events); })) {
            close(fd);
            continue;
        }
        connections_.emplace(fd, std::make_unique<Connection>());
    }
}

void MetricsServer::on_connection(int fd, uint32_t events) {
    auto found = connections_.find(fd);
    if (found == connections_.end()) return;
    Connection& connection = *found->second;
    if (!connection.out.empty()) {  // answering: write what is left
        if (!(events & net::kWritable)) return;
        while (connection.sent < connection.out.size()) {
            const ssize_t n = send(fd, connection.out.data() + connection.sent,
                                   connection.out.size() - connection.sent, MSG_NOSIGNAL | MSG_DONTWAIT);
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return;
            if (n <= 0) break;
            connection.sent += static_cast<size_t>(n);
        }
        close_connection(fd);
        return;
    }
    char buffer[2048];
    for (;;) {
        const ssize_t n = recv(fd, buffer, sizeof buffer, MSG_DONTWAIT);
        const bool    complete = connection.in.find("\r\n\r\n") != std::string::npos;
        if (n == 0 && complete) break;  // the client sent its request and shut its side: still answer
        if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
            close_connection(fd);
            return;
        }
        if (n < 0) break;
        connection.in.append(buffer, static_cast<size_t>(n));
        if (connection.in.size() > kMaxRequest) break;
    }
    if (connection.in.find("\r\n\r\n") != std::string::npos || connection.in.size() > kMaxRequest) {
        respond(fd, connection);
    }
}

void MetricsServer::respond(int fd, Connection& connection) {
    const std::string_view request(connection.in);
    const size_t           line_end = request.find("\r\n");
    const std::string_view line     = request.substr(0, line_end);
    const size_t           space1   = line.find(' ');
    const size_t           space2   = line.find(' ', space1 + 1);
    const std::string_view method   = line.substr(0, space1);
    const std::string_view target   = space1 == std::string_view::npos ? "" : line.substr(space1 + 1, space2 - space1 - 1);
    const std::string_view path     = target.substr(0, target.find('?'));
    const bool             head     = method == "HEAD";

    if (connection.in.size() > kMaxRequest) {
        connection.out = response("431 Request Header Fields Too Large", "text/plain", "too large\n", false);
    } else if (method != "GET" && !head) {
        connection.out = response("405 Method Not Allowed", "text/plain", "GET /metrics\n", false);
    } else if (path == "/metrics") {
        ++scrapes_;
        connection.out = response("200 OK", "text/plain; version=0.0.4; charset=utf-8", render_(), head);
    } else {
        connection.out = response("404 Not Found", "text/plain", "DNSentinel metrics are at /metrics\n", head);
    }
    connection.in.clear();
    if (loop_.modify_fd(fd, net::kWritable)) close_connection(fd);
}

void MetricsServer::close_connection(int fd) {
    loop_.remove_fd(fd);
    close(fd);
    connections_.erase(fd);
}

}  // namespace dnsentinel::telemetry
