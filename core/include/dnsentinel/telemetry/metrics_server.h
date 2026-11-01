#pragma once
/// @file telemetry/metrics_server.h
/// The Prometheus endpoint (README §7.10): GET /metrics on
/// telemetry.prometheus.addr answers with the text the `render` callback
/// builds, then closes the connection. Plain HTTP/1.1, on the event loop:
/// a scrape costs one render, nothing between scrapes. It has no
/// authentication, so it listens on localhost unless told otherwise.

#include "dnsentinel/net/event_loop.h"

#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>

namespace dnsentinel::telemetry {

struct MetricsServerConfig {
    std::string address = "127.0.0.1";
    uint16_t    port    = 9153;
};

class MetricsServer {
public:
    using RenderFn = std::function<std::string()>;

    [[nodiscard]] static std::expected<std::unique_ptr<MetricsServer>, std::string> create(net::EventLoop&     loop,
                                                                                           MetricsServerConfig config,
                                                                                           RenderFn            render);
    ~MetricsServer();
    MetricsServer(const MetricsServer&)            = delete;
    MetricsServer& operator=(const MetricsServer&) = delete;

    [[nodiscard]] uint64_t scrapes() const { return scrapes_; }
    [[nodiscard]] uint16_t port() const { return port_; }  // the one bound (config port 0: any free one)

private:
    struct Connection {
        std::string in;
        std::string out;
        size_t      sent = 0;
    };

    MetricsServer(net::EventLoop& loop, RenderFn render, int fd, uint16_t port);
    void accept_connections();
    void on_connection(int fd, uint32_t events);
    void respond(int fd, Connection& connection);
    void close_connection(int fd);

    net::EventLoop&                                       loop_;
    RenderFn                                              render_;
    int                                                   listen_fd_ = -1;
    uint16_t                                              port_      = 0;
    std::unordered_map<int, std::unique_ptr<Connection>> connections_;
    uint64_t                                              scrapes_ = 0;
};

}  // namespace dnsentinel::telemetry
