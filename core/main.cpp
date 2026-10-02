/// @file main.cpp
/// The dnsentinel daemon: load the config and root hints, start the
/// resolver and the UDP and TCP listeners, and run the event loop until
/// SIGINT or SIGTERM.

#include "dnsentinel/cache/cache.h"
#include "dnsentinel/net/event_loop.h"
#include "dnsentinel/net/tcp_listener.h"
#include "dnsentinel/net/udp_listener.h"
#include "dnsentinel/resolver/recursive_resolver.h"
#include "dnsentinel/resolver/root_hints.h"
#include "dnsentinel/server/config.h"
#include "dnsentinel/server/query_processor.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>

#include <cstdio>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

using namespace dnsentinel;

namespace {

net::EventLoop* g_loop = nullptr;

void on_signal(int) { g_loop->stop(); }  // stop() is async-signal-safe

void log(const std::string& message) { std::fprintf(stderr, "dnsentinel: %s\n", message.c_str()); }
void warn(const std::string& message) { log("warning: " + message); }

void usage(std::FILE* out) {
    std::fprintf(out,
                 "usage: dnsentinel [-c|--config <file>]\n"
                 "  -c, --config <file>  configuration (default: config/dnsentinel.yaml)\n"
                 "  -h, --help           show this help\n");
}

std::string endpoint(const std::string& address, uint16_t port) {
    const bool v6 = address.find(':') != std::string::npos;
    return (v6 ? "[" + address + "]" : address) + ":" + std::to_string(port);
}

/// Explain why a listener couldn't start.
void cannot_listen(const char* transport, const std::string& where, uint16_t port, std::error_code error,
                   const char* argv0) {
    log(std::string("cannot listen on ") + transport + " " + where + ": " + error.message());
    if (error == std::errc::permission_denied && port < 1024) {
        log(std::string("ports below 1024 need a capability: sudo setcap 'cap_net_bind_service=+ep' ") + argv0);
    }
}

bool is_loopback(const std::string& address) {
    in_addr v4{};
    if (inet_pton(AF_INET, address.c_str(), &v4) == 1) return (ntohl(v4.s_addr) >> 24) == 127;
    in6_addr v6{};
    return inet_pton(AF_INET6, address.c_str(), &v6) == 1 && IN6_IS_ADDR_LOOPBACK(&v6);
}

std::string ipv4_text(uint32_t address) {
    char text[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &address, text, sizeof text);
    return text;
}

std::string join(const std::vector<std::string>& items) {
    std::string out;
    for (const auto& item : items) out += (out.empty() ? "" : ", ") + item;
    return out;
}

}  // namespace

int main(int argc, char** argv) {
    std::string config_path = "config/dnsentinel.yaml";
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg = argv[i];
        if ((arg == "-c" || arg == "--config") && i + 1 < argc) {
            config_path = argv[++i];
        } else if (arg == "-h" || arg == "--help") {
            usage(stdout);
            return 0;
        } else {
            usage(stderr);
            return 2;
        }
    }

    // ─── Configuration: every error stops startup ───────────────────────────
    auto config = server::load_config(config_path);
    if (!config) {
        log(config.error());
        return 1;
    }
    auto hints = resolver::load_root_hints(config->resolver.root_hints_path);
    if (!hints) {
        log(hints.error());
        return 1;
    }
    if (!config->not_implemented.empty()) {
        warn("not implemented yet, ignored: " + join(config->not_implemented));
    }
    const std::string udp_at = endpoint(config->udp.address, config->udp.port);
    const std::string tcp_at = endpoint(config->tcp.address, config->tcp.port);
    if (!is_loopback(config->udp.address) || !is_loopback(config->tcp.address)) {
        warn("no access control yet (plan §5.5): anyone who can reach the listeners can use this resolver");
    }
    for (const auto& stub : config->resolver.stub_zones) {
        std::vector<std::string> servers;
        for (uint32_t a : stub.servers) servers.push_back(ipv4_text(a));
        log("stub zone " + stub.zone.to_string() + " -> " + join(servers));
    }

    // ─── Components, destroyed in reverse: listener first, loop last ────────
    auto loop = net::EventLoop::create();
    if (!loop) {
        log("cannot create the event loop: " + loop.error().message());
        return 1;
    }
    cache::Cache                cache(config->cache);
    resolver::RecursiveResolver resolver(config->resolver, std::move(*hints), **loop, cache);
    server::QueryProcessor      processor(resolver);
    resolver.on_spoof_alert([](const resolver::SpoofAlert& alert) {
        char server[INET_ADDRSTRLEN] = "?";
        inet_ntop(AF_INET, &alert.server, server, sizeof server);
        warn("possible spoofing: " + std::to_string(alert.replies) + " forged-looking replies for " +
             alert.question.qname.to_string() + " (type " + std::to_string(alert.question.qtype) +
             ") from " + server + "; asking it again over TCP");
    });

    auto handler = [&processor](Message query, const net::ClientInfo& client, net::Responder respond) {
        processor.handle(std::move(query), client, std::move(respond));
    };
    auto udp = net::UdpListener::create(**loop, config->udp, handler);
    if (!udp) {
        cannot_listen("udp", udp_at, config->udp.port, udp.error(), argv[0]);
        return 1;
    }
    auto tcp = net::TcpListener::create(**loop, config->tcp, handler);
    if (!tcp) {
        cannot_listen("tcp", tcp_at, config->tcp.port, tcp.error(), argv[0]);
        return 1;
    }

    g_loop = loop->get();
    struct sigaction action{};
    action.sa_handler = on_signal;
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, nullptr);
    sigaction(SIGTERM, &action, nullptr);

    resolver.prime_root([](std::expected<void, resolver::ResolveError> primed) {
        if (primed) {
            log("primed the root name servers");
        } else {
            warn("root priming failed (" + resolver::resolve_error_to_string(primed.error()) +
                 "); queries start from the root hints");
        }
    });

    log("listening on udp " + udp_at + " and tcp " + tcp_at);
    (*loop)->run();
    log("shutting down");
    action.sa_handler = SIG_DFL;  // a second Ctrl-C now just exits
    sigaction(SIGINT, &action, nullptr);
    sigaction(SIGTERM, &action, nullptr);
    return 0;
}
