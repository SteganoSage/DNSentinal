/// @file main.cpp
/// The dnsentinel daemon: load the config, root hints and block lists,
/// start the resolver and the UDP and TCP listeners, and run the event loop
/// until SIGINT or SIGTERM. SIGHUP reloads the block lists.

#include "dnsentinel/cache/cache.h"
#include "dnsentinel/net/event_loop.h"
#include "dnsentinel/net/tcp_listener.h"
#include "dnsentinel/net/udp_listener.h"
#include "dnsentinel/policy/blocklists.h"
#include "dnsentinel/resolver/recursive_resolver.h"
#include "dnsentinel/resolver/root_hints.h"
#include "dnsentinel/server/config.h"
#include "dnsentinel/server/query_processor.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <functional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

using namespace dnsentinel;

namespace {

net::EventLoop* g_loop      = nullptr;
int             g_reload_fd = -1;  // eventfd the loop watches; SIGHUP writes to it

void on_signal(int) { g_loop->stop(); }  // stop() is async-signal-safe

void on_reload_signal(int) {
    const uint64_t one = 1;
    [[maybe_unused]] const ssize_t n = write(g_reload_fd, &one, sizeof one);  // async-signal-safe
}

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

std::string ipv4_text(uint32_t address) {
    char text[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &address, text, sizeof text);
    return text;
}

/// An A or AAAA record's address as text.
std::string address_text(const RData& rdata) {
    char text[INET6_ADDRSTRLEN] = "?";
    if (const auto* a = std::get_if<RDataA>(&rdata)) inet_ntop(AF_INET, &a->addr, text, sizeof text);
    if (const auto* aaaa = std::get_if<RDataAAAA>(&rdata)) inet_ntop(AF_INET6, aaaa->addr, text, sizeof text);
    return text;
}

std::string join(const std::vector<std::string>& items) {
    std::string out;
    for (const auto& item : items) out += (out.empty() ? "" : ", ") + item;
    return out;
}

void log_lists(const policy::LoadReport& report) {
    for (const auto& file : report.files) {
        std::string line = (file.action == policy::ListAction::Block ? "  block " : "  allow ") + file.path + ": " +
                           std::to_string(file.stats.rules) + " domains";
        if (file.stats.skipped > 0) line += " (" + std::to_string(file.stats.skipped) + " unusable lines skipped)";
        log(line);
    }
    log("lists: " + std::to_string(report.domains) + " distinct domains, " +
        std::to_string(report.memory_bytes / 1024) + " KiB, read in " + std::to_string(report.took.count()) + " ms");
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
    {
        std::vector<std::string> allowed;
        for (const auto& subnet : config->access.allow) allowed.push_back(subnet.to_string());
        log("answering clients in " + join(allowed) + "; others are " +
            (config->access.deny == policy::DenyAction::Refuse ? "refused" : "ignored"));
    }
    for (const auto& stub : config->resolver.stub_zones) {
        std::vector<std::string> servers;
        for (uint32_t a : stub.servers) servers.push_back(ipv4_text(a));
        log("stub zone " + stub.zone.to_string() + " -> " + join(servers));
    }
    if (config->rebinding.enabled) {
        std::vector<std::string> exempt;
        for (const auto& zone : config->rebinding.exempt) exempt.push_back(zone.to_string());
        log("rebinding protection on; names that may resolve to private addresses: " + join(exempt));
    } else {
        warn("rebinding protection is off: public names may resolve to private addresses");
    }
    policy::Blocklists lists(config->lists);
    if (config->lists.blocklists.empty() && config->lists.allowlists.empty()) {
        log("no block lists configured");
    } else if (auto loaded = lists.load()) {
        log_lists(*loaded);
    } else {
        log(loaded.error());
        log("the public lists come from config/lists/download_feeds.sh; policy.blocklists names the files to read");
        return 1;
    }

    // ─── Components, destroyed in reverse: listener first, loop last ────────
    auto loop = net::EventLoop::create();
    if (!loop) {
        log("cannot create the event loop: " + loop.error().message());
        return 1;
    }
    cache::Cache                cache(config->cache);
    resolver::RecursiveResolver resolver(config->resolver, std::move(*hints), **loop, cache);
    server::QueryProcessor      processor(resolver, policy::AccessControl(config->access), lists,
                                          policy::RebindingFilter(config->rebinding));
    processor.on_block([](const server::BlockEvent& block) {
        // Names blocked by their own list entry are too many to log here (the
        // query log will record them); cloaked ones are rare and worth seeing.
        if (!block.via_cname()) return;
        std::string path;
        for (const auto& hop : block.chain) path += (path.empty() ? "" : " -> ") + hop.to_string();
        log("blocked a cloaked name: " + path + " (rule " + block.match.rule + " in " + block.match.source + ")");
    });
    processor.on_rebinding([](const server::RebindingEvent& event) {
        std::vector<std::string> addresses;
        for (const auto& rr : event.removed) addresses.push_back(address_text(rr.rdata));
        warn("possible DNS rebinding: " + event.question.qname.to_string() + " resolved to " + join(addresses) +
             " (private); " + (event.emptied ? "answered NXDOMAIN" : "removed from the answer") +
             ". If it is a local name, add it to policy.rebinding_protection.exempt");
    });
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

    // ─── Reloading the lists: on SIGHUP, and when a list file changes ───────
    // The files are read on a worker thread; the loop checks for the new
    // lists every 100 ms until they are ready, then uses them.
    std::function<void()> collect_reload = [&] {
        if (auto outcome = lists.finish_reload()) {
            if (*outcome) {
                log_lists(**outcome);
            } else {
                warn("reload failed, still using the previous lists: " + outcome->error());
            }
        } else {
            (*loop)->add_timer(std::chrono::milliseconds(100), collect_reload);
        }
    };
    auto reload = [&](const std::string& why) {
        if (!lists.start_reload()) return;  // one is already under way
        log("reloading the lists (" + why + ")");
        (*loop)->add_timer(std::chrono::milliseconds(100), collect_reload);
    };
    std::function<void()> check_files = [&] {
        if (lists.files_changed()) reload("a list file changed");
        (*loop)->add_timer(std::chrono::seconds(config->lists.reload_check_seconds), check_files);
    };
    if (config->lists.reload_check_seconds > 0) {
        (*loop)->add_timer(std::chrono::seconds(config->lists.reload_check_seconds), check_files);
    }

    g_reload_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (g_reload_fd < 0) {
        log("cannot create an eventfd: " + std::error_code(errno, std::system_category()).message());
        return 1;
    }
    if (auto error = (*loop)->add_fd(g_reload_fd, net::kReadable, [&](uint32_t) {
            uint64_t count = 0;
            [[maybe_unused]] const ssize_t n = read(g_reload_fd, &count, sizeof count);
            reload("SIGHUP");
        })) {
        log("cannot watch the reload eventfd: " + error.message());
        return 1;
    }

    g_loop = loop->get();
    struct sigaction action{};
    action.sa_handler = on_signal;
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, nullptr);
    sigaction(SIGTERM, &action, nullptr);
    action.sa_handler = on_reload_signal;
    sigaction(SIGHUP, &action, nullptr);

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
    action.sa_handler = SIG_IGN;  // the eventfd is about to close
    sigaction(SIGHUP, &action, nullptr);
    (*loop)->remove_fd(g_reload_fd);
    close(g_reload_fd);
    return 0;
}
