/// @file main.cpp
/// The dnsentinel daemon: load the config, root hints, certificates and
/// block lists, start the resolver and the UDP, TCP, DoT and DoH listeners and
/// the event stream to the slow path, the query log and the Prometheus
/// endpoint, and run the event loop until SIGINT or SIGTERM. SIGHUP reloads
/// the block lists.

#include "dnsentinel/cache/cache.h"
#include "dnsentinel/net/event_loop.h"
#include "dnsentinel/net/tcp_listener.h"
#include "dnsentinel/net/tls.h"
#include "dnsentinel/net/udp_listener.h"
#include "dnsentinel/policy/blocklists.h"
#include "dnsentinel/resolver/recursive_resolver.h"
#include "dnsentinel/resolver/root_hints.h"
#include "dnsentinel/server/config.h"
#include "dnsentinel/server/query_processor.h"
#include "dnsentinel/server/rule_commands.h"
#include "dnsentinel/telemetry/event_stream.h"
#include "dnsentinel/telemetry/metrics_server.h"
#include "dnsentinel/telemetry/query_event.h"
#include "dnsentinel/telemetry/query_log.h"
#include "dnsentinel/telemetry/query_metrics.h"

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

/// "a", "a and b", "a, b and c".
std::string join_and(const std::vector<std::string>& items) {
    if (items.size() < 2) return join(items);
    return join(std::vector<std::string>(items.begin(), items.end() - 1)) + " and " + items.back();
}

std::string describe_limits(const server::Config& c) {
    std::string out = "rate limits: ";
    if (c.rate_limit.qps == 0) {
        out += "none per client";
    } else {
        out += std::to_string(c.rate_limit.qps) + " queries/s per client (burst " + std::to_string(c.rate_limit.burst) +
               ", then " + (c.rate_limit.action == policy::DenyAction::Drop ? "dropped" : "refused") + ")";
    }
    if (c.rrl.responses_per_second == 0) {
        out += "; response rate limiting off";
    } else {
        out += "; " + std::to_string(c.rrl.responses_per_second) + " identical responses/s per /" +
               std::to_string(c.rrl.ipv4_prefix) + " or /" + std::to_string(c.rrl.ipv6_prefix) + " network";
        if (c.rrl.slip == 0) {
            out += " (more are dropped)";
        } else if (c.rrl.slip == 1) {
            out += " (more are sent truncated)";
        } else {
            out += " (1 in " + std::to_string(c.rrl.slip) + " more is sent truncated, the rest dropped)";
        }
    }
    if (!c.rate_limit.exempt.empty()) {
        std::vector<std::string> exempt;
        for (const auto& s : c.rate_limit.exempt) exempt.push_back(s.to_string());
        out += "; exempt: " + join(exempt);
    }
    return out;
}

/// The rate limiters' counters, for the periodic and final summaries.
struct LimitCounts {
    uint64_t over_client_limit = 0, rrl_dropped = 0, rrl_truncated = 0;

    static LimitCounts of(const server::Checks& checks) {
        return {checks.rate_limit.limited(), checks.rrl.dropped(), checks.rrl.slipped()};
    }
    LimitCounts operator-(const LimitCounts& o) const {
        return {over_client_limit - o.over_client_limit, rrl_dropped - o.rrl_dropped, rrl_truncated - o.rrl_truncated};
    }
    bool operator==(const LimitCounts&) const = default;

    [[nodiscard]] std::string describe() const {
        return std::to_string(over_client_limit) + " queries over a client's limit; " + std::to_string(rrl_dropped) +
               " responses dropped and " + std::to_string(rrl_truncated) + " truncated by RRL";
    }
};

/// A dynamic rule, for the log.
std::string describe_rule(const policy::DynamicRule& rule) {
    std::string domain = rule.domain.to_string();
    if (domain.size() > 1) domain.pop_back();
    char score[32];
    std::snprintf(score, sizeof score, "%.3f", rule.score);
    return "rule " + std::to_string(rule.id) + ": " + domain + " and below for " +
           (rule.client ? rule.client->to_string() : std::string("every client")) + " (" +
           (rule.reason.empty() ? "no reason given" : rule.reason) + ", score " + score +
           (rule.source.empty() ? "" : ", from " + rule.source) + ")";
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
    std::shared_ptr<net::TlsContext> dot_tls;
    if (config->dot) {
        auto tls = net::TlsContext::create_server(config->dot->cert, config->dot->key, {"dot"});
        if (!tls) {
            log("listen.dot: " + tls.error());
            log("for a lab certificate run certs/make_certs.sh (a phone's Private DNS needs a public one, plan §6.2)");
            return 1;
        }
        dot_tls = std::move(*tls);
    }
    std::shared_ptr<net::TlsContext> doh_tls;
    if (config->doh) {
        auto tls = net::TlsContext::create_server(config->doh->cert, config->doh->key, {"http/1.1"});
        if (!tls) {
            log("listen.doh: " + tls.error());
            log("for a lab certificate run certs/make_certs.sh, and trust certs/ca.crt in the browser (plan §6.3)");
            return 1;
        }
        doh_tls = std::move(*tls);
    }
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
#ifdef DNSENTINEL_WEAK_MODE
    if (config->resolver.weak.weaken) {
        warn("WEAK MODE: anti-spoofing is deliberately weakened (txid_bits=" +
             std::to_string(config->resolver.weak.txid_bits) +
             (config->resolver.weak.sequential_txid ? ", sequential IDs" : "") +
             (config->resolver.weak.fixed_source_port ? ", fixed source port " +
                  std::to_string(config->resolver.weak.fixed_source_port) : "") +
             (config->resolver.weak.accept_out_of_bailiwick ? ", bailiwick off" : "") +
             "). FOR THE ATTACK LAB ONLY (plan §5.10).");
    }
#endif
    log(describe_limits(*config));
    if (config->cache.serve_stale) {
        const auto& k = config->cache;
        log("serve-stale on: expired answers are kept " + std::to_string(k.max_stale_age / 3600) +
            " h and served (TTL " + std::to_string(k.stale_ttl) + " s) when resolving fails" +
            (k.stale_answer_after_ms > 0 ? " or takes over " + std::to_string(k.stale_answer_after_ms) + " ms" : ""));
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
#ifdef DNSENTINEL_ML
    std::optional<ml::DgaCheck> dga;
    if (config->dga.enabled) {
        auto loaded = ml::DgaCheck::load(config->dga);
        if (!loaded) {
            log("ml.dga: " + loaded.error());
            log("the model is models/dga (ml/dga/README.md); the allowlist comes from "
                "config/lists/download_feeds.sh; or set ml.dga.enabled: false");
            return 1;
        }
        dga = std::move(*loaded);
        const auto& model = dga->classifier();
        char        threshold[32];
        std::snprintf(threshold, sizeof threshold, "%.4f", model.threshold());
        log("dga classifier: " + std::to_string(model.trees().tree_count()) + " trees over " +
            std::to_string(model.features().size()) + " features, flags scores above " + threshold + "; " +
            std::to_string(dga->allowlist_size()) + " popular sites never scored; " +
            (dga->mode() == ml::DgaMode::Enforce ? "enforce mode: flagged names are answered as blocked"
                                                 : "monitor mode: flagged names are logged, then resolved"));
    }
#endif

    // ─── Components, destroyed in reverse: listener first, loop last ────────
    auto loop = net::EventLoop::create();
    if (!loop) {
        log("cannot create the event loop: " + loop.error().message());
        return 1;
    }
    cache::Cache                cache(config->cache);
    resolver::RecursiveResolver resolver(config->resolver, std::move(*hints), **loop, cache);
    server::Checks              checks{policy::AccessControl(config->access), policy::RateLimiter(config->rate_limit),
                          policy::RebindingFilter(config->rebinding), security::ResponseRateLimiter(config->rrl)};
#ifdef DNSENTINEL_ML
    checks.dga = std::move(dga);
#endif
    if (config->dynamic_rules.enabled) {
        const auto& d = config->dynamic_rules;
        checks.dynamic.emplace(d);
        log("dynamic rules on: up to " + std::to_string(d.max_rules) + ", each for at most " +
            std::to_string(d.max_ttl) + " s; names under one are answered " +
            (d.response == policy::BlockResponse::NxDomain ? "NXDOMAIN" : "0.0.0.0 / ::") +
            (config->events.path.empty() || !config->events.commands
                 ? " (none can be added: telemetry.events with commands is off)"
                 : " (the slow path adds them through telemetry.events)"));
    }
    server::QueryProcessor processor(resolver, lists, std::move(checks));
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
#ifdef DNSENTINEL_ML
    processor.on_dga([](const server::DgaEvent& event) {
        if (event.cached) return;  // logged when its registrable domain was first seen
        char score[32];
        std::snprintf(score, sizeof score, "%.3f", event.verdict.score);
        log("dga: " + event.question.qname.to_string() + " looks machine-generated (" + event.verdict.registrable +
            ", score " + score + "); " + (event.enforced ? "answered as blocked" : "resolved (monitor mode)"));
    });
#endif
    uint64_t spoof_alerts = 0;
    resolver.on_spoof_alert([&spoof_alerts](const resolver::SpoofAlert& alert) {
        ++spoof_alerts;
        char server[INET_ADDRSTRLEN] = "?";
        inet_ntop(AF_INET, &alert.server, server, sizeof server);
        warn("possible spoofing: " + std::to_string(alert.replies) + " forged-looking replies for " +
             alert.question.qname.to_string() + " (type " + std::to_string(alert.question.qtype) +
             ") from " + server + "; asking it again over TCP");
    });

    // ─── The event stream to the slow path, and its way back (README §6.2) ──
    server::RuleCommands commands(processor.dynamic_rules());
    commands.on_change([](const policy::DynamicRule& rule, bool renewed) {
        log(std::string(renewed ? "dynamic rule renewed, " : "dynamic rule added, ") + describe_rule(rule) + ", for " +
            std::to_string(std::chrono::ceil<std::chrono::seconds>(rule.expires - std::chrono::steady_clock::now())
                               .count()) +
            " s");
    });
    std::unique_ptr<telemetry::EventStream> events;
    if (!config->events.path.empty()) {
        auto stream = telemetry::EventStream::create(**loop, config->events, [&commands](std::string_view line) {
            return commands.handle(line, std::chrono::steady_clock::now());
        });
        if (!stream) {
            log("telemetry.events: " + stream.error());
            return 1;
        }
        events = std::move(*stream);
        log("event stream on " + config->events.path + " (up to " + std::to_string(config->events.max_readers) +
            " readers" + (config->events.commands ? ", which may change the dynamic rules" : "") +
            "): python -m analyzer.live");
    }

    // ─── The query log (README §7.10) ───────────────────────────────────────
    std::unique_ptr<telemetry::QueryLog> query_log;
    if (config->query_log.enabled) {
        auto opened = telemetry::QueryLog::open(config->query_log);
        if (!opened) {
            log("telemetry.query_log: " + opened.error());
            return 1;
        }
        query_log = std::move(*opened);
        const auto& q = config->query_log;
        log("query log: " + query_log->file_for("YYYY-MM-DD") + ", a file per UTC day, " +
            (q.retention_days > 0 ? "kept " + std::to_string(q.retention_days) + " days" : "kept forever") +
            (q.anonymise_clients ? ", clients anonymised" : "") +
            (q.exclude.empty() ? "" : ", " + std::to_string(q.exclude.size()) + " subnets never logged"));
    }
    if (events || query_log) {
        processor.on_query(
            [&events, &query_log](const telemetry::QueryEvent& event) {
                if (events && events->has_readers()) events->publish(telemetry::to_json(event));
                if (query_log) query_log->write(event);
            },
            [&events, &query_log] { return query_log || events->has_readers(); });
    }
    telemetry::QueryMetrics query_metrics;
    if (config->prometheus) processor.count_into(&query_metrics);
    std::function<void()> expire_rules = [&] {
        if (auto* rules = processor.dynamic_rules()) {
            for (const auto& rule : rules->expire(std::chrono::steady_clock::now())) {
                log("dynamic rule expired, " + describe_rule(rule) + "; " + std::to_string(rule.hits) +
                    " queries answered under it");
            }
        }
        (*loop)->add_timer(std::chrono::seconds(10), expire_rules);
    };
    (*loop)->add_timer(std::chrono::seconds(10), expire_rules);

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
    std::vector<std::string>          listening = {"udp " + udp_at, "tcp " + tcp_at};
    std::unique_ptr<net::TcpListener> dot;
    if (config->dot) {
        const std::string at       = endpoint(config->dot->tcp.address, config->dot->tcp.port);
        auto              listener = net::TcpListener::create(**loop, config->dot->tcp, handler, {.tls = dot_tls});
        if (!listener) {
            cannot_listen("dot", at, config->dot->tcp.port, listener.error(), argv[0]);
            return 1;
        }
        dot = std::move(*listener);
        listening.push_back("dot " + at);
    }
    std::unique_ptr<net::TcpListener> doh;
    if (config->doh) {
        const std::string at       = endpoint(config->doh->tcp.address, config->doh->tcp.port);
        auto              listener = net::TcpListener::create(**loop, config->doh->tcp, handler,
                                                              {.tls = doh_tls, .doh_path = config->doh->path});
        if (!listener) {
            cannot_listen("doh", at, config->doh->tcp.port, listener.error(), argv[0]);
            return 1;
        }
        doh = std::move(*listener);
        listening.push_back("doh https://" + at + config->doh->path);
    }

    // ─── The Prometheus endpoint (README §7.10) ─────────────────────────────
    // Each scrape renders everything afresh from the components' counters.
    const auto                               started = std::chrono::system_clock::now();
    std::unique_ptr<telemetry::MetricsServer> metrics;
    if (config->prometheus) {
        auto render = [&]() {
            using telemetry::exposition::single;
            std::string out;
            out.reserve(8192);
            query_metrics.render(out);
            single(out, "dnsentinel_cache_hits_total", "counter", "Answers found in the cache.", cache.hits());
            single(out, "dnsentinel_cache_misses_total", "counter", "Lookups the cache could not answer.",
                   cache.misses());
            single(out, "dnsentinel_cache_entries", "gauge", "Entries in the cache.", uint64_t{cache.size()});
            const resolver::ResolverStats& r = resolver.stats();
            single(out, "dnsentinel_upstream_queries_total", "counter", "Queries sent upstream, retries included.",
                   r.upstream_queries);
            single(out, "dnsentinel_upstream_minimised_queries_total", "counter",
                   "Upstream queries sent QNAME-minimised.", r.minimised_queries);
            single(out, "dnsentinel_minimisation_fallbacks_total", "counter",
                   "Zones sent the full name because a server mishandled a minimised one.", r.minimisation_fallbacks);
            single(out, "dnsentinel_stale_answers_total", "counter", "Clients answered with expired data.",
                   r.stale_answers);
            single(out, "dnsentinel_prefetches_total", "counter", "Background refreshes of popular entries.",
                   r.prefetches);
            single(out, "dnsentinel_spoof_alerts_total", "counter",
                   "Upstream queries that drew many forged-looking replies (each retried over TCP).", spoof_alerts);
            const server::Checks& k = processor.checks();
            single(out, "dnsentinel_rate_limited_total", "counter", "Queries over a client's rate limit.",
                   k.rate_limit.limited());
            single(out, "dnsentinel_rrl_dropped_total", "counter", "Responses dropped by response rate limiting.",
                   k.rrl.dropped());
            single(out, "dnsentinel_rrl_truncated_total", "counter",
                   "Responses sent truncated by response rate limiting.", k.rrl.slipped());
            single(out, "dnsentinel_blocklist_rules", "gauge", "Block list rules in force.", uint64_t{lists.size()});
            if (const auto* rules = processor.dynamic_rules()) {
                single(out, "dnsentinel_dynamic_rules", "gauge", "Dynamic rules in force.", uint64_t{rules->size()});
                single(out, "dnsentinel_dynamic_rules_added_total", "counter", "Dynamic rules added (not renewals).",
                       rules->added());
                single(out, "dnsentinel_dynamic_rule_blocks_total", "counter",
                       "Queries answered under a dynamic rule.", rules->blocked());
            }
#ifdef DNSENTINEL_ML
            if (const auto& d = k.dga) {
                const ml::DgaStats& s = d->stats();
                single(out, "dnsentinel_dga_scored_total", "counter",
                       "New registrable domains the DGA classifier scored.", s.scored);
                single(out, "dnsentinel_dga_flagged_total", "counter",
                       "Queries for names the DGA classifier judged generated.", s.flagged);
                single(out, "dnsentinel_dga_flagged_domains_total", "counter",
                       "Registrable domains the DGA classifier judged generated.", s.flagged_new);
            }
#endif
            if (events) {
                const auto& s = events->stats();
                single(out, "dnsentinel_events_published_total", "counter", "Query events sent to the slow path.",
                       s.published);
                single(out, "dnsentinel_events_dropped_total", "counter",
                       "Query events lost by readers that fell behind.", s.dropped);
                single(out, "dnsentinel_event_readers", "gauge", "Readers on the event stream.",
                       uint64_t{events->reader_count()});
            }
            if (query_log) {
                const auto s = query_log->stats();
                single(out, "dnsentinel_query_log_written_total", "counter", "Lines written to the query log.",
                       s.written);
                single(out, "dnsentinel_query_log_dropped_total", "counter",
                       "Query log lines lost because the disk fell behind.", s.dropped);
            }
            single(out, "dnsentinel_start_time_seconds", "gauge", "When the daemon started, in Unix time.",
                   static_cast<uint64_t>(
                       std::chrono::duration_cast<std::chrono::seconds>(started.time_since_epoch()).count()));
            return out;
        };
        auto server = telemetry::MetricsServer::create(**loop, *config->prometheus, render);
        if (!server) {
            log(server.error());
            return 1;
        }
        metrics = std::move(*server);
        listening.push_back("metrics http://" + endpoint(config->prometheus->address, metrics->port()) + "/metrics");
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

    // ─── What the rate limits did: every 10 s while they act, and at exit ────
    LimitCounts           reported;
    std::function<void()> report_limits = [&] {
        const LimitCounts now = LimitCounts::of(processor.checks());
        if (now != reported) log("rate limiting in the last 10 s: " + (now - reported).describe());
        reported = now;
        (*loop)->add_timer(std::chrono::seconds(10), report_limits);
    };
    (*loop)->add_timer(std::chrono::seconds(10), report_limits);

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
    action.sa_handler = SIG_IGN;  // TLS writes to a client that reset the connection raise it
    sigaction(SIGPIPE, &action, nullptr);

    resolver.prime_root([](std::expected<void, resolver::ResolveError> primed) {
        if (primed) {
            log("primed the root name servers");
        } else {
            warn("root priming failed (" + resolver::resolve_error_to_string(primed.error()) +
                 "); queries start from the root hints");
        }
    });

    log("listening on " + join_and(listening));
    (*loop)->run();
    if (const LimitCounts total = LimitCounts::of(processor.checks()); total != LimitCounts{}) {
        log("rate limiting since startup: " + total.describe());
    }
#ifdef DNSENTINEL_ML
    if (const auto& d = processor.checks().dga) {
        const ml::DgaStats& s = d->stats();
        log("dga since startup: " + std::to_string(s.queries) + " names checked: " + std::to_string(s.scored) +
            " scored, " + std::to_string(s.cache_hits) + " from the verdict cache, " + std::to_string(s.allowlisted) +
            " popular, " + std::to_string(s.skipped) + " not scored; " + std::to_string(s.flagged) + " flagged (" +
            std::to_string(s.flagged_new) + " domains)");
    }
#endif
    if (const auto* rules = processor.dynamic_rules(); rules && rules->added() > 0) {
        log("dynamic rules since startup: " + std::to_string(rules->added()) + " added, " +
            std::to_string(rules->blocked()) + " queries answered under them, " + std::to_string(rules->size()) +
            " still in force");
    }
    if (events) {
        const auto& s = events->stats();
        log("event stream since startup: " + std::to_string(s.readers) + " readers, " + std::to_string(s.published) +
            " events published, " + std::to_string(s.dropped) + " lost by readers that fell behind, " +
            std::to_string(s.commands) + " commands");
    }
    if (query_log) {
        query_log->close();  // so every queued line is counted
        const auto s = query_log->stats();
        log("query log since startup: " + std::to_string(s.written) + " lines written, " + std::to_string(s.dropped) +
            " lost because the disk fell behind, " + std::to_string(s.removed) + " old day files removed");
    }
    log("cache since startup: " + std::to_string(cache.hits()) + " hits, " + std::to_string(cache.misses()) +
        " misses, " + std::to_string(resolver.stats().stale_answers) + " stale answers, " +
        std::to_string(resolver.stats().prefetches) + " prefetches");
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
