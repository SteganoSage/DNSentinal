/// @file telemetry/query_metrics.cpp

#include "dnsentinel/telemetry/query_metrics.h"

#include <algorithm>
#include <cstdio>

namespace dnsentinel::telemetry {

namespace exposition {

void header(std::string& out, std::string_view name, std::string_view type, std::string_view help) {
    out.append("# HELP ").append(name).append(" ").append(help).append("\n");
    out.append("# TYPE ").append(name).append(" ").append(type).append("\n");
}

void sample(std::string& out, std::string_view name, std::string_view labels, uint64_t value) {
    out.append(name);
    if (!labels.empty()) out.append("{").append(labels).append("}");
    out.append(" ").append(std::to_string(value)).append("\n");
}

void single(std::string& out, std::string_view name, std::string_view type, std::string_view help, uint64_t value) {
    header(out, name, type, help);
    sample(out, name, "", value);
}

}  // namespace exposition

namespace {

constexpr std::array<std::string_view, 4> kTransportNames = {"udp", "tcp", "dot", "doh"};
constexpr std::array<Action, 9> kActionOrder = {Action::Answer,  Action::Block,       Action::CnameBlock,
                                                Action::Dynamic, Action::Dga,         Action::Refused,
                                                Action::RateLimited, Action::Rejected, Action::Rebinding};

size_t type_slot(uint16_t qtype) {
    const auto& types = QueryMetrics::kTypes;
    const auto  found = std::find(types.begin(), types.end(), qtype);
    return static_cast<size_t>(found - types.begin());  // types.size(): other
}

}  // namespace

QueryMetrics::QueryMetrics() : counts_(kTransports * kTypeSlots * kRcodes * kActions, 0) {}

void QueryMetrics::record(net::Transport transport, uint16_t qtype, uint8_t rcode, Action action,
                          std::chrono::microseconds latency) {
    const size_t t = std::min<size_t>(static_cast<size_t>(transport), kTransports - 1);
    const size_t r = std::min<size_t>(rcode, kRcodes - 1);
    const size_t a = std::min<size_t>(static_cast<size_t>(action), kActions - 1);
    ++counts_[((t * kTypeSlots + type_slot(qtype)) * kRcodes + r) * kActions + a];

    const auto us     = static_cast<uint64_t>(std::max<int64_t>(latency.count(), 0));
    const auto bucket = std::lower_bound(kBucketsUs.begin(), kBucketsUs.end(), us);
    ++buckets_[static_cast<size_t>(bucket - kBucketsUs.begin())];
    ++count_;
    sum_us_ += us;
}

void QueryMetrics::render(std::string& out) const {
    using namespace exposition;
    header(out, "dnsentinel_queries_total", "counter",
           "Queries answered, by transport, type, rcode and the check that decided the answer.");
    for (size_t t = 0; t < kTransports; ++t) {
        for (size_t s = 0; s < kTypeSlots; ++s) {
            const std::string type = s < kTypes.size() ? type_name(kTypes[s]) : "other";
            for (size_t r = 0; r < kRcodes; ++r) {
                const std::string rcode = r + 1 < kRcodes ? rcode_name(static_cast<uint8_t>(r)) : "other";
                for (size_t a = 0; a < kActions; ++a) {
                    const uint64_t n = counts_[((t * kTypeSlots + s) * kRcodes + r) * kActions + a];
                    if (n == 0) continue;  // only the series that happened
                    const std::string labels = "transport=\"" + std::string(kTransportNames[t]) + "\",qtype=\"" +
                                               type + "\",rcode=\"" + rcode + "\",action=\"" +
                                               std::string(action_name(kActionOrder[a])) + "\"";
                    sample(out, "dnsentinel_queries_total", labels, n);
                }
            }
        }
    }

    header(out, "dnsentinel_query_duration_seconds", "histogram",
           "From a query arriving to its answer going out, cache hits and blocked names included.");
    uint64_t cumulative = 0;
    for (size_t i = 0; i < kBucketsUs.size(); ++i) {
        cumulative += buckets_[i];
        char bound[32];
        std::snprintf(bound, sizeof bound, "%g", kBucketsUs[i] / 1e6);
        sample(out, "dnsentinel_query_duration_seconds_bucket", std::string("le=\"") + bound + "\"", cumulative);
    }
    sample(out, "dnsentinel_query_duration_seconds_bucket", "le=\"+Inf\"", count_);
    char sum[48];  // exact: the microseconds are whole
    std::snprintf(sum, sizeof sum, "%llu.%06llu", static_cast<unsigned long long>(sum_us_ / 1'000'000),
                  static_cast<unsigned long long>(sum_us_ % 1'000'000));
    out.append("dnsentinel_query_duration_seconds_sum ").append(sum).append("\n");
    sample(out, "dnsentinel_query_duration_seconds_count", "", count_);
}

}  // namespace dnsentinel::telemetry
