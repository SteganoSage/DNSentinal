#pragma once
/// @file telemetry/query_metrics.h
/// Counters for every answered query and a latency histogram, in
/// Prometheus's text format (README §7.10): the dashboard's overview and
/// experiments E2-E4. Recording a query is a few array increments on the
/// event loop; nothing is formatted until /metrics is scraped.

#include "dnsentinel/net/query_handler.h"
#include "dnsentinel/telemetry/query_event.h"

#include <array>
#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace dnsentinel::telemetry {

/// Writing Prometheus's text exposition format (version 0.0.4).
namespace exposition {
/// The "# HELP" and "# TYPE" lines that start a metric.
void header(std::string& out, std::string_view name, std::string_view type, std::string_view help);
/// One sample: name{labels} value. `labels` is "" or `a="x",b="y"`.
void sample(std::string& out, std::string_view name, std::string_view labels, uint64_t value);
/// A metric with one unlabelled sample: header and value. `type` is "counter" or "gauge".
void single(std::string& out, std::string_view name, std::string_view type, std::string_view help, uint64_t value);
}  // namespace exposition

class QueryMetrics {
public:
    QueryMetrics();

    void record(net::Transport transport, uint16_t qtype, uint8_t rcode, Action action,
                std::chrono::microseconds latency);

    /// dnsentinel_queries_total{transport,qtype,rcode,action} and
    /// dnsentinel_query_duration_seconds (a histogram), appended to `out`.
    void render(std::string& out) const;

    [[nodiscard]] uint64_t total() const { return count_; }

    /// The types counted by name; the rest are "other", so a flood of odd
    /// types can't add series without bound.
    static constexpr std::array<uint16_t, 13> kTypes = {1, 28, 65, 64, 12, 5, 15, 16, 33, 2, 6, 10, 255};
    /// Latency bucket bounds, in microseconds (+Inf is implied).
    static constexpr std::array<uint32_t, 15> kBucketsUs = {100,    250,    500,     1000,    2500,
                                                            5000,   10000,  25000,   50000,   100000,
                                                            250000, 500000, 1000000, 2500000, 5000000};

private:
    static constexpr size_t kTransports = 4;
    static constexpr size_t kTypeSlots  = kTypes.size() + 1;  // + other
    static constexpr size_t kRcodes     = 7;                  // NOERROR..REFUSED, other
    static constexpr size_t kActions    = 9;

    std::vector<uint64_t>                       counts_;  // transport x type x rcode x action
    std::array<uint64_t, kBucketsUs.size() + 1> buckets_{};  // the last one: over every bound
    uint64_t                                    count_  = 0;
    uint64_t                                    sum_us_ = 0;
};

}  // namespace dnsentinel::telemetry
