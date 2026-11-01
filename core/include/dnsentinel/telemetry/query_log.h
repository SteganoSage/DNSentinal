#pragma once
/// @file telemetry/query_log.h
/// The query log (README §7.10): every answered query, one JSON line each
/// (the event stream's line, telemetry/query_event.h), in a file per day,
/// kept retention_days. It is what the dashboard reads and how trace W1 is
/// collected (EVALUATION.md §3.5).
///
/// A DNS log is itself sensitive, so clients can be anonymised (a keyed
/// hash: the same device keeps the same label, the address isn't stored)
/// and subnets excluded altogether. Lines are queued on the event loop and
/// written by a thread of the log's own, so a slow disk never delays an
/// answer: when ring_buffer_size lines are already waiting, the newest are
/// dropped and counted.
///
/// path "logs/queries.jsonl" gives logs/queries-2026-11-01.jsonl,
/// logs/queries-2026-11-02.jsonl, ... (UTC days, from each query's time).

#include "dnsentinel/policy/acl.h"
#include "dnsentinel/telemetry/query_event.h"

#include <sys/socket.h>

#include <array>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <expected>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace dnsentinel::telemetry {

struct QueryLogConfig {
    bool                        enabled           = false;
    std::string                 path              = "logs/queries.jsonl";
    uint32_t                    retention_days    = 7;  // older day files are removed; 0: keep everything
    bool                        anonymise_clients = false;
    size_t                      ring_buffer_size  = 8192;  // lines waiting to be written
    std::vector<policy::Subnet> exclude{};               // clients never logged
};

class QueryLog {
public:
    struct Stats {
        uint64_t written = 0;  // lines written
        uint64_t dropped = 0;  // lines lost because the writer fell behind
        uint64_t removed = 0;  // day files removed for being older than the retention
    };

    /// Create the directory if needed and start the writer. With
    /// anonymise_clients, the hash key is kept beside the log
    /// (.anonymise-key, mode 0600), so labels stay the same across restarts.
    [[nodiscard]] static std::expected<std::unique_ptr<QueryLog>, std::string> open(QueryLogConfig config);
    ~QueryLog();  // close()
    QueryLog(const QueryLog&)            = delete;
    QueryLog& operator=(const QueryLog&) = delete;

    /// Queue the event's line (never blocks for I/O). Excluded clients are skipped.
    void write(const QueryEvent& event);

    /// Write what is queued and stop the writer, so stats() are final. Lines
    /// written after this are dropped.
    void close();

    /// How a client appears in the log: its address, or "anon-" and 12 hex digits.
    [[nodiscard]] std::string client_label(const sockaddr_storage& client) const;

    [[nodiscard]] bool  excluded(const sockaddr_storage& client) const;
    [[nodiscard]] Stats stats() const;
    [[nodiscard]] const QueryLogConfig& config() const { return config_; }

    /// The day file a query of this UTC day ("2026-11-01") goes to.
    [[nodiscard]] std::string file_for(const std::string& day) const;

private:
    explicit QueryLog(QueryLogConfig config);
    void run();
    void flush(std::deque<std::pair<std::string, std::string>>& batch);  // (day, line)
    void remove_old(const std::string& newest_day);

    QueryLogConfig config_;
    std::string    stem_, extension_, directory_;
    std::array<unsigned char, 32> key_{};

    mutable std::mutex                              mutex_;
    std::condition_variable                         wake_;
    std::deque<std::pair<std::string, std::string>> queue_;
    bool                                            stopping_ = false;
    std::atomic<uint64_t>                           dropped_{0};

    // the writer thread's
    std::FILE*            file_ = nullptr;
    std::string           day_;
    std::atomic<uint64_t> written_{0};
    std::atomic<uint64_t> removed_{0};
    std::thread           writer_;
};

}  // namespace dnsentinel::telemetry
