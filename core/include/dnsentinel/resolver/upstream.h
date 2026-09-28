#pragma once
/// @file resolver/upstream.h
/// Sends one query to one upstream server over UDP and waits for the
/// matching response on the event loop.

#include "dnsentinel/net/event_loop.h"
#include "dnsentinel/types.h"

#include <netinet/in.h>

#include <chrono>
#include <cstdint>
#include <expected>
#include <functional>
#include <unordered_map>
#include <vector>

namespace dnsentinel::resolver {

enum class UpstreamError {
    Timeout,       // no matching response in time
    NetworkError,  // could not send, or the server's port is closed (ICMP)
};

class UpstreamClient {
public:
    using QueryId  = uint64_t;
    using Callback = std::function<void(std::expected<Message, UpstreamError>)>;

    struct Stats {
        uint64_t sent       = 0;
        uint64_t answered   = 0;
        uint64_t timeouts   = 0;
        uint64_t errors     = 0;
        uint64_t mismatched = 0;  // wrong ID / question, or unparseable (possible spoofing)
    };

    /// `loop` must outlive the client.
    explicit UpstreamClient(net::EventLoop& loop);

    /// Cancels every query in flight without calling its callback.
    ~UpstreamClient();

    UpstreamClient(const UpstreamClient&)            = delete;
    UpstreamClient& operator=(const UpstreamClient&) = delete;

    /// Send `query` (one question) to `server`. Each query gets a fresh
    /// socket, so the kernel picks a random source port, and a random ID
    /// (query.header.id is overwritten). The socket is connected, so only
    /// packets from `server` are seen; of those, anything that isn't a
    /// response with the same ID and question is counted and ignored while
    /// waiting continues, so a forged packet can't cut a real query short.
    ///
    /// `done` is called exactly once, and never before send() returns,
    /// unless the query is cancelled first.
    QueryId send(const sockaddr_in& server, Message query, std::chrono::milliseconds timeout,
                 Callback done);

    /// Abandon a query without calling its callback. Unknown ids are ignored.
    void cancel(QueryId id);

    [[nodiscard]] const Stats& stats() const { return stats_; }

private:
    struct Pending {
        int                     fd = -1;
        uint16_t                txid = 0;
        Question                question;
        net::EventLoop::TimerId timer = 0;
        Callback                done;
    };

    void on_readable(QueryId id);
    void finish(QueryId id, std::expected<Message, UpstreamError> result);
    void release(Pending& p);

    net::EventLoop&                      loop_;
    QueryId                              next_id_ = 1;
    std::unordered_map<QueryId, Pending> pending_;
    std::vector<uint8_t>                 buffer_;
    Stats                                stats_;
};

}  // namespace dnsentinel::resolver
