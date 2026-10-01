#pragma once
/// @file resolver/upstream.h
/// Sends one query to one upstream server, over UDP or TCP, and waits for
/// the matching response on the event loop.

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
    NetworkError,  // could not send, the server's port is closed, or a TCP exchange broke off
    CaseMismatch,  // timed out, but a reply matched in all but letter case (0x20): the server
                   // probably normalises case (or that reply was forged)
};

enum class UpstreamTransport {
    Udp,
    Tcp,  // for answers too big for UDP (TC), or when UDP is being spoofed
};

class UpstreamClient {
public:
    using QueryId  = uint64_t;
    using Callback = std::function<void(std::expected<Message, UpstreamError>)>;

    struct Stats {
        uint64_t sent       = 0;
        uint64_t sent_tcp   = 0;  // of `sent`
        uint64_t answered   = 0;
        uint64_t timeouts   = 0;
        uint64_t errors     = 0;
        uint64_t mismatched = 0;  // wrong ID / question, or unparseable (possible spoofing)
        uint64_t case_mismatches = 0;  // right ID and question, wrong letter case (0x20)
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
    /// packets from `server` are seen. Over UDP, anything that isn't a
    /// response with the same ID and question is counted and ignored while
    /// waiting continues, so a forged packet can't cut a real query short.
    /// Over TCP (one query per connection) a mismatch is a NetworkError.
    /// `timeout` covers the whole exchange, TCP handshake included.
    ///
    /// With `match_case` (0x20, plan §5.2) the reply must also echo the
    /// question's letter case exactly. A reply that differs only in case is
    /// counted and ignored like any other mismatch; if nothing better comes
    /// before the timeout, the query ends with CaseMismatch instead of
    /// Timeout, so the caller can tell a case-normalising server from a dead one.
    ///
    /// `done` is called exactly once, and never before send() returns,
    /// unless the query is cancelled first.
    QueryId send(const sockaddr_in& server, Message query, std::chrono::milliseconds timeout,
                 Callback done, UpstreamTransport transport = UpstreamTransport::Udp,
                 bool match_case = false);

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
        bool                    match_case      = false;  // 0x20
        bool                    wrong_case_seen = false;
        // TCP only
        std::vector<uint8_t> out;  // the framed query
        size_t               written = 0;
        std::vector<uint8_t> in;   // the framed response so far
    };

    void on_readable(QueryId id);
    void on_tcp_event(QueryId id, uint32_t events);
    void finish(QueryId id, std::expected<Message, UpstreamError> result);
    void release(Pending& p);

    net::EventLoop&                      loop_;
    QueryId                              next_id_ = 1;
    std::unordered_map<QueryId, Pending> pending_;
    std::vector<uint8_t>                 buffer_;
    Stats                                stats_;
};

}  // namespace dnsentinel::resolver
