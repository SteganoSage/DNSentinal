#pragma once
/// @file telemetry/event_stream.h
/// The event bus to the slow path (README §6.2): every answered query, one
/// JSON line each (telemetry/query_event.h), to every reader connected to a
/// Unix socket; and the way back to the policy engine: a reader may send
/// commands, one JSON object per line, each answered with one line
/// (server/rule_commands.h: the dynamic rules of README §7.6.6).
///
/// Never slows an answer. Events wait in a buffer per reader, written as the
/// socket takes them; a reader that falls buffer_bytes behind loses the newer
/// events until it catches up, and then first gets {"type":"dropped","count":N}.
/// Nothing is formatted when no reader is connected.
///
/// Who can connect can add rules that block names, so the socket is made
/// readable and writable by the daemon's user only (mode 0600), in a
/// directory created 0700 if missing. Everything runs on the event loop.

#include "dnsentinel/net/event_loop.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>

namespace dnsentinel::telemetry {

struct EventStreamConfig {
    std::string path{};                        // telemetry.events.socket; empty: no event stream
    size_t      buffer_bytes = size_t{4} << 20;  // per reader: unread events beyond this are dropped
    size_t      max_readers  = 8;              // more are turned away
    bool        commands     = true;           // readers may send commands (change the dynamic rules)
};

class EventStream {
public:
    /// The reply to one command line: a JSON object, without the newline.
    using CommandFn = std::function<std::string(std::string_view line)>;

    struct Stats {
        uint64_t published = 0;  // events published while someone was reading
        uint64_t dropped   = 0;  // events a reader lost because it fell behind
        uint64_t readers   = 0;  // readers that ever connected
        uint64_t commands  = 0;  // command lines answered
    };

    /// Listen on config.path, replacing a socket left there by a daemon that
    /// is gone (but not one still listening).
    [[nodiscard]] static std::expected<std::unique_ptr<EventStream>, std::string> create(net::EventLoop&   loop,
                                                                                         EventStreamConfig config,
                                                                                         CommandFn         on_command);
    ~EventStream();  // closes every reader and removes the socket file
    EventStream(const EventStream&)            = delete;
    EventStream& operator=(const EventStream&) = delete;

    /// Whether anyone is connected (if not, there is no point building an event).
    [[nodiscard]] bool has_readers() const { return !readers_.empty(); }
    [[nodiscard]] size_t reader_count() const { return readers_.size(); }

    /// Send one line (without the newline) to every reader.
    void publish(std::string_view line);

    [[nodiscard]] const Stats& stats() const { return stats_; }
    [[nodiscard]] const std::string& path() const { return config_.path; }

private:
    struct Reader {
        int         fd = -1;
        std::string out;       // waiting to be written
        size_t      sent = 0;  // of `out`, already written
        std::string in;        // a command line still being read
        uint64_t    dropped = 0;  // events lost since the reader last got one
        bool        writing = false;  // watching for writability
    };

    EventStream(net::EventLoop& loop, EventStreamConfig config, CommandFn on_command, int listen_fd);
    void accept_readers();
    void on_reader(int fd, uint32_t events);
    void append(Reader& reader, std::string_view line);
    void write_out(Reader& reader);
    void close_reader(int fd);

    net::EventLoop&                                  loop_;
    EventStreamConfig                                config_;
    CommandFn                                        on_command_;
    int                                              listen_fd_ = -1;
    std::unordered_map<int, std::unique_ptr<Reader>> readers_;
    Stats                                            stats_;
};

}  // namespace dnsentinel::telemetry
