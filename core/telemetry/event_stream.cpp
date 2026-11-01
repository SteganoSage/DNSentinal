/// @file telemetry/event_stream.cpp

#include "dnsentinel/telemetry/event_stream.h"

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <system_error>
#include <utility>

namespace dnsentinel::telemetry {

namespace {

constexpr size_t kMaxCommandLine = 64 * 1024;  // a reader sending more without a newline is cut off

std::string errno_text() { return std::error_code(errno, std::system_category()).message(); }

sockaddr_un socket_address(const std::string& path) {
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path, path.data(), path.size());  // the caller checked the length
    return address;
}

/// Is a daemon still listening at `path`?
bool listening(const std::string& path) {
    const int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return false;
    const sockaddr_un address = socket_address(path);
    const bool        alive   = connect(fd, reinterpret_cast<const sockaddr*>(&address), sizeof address) == 0;
    close(fd);
    return alive;
}

}  // namespace

std::expected<std::unique_ptr<EventStream>, std::string> EventStream::create(net::EventLoop&   loop,
                                                                             EventStreamConfig config,
                                                                             CommandFn         on_command) {
    const std::string& path = config.path;
    if (path.empty() || path.size() >= sizeof(sockaddr_un{}.sun_path)) {
        return std::unexpected("telemetry.events.socket: a socket path needs 1 to " +
                               std::to_string(sizeof(sockaddr_un{}.sun_path) - 1) + " characters");
    }
    const std::filesystem::path parent = std::filesystem::path(path).parent_path();
    if (!parent.empty() && !std::filesystem::exists(parent)) {
        if (mkdir(parent.c_str(), 0700) != 0) {
            return std::unexpected("cannot create " + parent.string() + " for the event socket: " + errno_text());
        }
    }
    struct stat existing{};
    if (lstat(path.c_str(), &existing) == 0) {
        if (!S_ISSOCK(existing.st_mode)) return std::unexpected(path + " exists and is not a socket");
        if (listening(path)) return std::unexpected(path + " is in use: is another dnsentinel running?");
        unlink(path.c_str());  // left by a daemon that is gone
    }

    const int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return std::unexpected("cannot create the event socket: " + errno_text());
    const sockaddr_un address = socket_address(path);
    const mode_t      before  = umask(0177);  // created 0600: no window in which others could connect
    const int         bound   = bind(fd, reinterpret_cast<const sockaddr*>(&address), sizeof address);
    umask(before);
    if (bound != 0 || listen(fd, 16) != 0) {
        std::string error = "cannot listen on " + path + ": " + errno_text();
        close(fd);
        return std::unexpected(std::move(error));
    }
    std::unique_ptr<EventStream> stream(new EventStream(loop, std::move(config), std::move(on_command), fd));
    if (auto error = loop.add_fd(fd, net::kReadable, [raw = stream.get()](uint32_t) { raw->accept_readers(); })) {
        return std::unexpected("cannot watch the event socket: " + error.message());
    }
    return stream;
}

EventStream::EventStream(net::EventLoop& loop, EventStreamConfig config, CommandFn on_command, int listen_fd)
    : loop_(loop), config_(std::move(config)), on_command_(std::move(on_command)), listen_fd_(listen_fd) {}

EventStream::~EventStream() {
    while (!readers_.empty()) close_reader(readers_.begin()->first);
    if (listen_fd_ >= 0) {
        loop_.remove_fd(listen_fd_);
        close(listen_fd_);
        unlink(config_.path.c_str());
    }
}

void EventStream::accept_readers() {
    for (;;) {
        const int fd = accept4(listen_fd_, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) return;  // EAGAIN: none left; anything else: try again on the next wakeup
        if (readers_.size() >= config_.max_readers) {
            constexpr std::string_view busy = R"({"type":"error","error":"too many readers"})" "\n";
            [[maybe_unused]] const ssize_t n = send(fd, busy.data(), busy.size(), MSG_NOSIGNAL);
            close(fd);
            continue;
        }
        if (loop_.add_fd(fd, net::kReadable, [this, fd](uint32_t events) { on_reader(fd, events); })) {
            close(fd);
            continue;
        }
        auto reader = std::make_unique<Reader>();
        reader->fd  = fd;
        readers_.emplace(fd, std::move(reader));
        ++stats_.readers;
    }
}

void EventStream::publish(std::string_view line) {
    if (readers_.empty()) return;
    ++stats_.published;
    for (auto& [fd, reader] : readers_) {
        const size_t waiting = reader->out.size() - reader->sent;
        if (waiting + line.size() + 1 > config_.buffer_bytes) {  // it fell behind: this one is lost
            ++reader->dropped;
            ++stats_.dropped;
            continue;
        }
        if (reader->dropped > 0) {
            append(*reader, R"({"type":"dropped","count":)" + std::to_string(reader->dropped) + "}");
            reader->dropped = 0;
        }
        append(*reader, line);
    }
}

void EventStream::append(Reader& reader, std::string_view line) {
    if (reader.sent > 0 && reader.sent == reader.out.size()) {  // all written: start the buffer afresh
        reader.out.clear();
        reader.sent = 0;
    }
    reader.out.append(line);
    reader.out.push_back('\n');
    if (!reader.writing && !loop_.modify_fd(reader.fd, net::kReadable | net::kWritable)) reader.writing = true;
}

void EventStream::write_out(Reader& reader) {
    while (reader.sent < reader.out.size()) {
        const ssize_t n = send(reader.fd, reader.out.data() + reader.sent, reader.out.size() - reader.sent,
                               MSG_NOSIGNAL | MSG_DONTWAIT);
        if (n <= 0) {
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return;  // full: wait
            close_reader(reader.fd);
            return;
        }
        reader.sent += static_cast<size_t>(n);
        // don't let the part already written pile up in front of the rest
        if (reader.sent >= (size_t{1} << 20) && reader.sent < reader.out.size()) {
            reader.out.erase(0, reader.sent);
            reader.sent = 0;
        }
    }
    reader.out.clear();
    reader.sent = 0;
    if (reader.writing && !loop_.modify_fd(reader.fd, net::kReadable)) reader.writing = false;
}

void EventStream::on_reader(int fd, uint32_t events) {
    auto found = readers_.find(fd);
    if (found == readers_.end()) return;
    Reader& reader = *found->second;
    if (events & net::kWritable) {
        write_out(reader);
        if (!readers_.contains(fd)) return;
    }
    if (!(events & ~net::kWritable)) return;  // nothing to read
    char buffer[4096];
    for (;;) {
        const ssize_t n = recv(fd, buffer, sizeof buffer, MSG_DONTWAIT);
        if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
            close_reader(fd);  // the reader left
            return;
        }
        if (n < 0) break;
        reader.in.append(buffer, static_cast<size_t>(n));
    }
    size_t start = 0;
    for (size_t end; (end = reader.in.find('\n', start)) != std::string::npos; start = end + 1) {
        std::string_view line(reader.in.data() + start, end - start);
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        if (line.empty()) continue;
        if (reader.out.size() - reader.sent > config_.buffer_bytes) {  // sends commands, never reads the replies
            close_reader(fd);
            return;
        }
        ++stats_.commands;
        constexpr std::string_view off =
            R"x({"type":"reply","ok":false,"error":"commands are off (telemetry.events.commands)"})x";
        append(reader, config_.commands && on_command_ ? on_command_(line) : std::string(off));
    }
    reader.in.erase(0, start);
    if (reader.in.size() > kMaxCommandLine) close_reader(fd);
}

void EventStream::close_reader(int fd) {
    loop_.remove_fd(fd);
    close(fd);
    readers_.erase(fd);
}

}  // namespace dnsentinel::telemetry
