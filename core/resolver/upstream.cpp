/// @file resolver/upstream.cpp
/// One UDP query to one upstream server: fresh socket, random ID,
/// response validation, timeout.

#include "dnsentinel/resolver/upstream.h"

#include "dnsentinel/wire/builder.h"
#include "dnsentinel/wire/parser.h"

#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <span>

namespace dnsentinel::resolver {

namespace {

constexpr size_t kMaxDatagram = 65535;

}  // namespace

UpstreamClient::UpstreamClient(net::EventLoop& loop) : loop_(loop), buffer_(kMaxDatagram) {}

UpstreamClient::~UpstreamClient() {
    for (auto& [id, p] : pending_) release(p);
}

UpstreamClient::QueryId UpstreamClient::send(const sockaddr_in& server, Message query,
                                             std::chrono::milliseconds timeout, Callback done) {
    const QueryId id = next_id_++;
    Pending& p = pending_[id];
    p.done     = std::move(done);
    // arc4random is a CSPRNG (glibc >= 2.36 seeds it from getrandom()), so
    // the ID can't be predicted from earlier ones.
    p.txid = static_cast<uint16_t>(arc4random());
    if (!query.questions.empty()) p.question = query.questions.front();
    query.header.id = p.txid;

    auto fail_soon = [&] {
        // Report on the next iteration: callers never see a callback from
        // inside send().
        ++stats_.errors;
        p.timer = loop_.add_timer(std::chrono::milliseconds(0),
                                  [this, id] { finish(id, std::unexpected(UpstreamError::NetworkError)); });
        return id;
    };

    p.fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (p.fd < 0) return fail_soon();
    // connect() picks a random ephemeral source port and makes the kernel
    // drop datagrams from any other address or port.
    if (connect(p.fd, reinterpret_cast<const sockaddr*>(&server), sizeof server) < 0) return fail_soon();

    const std::vector<uint8_t> bytes = wire::build(query, {.max_size = 512});
    if (::send(p.fd, bytes.data(), bytes.size(), 0) < 0) return fail_soon();
    if (loop_.add_fd(p.fd, net::kReadable, [this, id](uint32_t) { on_readable(id); })) return fail_soon();

    ++stats_.sent;
    p.timer = loop_.add_timer(timeout, [this, id] {
        ++stats_.timeouts;
        finish(id, std::unexpected(UpstreamError::Timeout));
    });
    return id;
}

void UpstreamClient::cancel(QueryId id) {
    auto it = pending_.find(id);
    if (it == pending_.end()) return;
    release(it->second);
    pending_.erase(it);
}

void UpstreamClient::release(Pending& p) {
    if (p.fd >= 0) {
        loop_.remove_fd(p.fd);
        close(p.fd);
        p.fd = -1;
    }
    if (p.timer) loop_.cancel_timer(p.timer);
    p.timer = 0;
}

void UpstreamClient::finish(QueryId id, std::expected<Message, UpstreamError> result) {
    auto it = pending_.find(id);
    if (it == pending_.end()) return;
    Callback done = std::move(it->second.done);
    release(it->second);
    pending_.erase(it);
    done(std::move(result));  // last: it may send new queries or destroy us
}

void UpstreamClient::on_readable(QueryId id) {
    auto it = pending_.find(id);
    if (it == pending_.end()) return;
    Pending& p = it->second;

    while (true) {
        const ssize_t n = recv(p.fd, buffer_.data(), buffer_.size(), 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            if (errno == EINTR) continue;
            // ECONNREFUSED: ICMP port unreachable, nobody is listening.
            ++stats_.errors;
            finish(id, std::unexpected(UpstreamError::NetworkError));
            return;
        }

        auto msg = wire::parse(std::span<const uint8_t>(buffer_.data(), static_cast<size_t>(n)));
        const bool matches = msg && msg->header.qr && msg->header.id == p.txid &&
                             msg->questions.size() == 1 && msg->questions.front() == p.question;
        if (!matches) {
            ++stats_.mismatched;
            continue;  // keep waiting for the real answer
        }
        ++stats_.answered;
        finish(id, std::move(*msg));
        return;
    }
}

}  // namespace dnsentinel::resolver
