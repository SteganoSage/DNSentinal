/// @file resolver/upstream.cpp
/// One query to one upstream server, over UDP or TCP: fresh socket, random
/// ID, response validation, timeout.

#include "dnsentinel/resolver/upstream.h"

#include "dnsentinel/security/zero_x20.h"
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

enum class Match { No, WrongCase, Yes };

/// Is `msg` the response to our query: same ID and question, and (for
/// 0x20) the question in exactly the case we sent?
Match match(const std::expected<Message, wire::ParseError>& msg, uint16_t txid, const Question& question,
            bool match_case) {
    if (!msg || !msg->header.qr || msg->header.id != txid || msg->questions.size() != 1 ||
        !(msg->questions.front() == question)) {
        return Match::No;
    }
    if (match_case && !security::same_case(msg->questions.front().qname, question.qname)) return Match::WrongCase;
    return Match::Yes;
}

}  // namespace

UpstreamClient::UpstreamClient(net::EventLoop& loop, uint32_t spoof_threshold)
    : loop_(loop), spoof_threshold_(spoof_threshold), buffer_(kMaxDatagram) {}

UpstreamClient::~UpstreamClient() {
    for (auto& [id, p] : pending_) release(p);
}

UpstreamClient::QueryId UpstreamClient::send(const sockaddr_in& server, Message query,
                                             std::chrono::milliseconds timeout, Callback done,
                                             UpstreamTransport transport, bool match_case) {
    const bool    tcp = transport == UpstreamTransport::Tcp;
    const QueryId id  = next_id_++;
    Pending& p = pending_[id];
    p.done       = std::move(done);
    p.match_case = match_case;
    // arc4random is a CSPRNG (glibc >= 2.36 seeds it from getrandom()), so
    // the ID can't be predicted from earlier ones.
    p.txid = static_cast<uint16_t>(arc4random());
#ifdef DNSENTINEL_WEAK_MODE
    if (weak_.weaken) {  // lab-only: a predictable or low-entropy ID (plan §5.10)
        const uint16_t mask = weak_.txid_bits >= 16 ? 0xFFFF
                                                    : static_cast<uint16_t>((1u << weak_.txid_bits) - 1);
        p.txid = static_cast<uint16_t>(weak_.sequential_txid ? weak_seq_++ : arc4random()) & mask;
    }
#endif
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

    p.fd = socket(AF_INET, (tcp ? SOCK_STREAM : SOCK_DGRAM) | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (p.fd < 0) return fail_soon();
#ifdef DNSENTINEL_WEAK_MODE
    if (weak_.weaken && weak_.fixed_source_port != 0 && !tcp) {  // lab-only: a known source port
        const int reuse = 1;
        setsockopt(p.fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof reuse);
        sockaddr_in local{};
        local.sin_family      = AF_INET;
        local.sin_addr.s_addr = htonl(INADDR_ANY);
        local.sin_port        = htons(weak_.fixed_source_port);
        if (bind(p.fd, reinterpret_cast<const sockaddr*>(&local), sizeof local) < 0) return fail_soon();
    }
#endif
    // connect() picks a random ephemeral source port and makes the kernel
    // drop datagrams from any other address or port. For TCP it starts the
    // handshake; the socket turns writable when that completes.
    if (connect(p.fd, reinterpret_cast<const sockaddr*>(&server), sizeof server) < 0 &&
        !(tcp && errno == EINPROGRESS)) {
        return fail_soon();
    }

    if (tcp) {
        p.out = wire::build_tcp(query);
        if (loop_.add_fd(p.fd, net::kWritable, [this, id](uint32_t events) { on_tcp_event(id, events); })) {
            return fail_soon();
        }
        ++stats_.sent_tcp;
    } else {
        const std::vector<uint8_t> bytes = wire::build(query, {.max_size = 512});
        if (::send(p.fd, bytes.data(), bytes.size(), 0) < 0) return fail_soon();
        if (loop_.add_fd(p.fd, net::kReadable, [this, id](uint32_t) { on_readable(id); })) return fail_soon();
    }

    ++stats_.sent;
    p.timer = loop_.add_timer(timeout, [this, id] {
        ++stats_.timeouts;
        auto it = pending_.find(id);
        const bool wrong_case = it != pending_.end() && it->second.wrong_case_seen;
        finish(id, std::unexpected(wrong_case ? UpstreamError::CaseMismatch : UpstreamError::Timeout));
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
        const Match m = match(msg, p.txid, p.question, p.match_case);
        if (m != Match::Yes) {
            if (m == Match::WrongCase) {
                // Forged (the forger didn't know our case pattern), or a server
                // that normalises case. Keep waiting: if the server does echo
                // case, its real answer is still on the way.
                ++stats_.case_mismatches;
                p.wrong_case_seen = true;
            } else {
                ++stats_.mismatched;
            }
            // The socket is connected, so these came from the server's
            // address to our random port: someone who guessed the port, or is
            // spraying all of them, is racing the real answer (Kaminsky).
            if (spoof_threshold_ != 0 && ++p.suspicious >= spoof_threshold_) {
                ++stats_.spoof_alerts;
                finish(id, std::unexpected(UpstreamError::SpoofSuspected));
                return;
            }
            continue;  // keep waiting for the real answer
        }
        ++stats_.answered;
        finish(id, std::move(*msg));
        return;
    }
}

void UpstreamClient::on_tcp_event(QueryId id, uint32_t events) {
    auto it = pending_.find(id);
    if (it == pending_.end()) return;
    Pending& p = it->second;
    auto broke_off = [&] {
        ++stats_.errors;
        finish(id, std::unexpected(UpstreamError::NetworkError));
    };

    if (p.written < p.out.size()) {  // connecting, then sending the query
        if (events & (EPOLLERR | EPOLLHUP)) return broke_off();  // refused, unreachable or reset
        while (p.written < p.out.size()) {
            const ssize_t n = ::send(p.fd, p.out.data() + p.written, p.out.size() - p.written, MSG_NOSIGNAL);
            if (n < 0) {
                if (errno == EINTR) continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK) return;
                return broke_off();
            }
            p.written += static_cast<size_t>(n);
        }
        if (loop_.modify_fd(p.fd, net::kReadable)) return broke_off();
        return;
    }

    while (true) {  // reading the response
        const ssize_t n = recv(p.fd, buffer_.data(), buffer_.size(), 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            return broke_off();
        }
        if (n == 0) return broke_off();  // closed before the whole response arrived
        p.in.insert(p.in.end(), buffer_.begin(), buffer_.begin() + n);
        if (p.in.size() < 2) continue;
        const size_t length = (size_t{p.in[0]} << 8) | p.in[1];
        if (p.in.size() - 2 < length) continue;

        auto msg = wire::parse(std::span<const uint8_t>(p.in.data() + 2, length));
        const Match m = match(msg, p.txid, p.question, p.match_case);
        if (m == Match::WrongCase) {  // nothing else will come on this connection
            ++stats_.case_mismatches;
            finish(id, std::unexpected(UpstreamError::CaseMismatch));
            return;
        }
        if (m == Match::No) {
            ++stats_.mismatched;
            return broke_off();
        }
        ++stats_.answered;
        finish(id, std::move(*msg));
        return;
    }
}

}  // namespace dnsentinel::resolver
