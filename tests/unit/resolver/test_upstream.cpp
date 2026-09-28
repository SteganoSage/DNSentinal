#include "dnsentinel/resolver/upstream.h"

#include "dnsentinel/net/event_loop.h"
#include "dnsentinel/wire/builder.h"
#include "dnsentinel/wire/parser.h"
#include "../wire/wire_test_util.h"

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <optional>
#include <set>
#include <span>
#include <vector>

using namespace dnsentinel;
using namespace dnsentinel::resolver;
using namespace dnsentinel::test;
using namespace std::chrono_literals;
using Result = std::expected<Message, UpstreamError>;
using Clock  = std::chrono::steady_clock;

namespace {

sockaddr_in loopback(uint16_t port) {
    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return addr;
}

Message query_for(std::string_view qname) {
    Message q;
    q.questions.push_back({name(qname), 1, 1});
    return q;
}

/// A bare UDP socket standing in for a DNS server, so tests control the
/// exact datagrams sent back (including forged ones).
class RawServer {
public:
    explicit RawServer(net::EventLoop& loop) : loop_(loop) {
        fd_ = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        sockaddr_in addr = loopback(0);
        EXPECT_EQ(bind(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof addr), 0);
        socklen_t len = sizeof addr;
        getsockname(fd_, reinterpret_cast<sockaddr*>(&addr), &len);
        port = ntohs(addr.sin_port);
        EXPECT_FALSE(loop_.add_fd(fd_, net::kReadable, [this](uint32_t) { on_readable(); }));
    }
    ~RawServer() {
        loop_.remove_fd(fd_);
        close(fd_);
    }

    /// Datagrams to send back for each query, in order.
    std::function<std::vector<std::vector<uint8_t>>(const Message&)> reply;
    uint16_t                                         port = 0;
    std::vector<std::pair<uint16_t, uint16_t>>       seen;  // (client port, query ID)

private:
    void on_readable() {
        std::vector<uint8_t> buf(65535);
        sockaddr_in peer{};
        socklen_t   len = sizeof peer;
        ssize_t     n;
        while ((n = recvfrom(fd_, buf.data(), buf.size(), 0, reinterpret_cast<sockaddr*>(&peer), &len)) > 0) {
            auto q = wire::parse(std::span<const uint8_t>(buf.data(), static_cast<size_t>(n)));
            ASSERT_TRUE(q.has_value());
            seen.emplace_back(ntohs(peer.sin_port), q->header.id);
            if (!reply) continue;
            for (const auto& datagram : reply(*q)) {
                sendto(fd_, datagram.data(), datagram.size(), 0, reinterpret_cast<sockaddr*>(&peer), len);
            }
        }
    }

    net::EventLoop& loop_;
    int             fd_ = -1;
};

std::vector<uint8_t> answer_to(const Message& q) {
    Message r = wire::make_response(q);
    r.header.aa = true;
    r.answers.push_back(make_rr("www.example.test", RRType::A, ipv4("192.0.2.1")));
    return wire::build(r);
}

class UpstreamTest : public ::testing::Test {
protected:
    std::unique_ptr<net::EventLoop> loop = net::EventLoop::create().value();

    void run_for(std::chrono::milliseconds limit) {
        auto guard = loop->add_timer(limit, [this] { loop->stop(); });
        loop->run();
        loop->cancel_timer(guard);
    }
};

}  // namespace

TEST_F(UpstreamTest, AcceptsOnlyTheMatchingResponse) {
    RawServer server(*loop);
    server.reply = [](const Message& q) {
        Message wrong_id = wire::make_response(q);
        wrong_id.header.id ^= 1;
        Message wrong_question = wire::make_response(q);
        wrong_question.questions[0].qname = name("other.example.test");
        return std::vector<std::vector<uint8_t>>{
            {0xde, 0xad},  // garbage
            wire::build(wrong_id),
            wire::build(wrong_question),
            answer_to(q),  // the real one, last
        };
    };

    UpstreamClient client(*loop);
    std::optional<Result> result;
    client.send(loopback(server.port), query_for("www.example.test"), 2s, [&](Result r) {
        result = std::move(r);
        loop->stop();
    });
    run_for(3s);

    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->has_value());
    EXPECT_EQ((*result)->answers.size(), 1u);
    EXPECT_EQ((*result)->header.id, server.seen.at(0).second);
    EXPECT_EQ(client.stats().mismatched, 3u);
    EXPECT_EQ(client.stats().answered, 1u);
}

TEST_F(UpstreamTest, TimesOutWhenNothingAnswers) {
    RawServer server(*loop);  // receives, never replies
    UpstreamClient client(*loop);
    std::optional<Result> result;
    const auto start = Clock::now();
    client.send(loopback(server.port), query_for("www.example.test"), 50ms, [&](Result r) {
        result = std::move(r);
        loop->stop();
    });
    run_for(2s);
    ASSERT_TRUE(result.has_value());
    ASSERT_FALSE(result->has_value());
    EXPECT_EQ(result->error(), UpstreamError::Timeout);
    EXPECT_GE(Clock::now() - start, 50ms);
}

TEST_F(UpstreamTest, ClosedPortIsANetworkError) {
    uint16_t closed_port;
    {
        RawServer temp(*loop);
        closed_port = temp.port;
    }  // closed: the kernel answers with ICMP port unreachable

    UpstreamClient client(*loop);
    std::optional<Result> result;
    const auto start = Clock::now();
    client.send(loopback(closed_port), query_for("www.example.test"), 5s, [&](Result r) {
        result = std::move(r);
        loop->stop();
    });
    run_for(6s);
    ASSERT_TRUE(result.has_value());
    ASSERT_FALSE(result->has_value());
    EXPECT_EQ(result->error(), UpstreamError::NetworkError);
    EXPECT_LT(Clock::now() - start, 1s);  // didn't wait for the timeout
}

TEST_F(UpstreamTest, CancelledQueryNeverCallsBack) {
    RawServer server(*loop);
    server.reply = [](const Message& q) { return std::vector<std::vector<uint8_t>>{answer_to(q)}; };
    UpstreamClient client(*loop);
    bool called = false;
    auto id     = client.send(loopback(server.port), query_for("www.example.test"), 1s,
                              [&](Result) { called = true; });
    client.cancel(id);
    run_for(100ms);
    EXPECT_FALSE(called);
}

TEST_F(UpstreamTest, CallbackNeverRunsInsideSend) {
    UpstreamClient client(*loop);
    sockaddr_in broadcast = loopback(53);
    broadcast.sin_addr.s_addr = htonl(INADDR_BROADCAST);  // connect() refuses this
    bool returned = false;
    std::optional<Result> result;
    client.send(broadcast, query_for("www.example.test"), 1s, [&](Result r) {
        EXPECT_TRUE(returned);
        result = std::move(r);
        loop->stop();
    });
    returned = true;
    run_for(2s);
    ASSERT_TRUE(result.has_value());
    ASSERT_FALSE(result->has_value());
    EXPECT_EQ(result->error(), UpstreamError::NetworkError);
}

TEST_F(UpstreamTest, EveryQueryGetsAFreshPortAndARandomId) {
    // Plan §5.1: an off-path spoofer must guess both.
    RawServer server(*loop);
    server.reply = [](const Message& q) { return std::vector<std::vector<uint8_t>>{answer_to(q)}; };
    UpstreamClient client(*loop);
    int done = 0;
    for (int i = 0; i < 32; ++i) {
        client.send(loopback(server.port), query_for("www.example.test"), 2s, [&](Result r) {
            EXPECT_TRUE(r.has_value());
            if (++done == 32) loop->stop();
        });
    }
    run_for(3s);
    ASSERT_EQ(server.seen.size(), 32u);

    std::set<uint16_t> ports, ids;
    bool sequential = true;
    for (size_t i = 0; i < server.seen.size(); ++i) {
        ports.insert(server.seen[i].first);
        ids.insert(server.seen[i].second);
        if (i > 0 && server.seen[i].second != static_cast<uint16_t>(server.seen[i - 1].second + 1)) {
            sequential = false;
        }
    }
    EXPECT_EQ(ports.size(), 32u);  // all in flight at once, each on its own socket
    EXPECT_GE(ids.size(), 30u);    // 16-bit random IDs rarely collide
    EXPECT_FALSE(sequential);
}
