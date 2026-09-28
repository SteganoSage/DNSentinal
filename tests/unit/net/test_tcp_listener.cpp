#include "dnsentinel/net/tcp_listener.h"

#include "dnsentinel/wire/builder.h"
#include "dnsentinel/wire/parser.h"
#include "../wire/wire_test_util.h"

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <optional>
#include <span>
#include <string>
#include <vector>

using namespace dnsentinel;
using namespace dnsentinel::net;
using namespace dnsentinel::test;
using namespace std::chrono_literals;

namespace {

sockaddr_in v4(const char* ip, uint16_t port) {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    EXPECT_EQ(inet_pton(AF_INET, ip, &addr.sin_addr), 1) << ip;
    return addr;
}

Message query(uint16_t id) {
    Message q;
    q.header.id = id;
    q.header.rd = true;
    q.questions.push_back({name("example.com"), 1, 1});
    return q;
}

/// A TCP client on the loop. It collects framed replies and stops the loop
/// once `expected` have arrived, or when the server closes the connection.
class TcpClient {
public:
    TcpClient(EventLoop& loop, uint16_t port, const char* from = "127.0.0.1") : loop_(loop) {
        fd_ = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        const sockaddr_in local = v4(from, 0);
        EXPECT_EQ(bind(fd_, reinterpret_cast<const sockaddr*>(&local), sizeof local), 0);
        const sockaddr_in server = v4("127.0.0.1", port);
        // Blocking connect: on loopback the kernel completes the handshake
        // from the listen backlog, before the server calls accept().
        EXPECT_EQ(connect(fd_, reinterpret_cast<const sockaddr*>(&server), sizeof server), 0);
        fcntl(fd_, F_SETFL, O_NONBLOCK);
        EXPECT_FALSE(loop_.add_fd(fd_, kReadable, [this](uint32_t) { drain(); }));
    }
    ~TcpClient() {
        loop_.remove_fd(fd_);
        close(fd_);
    }

    void send(std::span<const uint8_t> bytes) {
        ASSERT_EQ(::send(fd_, bytes.data(), bytes.size(), MSG_NOSIGNAL), static_cast<ssize_t>(bytes.size()));
    }
    void send_query(uint16_t id) { send(wire::build_tcp(query(id))); }
    void finish_sending() { shutdown(fd_, SHUT_WR); }

    size_t               expected = 1;
    std::vector<Message> replies;
    bool                 closed = false;  // by the server

private:
    void drain() {
        uint8_t buf[4096];
        while (true) {
            const ssize_t n = recv(fd_, buf, sizeof buf, 0);
            if (n > 0) {
                in_.insert(in_.end(), buf, buf + n);
                continue;
            }
            if (n == 0 || errno == ECONNRESET) {
                closed = true;
                loop_.remove_fd(fd_);
            }
            break;
        }
        while (in_.size() >= 2) {
            const size_t length = (size_t{in_[0]} << 8) | in_[1];
            if (in_.size() - 2 < length) break;
            auto msg = wire::parse(std::span<const uint8_t>(in_.data() + 2, length));
            ASSERT_TRUE(msg.has_value());
            replies.push_back(std::move(*msg));
            in_.erase(in_.begin(), in_.begin() + static_cast<ptrdiff_t>(2 + length));
        }
        if (closed || replies.size() >= expected) loop_.stop();
    }

    EventLoop&           loop_;
    int                  fd_ = -1;
    std::vector<uint8_t> in_;
};

class TcpListenerTest : public ::testing::Test {
protected:
    std::unique_ptr<EventLoop> loop = EventLoop::create().value();
    std::vector<ClientInfo>    clients;
    uint32_t                   answer_records = 1;

    /// Answers every query at once with `answer_records` A records.
    QueryHandler answering_handler() {
        return [this](Message q, const ClientInfo& client, Responder respond) {
            clients.push_back(client);
            Message r = wire::make_response(q);
            for (uint32_t i = 0; i < answer_records; ++i) r.answers.push_back(make_rr("example.com", RRType::A, RDataA{i}));
            respond(r);
        };
    }

    std::unique_ptr<TcpListener> listen(QueryHandler handler, TcpListenerConfig config = {}) {
        config.address = "127.0.0.1";
        config.port    = 0;
        auto l         = TcpListener::create(*loop, config, std::move(handler));
        EXPECT_TRUE(l.has_value()) << (l ? "" : l.error().message());
        return l ? std::move(*l) : nullptr;
    }

    /// Runs the loop until something stops it; false on timeout.
    bool run(std::chrono::milliseconds timeout = 2s) {
        bool timed_out = false;
        auto id        = loop->add_timer(timeout, [&] {
            timed_out = true;
            loop->stop();
        });
        loop->run();
        loop->cancel_timer(id);
        return !timed_out;
    }
};

}  // namespace

TEST_F(TcpListenerTest, AnswersAQuery) {
    auto listener = listen(answering_handler());
    ASSERT_TRUE(listener);
    TcpClient client(*loop, listener->port());
    client.send_query(0x1111);
    ASSERT_TRUE(run());

    ASSERT_EQ(client.replies.size(), 1u);
    EXPECT_EQ(client.replies[0].header.id, 0x1111);
    EXPECT_TRUE(client.replies[0].header.qr);
    ASSERT_EQ(clients.size(), 1u);
    EXPECT_EQ(clients[0].transport, Transport::Tcp);
    EXPECT_EQ(listener->stats().accepted, 1u);
    EXPECT_EQ(listener->stats().queries, 1u);
    EXPECT_EQ(listener->stats().responses_sent, 1u);
}

TEST_F(TcpListenerTest, LargeAnswersAreNotTruncated) {
    answer_records = 300;  // ~5 KB: far beyond any UDP answer we'd send
    auto listener  = listen(answering_handler());
    ASSERT_TRUE(listener);
    TcpClient client(*loop, listener->port());
    client.send_query(1);
    ASSERT_TRUE(run());
    ASSERT_EQ(client.replies.size(), 1u);
    EXPECT_FALSE(client.replies[0].header.tc);
    EXPECT_EQ(client.replies[0].answers.size(), 300u);
}

TEST_F(TcpListenerTest, PipelinedQueriesAreAnsweredAsTheyAreReady) {
    std::vector<std::pair<Message, Responder>> held;
    auto listener = listen([&](Message q, const ClientInfo&, Responder respond) {
        held.emplace_back(std::move(q), std::move(respond));
        if (held.size() < 3) return;
        for (auto it = held.rbegin(); it != held.rend(); ++it) it->second(wire::make_response(it->first));  // last first
    });
    ASSERT_TRUE(listener);
    TcpClient client(*loop, listener->port());
    client.expected = 3;
    std::vector<uint8_t> three;  // one write carrying three queries
    for (uint16_t id : {1, 2, 3}) {
        auto framed = wire::build_tcp(query(id));
        three.insert(three.end(), framed.begin(), framed.end());
    }
    client.send(three);
    ASSERT_TRUE(run());

    ASSERT_EQ(client.replies.size(), 3u);
    EXPECT_EQ(client.replies[0].header.id, 3);
    EXPECT_EQ(client.replies[1].header.id, 2);
    EXPECT_EQ(client.replies[2].header.id, 1);
}

TEST_F(TcpListenerTest, QueryArrivingInPiecesIsReassembled) {
    auto listener = listen(answering_handler());
    ASSERT_TRUE(listener);
    TcpClient  client(*loop, listener->port());
    const auto framed = wire::build_tcp(query(0x2222));
    client.send(std::span(framed).first(1));  // half the length prefix
    EXPECT_FALSE(run(50ms));
    client.send(std::span(framed).subspan(1, 8));
    EXPECT_FALSE(run(50ms));
    client.send(std::span(framed).subspan(9));
    ASSERT_TRUE(run());
    ASSERT_EQ(client.replies.size(), 1u);
    EXPECT_EQ(client.replies[0].header.id, 0x2222);
}

TEST_F(TcpListenerTest, GarbageClosesTheConnection) {
    auto listener = listen(answering_handler());
    ASSERT_TRUE(listener);
    TcpClient client(*loop, listener->port());
    const uint8_t garbage[] = {0x00, 0x05, 'h', 'e', 'l', 'l', 'o'};
    client.send(garbage);
    ASSERT_TRUE(run());
    EXPECT_TRUE(client.closed);
    EXPECT_TRUE(client.replies.empty());
    EXPECT_EQ(listener->stats().dropped_malformed, 1u);
    EXPECT_EQ(listener->connections(), 0u);
}

TEST_F(TcpListenerTest, IdleConnectionIsClosedEvenIfItTricklesBytes) {
    auto listener = listen(answering_handler(), {.idle_timeout_ms = 50});
    ASSERT_TRUE(listener);
    TcpClient  client(*loop, listener->port());
    const auto framed = wire::build_tcp(query(1));
    client.send(std::span(framed).first(3));  // never finished
    ASSERT_TRUE(run());
    EXPECT_TRUE(client.closed);
    EXPECT_EQ(listener->stats().idle_closed, 1u);
    EXPECT_EQ(listener->connections(), 0u);
}

TEST_F(TcpListenerTest, SlowAnswerOutlivesTheIdleTimeout) {
    auto listener = listen(
        [&](Message q, const ClientInfo&, Responder respond) {
            loop->add_timer(150ms, [q, respond] { respond(wire::make_response(q)); });  // resolving takes a while
        },
        {.idle_timeout_ms = 50});
    ASSERT_TRUE(listener);
    TcpClient client(*loop, listener->port());
    client.send_query(7);
    ASSERT_TRUE(run());
    ASSERT_EQ(client.replies.size(), 1u);
    EXPECT_EQ(client.replies[0].header.id, 7);
    EXPECT_FALSE(client.closed);
}

TEST_F(TcpListenerTest, ClientThatStopsSendingStillGetsItsAnswer) {
    auto listener = listen([&](Message q, const ClientInfo&, Responder respond) {
        loop->add_timer(20ms, [q, respond] { respond(wire::make_response(q)); });
    });
    ASSERT_TRUE(listener);
    TcpClient client(*loop, listener->port());
    client.expected = 2;  // run until the server closes
    client.send_query(9);
    client.finish_sending();
    ASSERT_TRUE(run());
    ASSERT_EQ(client.replies.size(), 1u);
    EXPECT_EQ(client.replies[0].header.id, 9);
    EXPECT_TRUE(client.closed);  // then the server hangs up: nothing more is owed
}

TEST_F(TcpListenerTest, ConnectionLimitsAreEnforced) {
    auto listener = listen(answering_handler(), {.max_connections = 3, .max_per_client = 2});
    ASSERT_TRUE(listener);
    TcpClient a(*loop, listener->port(), "127.0.0.1");
    TcpClient b(*loop, listener->port(), "127.0.0.1");
    TcpClient c(*loop, listener->port(), "127.0.0.1");  // third from one address: over max_per_client
    ASSERT_TRUE(run());
    EXPECT_TRUE(c.closed);

    TcpClient d(*loop, listener->port(), "127.0.0.2");
    TcpClient e(*loop, listener->port(), "127.0.0.3");  // fourth in all: over max_connections
    ASSERT_TRUE(run());
    EXPECT_TRUE(e.closed);
    EXPECT_EQ(listener->stats().rejected, 2u);
    EXPECT_EQ(listener->connections(), 3u);

    for (TcpClient* client : {&a, &b, &d}) {  // the others still work
        client->send_query(1);
        ASSERT_TRUE(run());
        EXPECT_EQ(client->replies.size(), 1u);
        EXPECT_FALSE(client->closed);
    }
}

TEST_F(TcpListenerTest, ResponderAfterListenerIsGoneDoesNothing) {
    std::optional<std::pair<Message, Responder>> held;
    auto listener = listen([&](Message q, const ClientInfo&, Responder respond) {
        held.emplace(std::move(q), std::move(respond));
        loop->stop();
    });
    ASSERT_TRUE(listener);
    TcpClient client(*loop, listener->port());
    client.send_query(1);
    ASSERT_TRUE(run());
    ASSERT_TRUE(held.has_value());

    listener.reset();
    held->second(wire::make_response(held->first));  // must not crash or send
    run(50ms);
    EXPECT_TRUE(client.replies.empty());
}

TEST_F(TcpListenerTest, RejectsInvalidAddress) {
    auto l = TcpListener::create(*loop, {.address = "not-an-ip", .port = 0}, answering_handler());
    ASSERT_FALSE(l.has_value());
    EXPECT_EQ(l.error(), std::errc::invalid_argument);
}
