#include "dnsentinel/net/udp_listener.h"

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
#include <span>
#include <string>
#include <vector>

using namespace dnsentinel;
using namespace dnsentinel::net;
using namespace dnsentinel::test;
using namespace std::chrono_literals;

namespace {

sockaddr_storage make_addr(const char* ip, uint16_t port) {
    sockaddr_storage addr{};
    auto* v4 = reinterpret_cast<sockaddr_in*>(&addr);
    auto* v6 = reinterpret_cast<sockaddr_in6*>(&addr);
    if (inet_pton(AF_INET, ip, &v4->sin_addr) == 1) {
        v4->sin_family = AF_INET;
        v4->sin_port   = htons(port);
    } else {
        addr = {};
        EXPECT_EQ(inet_pton(AF_INET6, ip, &v6->sin6_addr), 1) << ip;
        v6->sin6_family = AF_INET6;
        v6->sin6_port   = htons(port);
    }
    return addr;
}

std::string ip_of(const sockaddr_storage& addr) {
    char text[INET6_ADDRSTRLEN] = {};
    if (addr.ss_family == AF_INET) {
        inet_ntop(AF_INET, &reinterpret_cast<const sockaddr_in*>(&addr)->sin_addr, text, sizeof text);
    } else {
        inet_ntop(AF_INET6, &reinterpret_cast<const sockaddr_in6*>(&addr)->sin6_addr, text, sizeof text);
    }
    return text;
}

uint16_t port_of(const sockaddr_storage& addr) {
    return ntohs(addr.ss_family == AF_INET ? reinterpret_cast<const sockaddr_in*>(&addr)->sin_port
                                           : reinterpret_cast<const sockaddr_in6*>(&addr)->sin6_port);
}

std::vector<uint8_t> query_bytes(uint16_t id, std::optional<EdnsInfo> edns = std::nullopt) {
    Message q;
    q.header.id = id;
    q.header.rd = true;
    q.questions.push_back({name("example.com"), 1, 1});
    q.edns = edns;
    return wire::build(q);
}

/// A plain UDP socket on the same loop. It collects replies and stops the
/// loop once `expected` of them have arrived.
class TestClient {
public:
    struct Reply {
        Message          msg;
        size_t           size = 0;
        sockaddr_storage from{};
    };

    TestClient(EventLoop& loop, int family) : loop_(loop) {
        fd_ = socket(family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        EXPECT_GE(fd_, 0);
        EXPECT_FALSE(loop_.add_fd(fd_, kReadable, [this](uint32_t) { drain(); }));
    }
    ~TestClient() {
        loop_.remove_fd(fd_);
        close(fd_);
    }

    void send(std::span<const uint8_t> bytes, const sockaddr_storage& to) {
        const socklen_t len = to.ss_family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
        ASSERT_EQ(sendto(fd_, bytes.data(), bytes.size(), 0, reinterpret_cast<const sockaddr*>(&to), len),
                  static_cast<ssize_t>(bytes.size()));
    }

    [[nodiscard]] uint16_t local_port() const {
        sockaddr_storage addr{};
        socklen_t        len = sizeof addr;
        getsockname(fd_, reinterpret_cast<sockaddr*>(&addr), &len);
        return port_of(addr);
    }

    size_t             expected = 1;
    std::vector<Reply> replies;

private:
    void drain() {
        std::vector<uint8_t> buf(65535);
        while (true) {
            Reply     r;
            socklen_t len = sizeof r.from;
            ssize_t   n   = recvfrom(fd_, buf.data(), buf.size(), 0, reinterpret_cast<sockaddr*>(&r.from), &len);
            if (n < 0) break;
            r.size   = static_cast<size_t>(n);
            auto msg = wire::parse(std::span<const uint8_t>(buf.data(), r.size));
            ASSERT_TRUE(msg.has_value());
            r.msg = std::move(*msg);
            replies.push_back(std::move(r));
        }
        if (replies.size() >= expected) loop_.stop();
    }

    EventLoop& loop_;
    int        fd_ = -1;
};

class UdpListenerTest : public ::testing::Test {
protected:
    std::unique_ptr<EventLoop> loop = EventLoop::create().value();
    std::vector<Message>       handled;
    std::vector<ClientInfo>    clients;
    int                        answer_records = 1;

    /// Answers every query with `answer_records` A records.
    QueryHandler answering_handler() {
        return [this](Message query, const ClientInfo& client, Responder respond) {
            clients.push_back(client);
            Message response = wire::make_response(query);
            for (int i = 0; i < answer_records; ++i) {
                response.answers.push_back(make_rr("example.com", RRType::A, RDataA{static_cast<uint32_t>(i)}));
            }
            handled.push_back(std::move(query));
            respond(response);
        };
    }

    std::unique_ptr<UdpListener> listen(const char* address, QueryHandler handler,
                                        uint16_t max_response_size = wire::kEdnsUdpPayloadSize) {
        auto l = UdpListener::create(*loop, {.address = address, .port = 0, .max_response_size = max_response_size},
                                     std::move(handler));
        EXPECT_TRUE(l.has_value()) << (l ? "" : l.error().message());
        return l ? std::move(*l) : nullptr;
    }

    /// Runs the loop until the client stops it; false on timeout.
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

TEST_F(UdpListenerTest, AnswersQuery) {
    auto listener = listen("127.0.0.1", answering_handler());
    ASSERT_TRUE(listener);
    TestClient client(*loop, AF_INET);
    client.send(query_bytes(0x1111), make_addr("127.0.0.1", listener->port()));
    ASSERT_TRUE(run());

    ASSERT_EQ(client.replies.size(), 1u);
    const Message& reply = client.replies[0].msg;
    EXPECT_EQ(reply.header.id, 0x1111);
    EXPECT_TRUE(reply.header.qr);
    EXPECT_EQ(reply.questions, handled.at(0).questions);
    EXPECT_EQ(reply.answers.size(), 1u);

    // The handler sees who asked.
    ASSERT_EQ(clients.size(), 1u);
    EXPECT_EQ(clients[0].transport, Transport::Udp);
    EXPECT_EQ(ip_of(clients[0].addr), "127.0.0.1");
    EXPECT_EQ(port_of(clients[0].addr), client.local_port());

    EXPECT_EQ(listener->stats().queries, 1u);
    EXPECT_EQ(listener->stats().responses_sent, 1u);
}

TEST_F(UdpListenerTest, DropsGarbageAndResponsesSilently) {
    auto listener = listen("127.0.0.1", answering_handler());
    ASSERT_TRUE(listener);
    TestClient client(*loop, AF_INET);
    const auto to = make_addr("127.0.0.1", listener->port());

    std::string garbage = "definitely not dns";
    client.send(std::span(reinterpret_cast<const uint8_t*>(garbage.data()), garbage.size()), to);

    Message q;
    q.questions.push_back({name("example.com"), 1, 1});
    client.send(wire::build(wire::make_response(q)), to);  // QR=1

    client.send(query_bytes(0x2222), to);  // loopback keeps order: this one is processed last
    ASSERT_TRUE(run());

    ASSERT_EQ(client.replies.size(), 1u);
    EXPECT_EQ(client.replies[0].msg.header.id, 0x2222);
    EXPECT_EQ(handled.size(), 1u);
    EXPECT_EQ(listener->stats().dropped_malformed, 1u);
    EXPECT_EQ(listener->stats().dropped_responses, 1u);
    EXPECT_EQ(listener->stats().queries, 1u);
}

TEST_F(UdpListenerTest, SizesResponsesToClientBuffer) {
    answer_records = 60;  // one ~1 KB RRset: too big for 512, fits in 1232
    auto listener  = listen("127.0.0.1", answering_handler());
    ASSERT_TRUE(listener);
    TestClient client(*loop, AF_INET);
    client.expected = 2;
    const auto to   = make_addr("127.0.0.1", listener->port());

    client.send(query_bytes(1), to);                                      // no EDNS: 512
    client.send(query_bytes(2, EdnsInfo{.udp_payload_size = 4096}), to);  // EDNS: ours, 1232
    ASSERT_TRUE(run());
    ASSERT_EQ(client.replies.size(), 2u);

    for (const auto& r : client.replies) {
        if (r.msg.header.id == 1) {
            EXPECT_TRUE(r.msg.header.tc);
            EXPECT_LE(r.size, 512u);
            EXPECT_TRUE(r.msg.answers.empty());  // never a partial RRset
            EXPECT_FALSE(r.msg.edns.has_value());
        } else {
            EXPECT_FALSE(r.msg.header.tc);
            EXPECT_EQ(r.msg.answers.size(), 60u);
            EXPECT_GT(r.size, 512u);
            EXPECT_TRUE(r.msg.edns.has_value());
        }
    }
}

TEST_F(UdpListenerTest, CapsResponsesAtOurBuffer) {
    answer_records = 100;  // ~1.6 KB: more than our 1232 even though the client allows 4096
    auto listener  = listen("127.0.0.1", answering_handler());
    ASSERT_TRUE(listener);
    TestClient client(*loop, AF_INET);
    client.send(query_bytes(1, EdnsInfo{.udp_payload_size = 4096}), make_addr("127.0.0.1", listener->port()));
    ASSERT_TRUE(run());
    ASSERT_EQ(client.replies.size(), 1u);
    EXPECT_TRUE(client.replies[0].msg.header.tc);
    EXPECT_LE(client.replies[0].size, wire::kEdnsUdpPayloadSize);
}

TEST_F(UdpListenerTest, LargerConfiguredBufferAvoidsTruncation) {
    answer_records = 100;
    auto listener  = listen("127.0.0.1", answering_handler(), 4096);
    ASSERT_TRUE(listener);
    TestClient client(*loop, AF_INET);
    client.send(query_bytes(1, EdnsInfo{.udp_payload_size = 4096}), make_addr("127.0.0.1", listener->port()));
    ASSERT_TRUE(run());
    ASSERT_EQ(client.replies.size(), 1u);
    EXPECT_FALSE(client.replies[0].msg.header.tc);
    EXPECT_EQ(client.replies[0].msg.answers.size(), 100u);
}

TEST_F(UdpListenerTest, RepliesFromTheAddressTheClientAsked) {
    // Bound to 0.0.0.0, a query sent to 127.0.0.2 must be answered from
    // 127.0.0.2; without IP_PKTINFO the kernel would pick 127.0.0.1.
    auto listener = listen("0.0.0.0", answering_handler());
    ASSERT_TRUE(listener);
    TestClient client(*loop, AF_INET);
    client.expected = 2;
    client.send(query_bytes(1), make_addr("127.0.0.2", listener->port()));
    client.send(query_bytes(2), make_addr("127.0.0.1", listener->port()));
    ASSERT_TRUE(run());

    ASSERT_EQ(client.replies.size(), 2u);
    for (const auto& r : client.replies) {
        EXPECT_EQ(ip_of(r.from), r.msg.header.id == 1 ? "127.0.0.2" : "127.0.0.1");
        EXPECT_EQ(port_of(r.from), listener->port());
    }
}

TEST_F(UdpListenerTest, Ipv6) {
    auto created = UdpListener::create(*loop, {.address = "::1", .port = 0}, answering_handler());
    if (!created && (created.error() == std::errc::address_not_available ||
                     created.error() == std::errc::address_family_not_supported)) {
        GTEST_SKIP() << "no IPv6 loopback: " << created.error().message();
    }
    ASSERT_TRUE(created.has_value()) << created.error().message();
    auto& listener = *created;

    TestClient client(*loop, AF_INET6);
    client.send(query_bytes(0x6666), make_addr("::1", listener->port()));
    ASSERT_TRUE(run());
    ASSERT_EQ(client.replies.size(), 1u);
    EXPECT_EQ(client.replies[0].msg.header.id, 0x6666);
    EXPECT_EQ(ip_of(client.replies[0].from), "::1");
    EXPECT_EQ(ip_of(clients.at(0).addr), "::1");
}

TEST_F(UdpListenerTest, ResponderCanBeCalledLater) {
    std::vector<std::pair<Message, Responder>> pending;
    auto listener = listen("127.0.0.1", [&](Message q, const ClientInfo&, Responder respond) {
        pending.emplace_back(std::move(q), std::move(respond));
        loop->add_timer(20ms, [&] {
            for (auto& [query, reply] : pending) reply(wire::make_response(query));
            pending.clear();
        });
    });
    ASSERT_TRUE(listener);
    TestClient client(*loop, AF_INET);
    client.send(query_bytes(0x3333), make_addr("127.0.0.1", listener->port()));
    ASSERT_TRUE(run());
    ASSERT_EQ(client.replies.size(), 1u);
    EXPECT_EQ(client.replies[0].msg.header.id, 0x3333);
}

TEST_F(UdpListenerTest, ResponderAfterListenerIsGoneDoesNothing) {
    std::optional<std::pair<Message, Responder>> pending;
    auto listener = listen("127.0.0.1", [&](Message q, const ClientInfo&, Responder respond) {
        pending.emplace(std::move(q), std::move(respond));
        loop->stop();
    });
    ASSERT_TRUE(listener);
    TestClient client(*loop, AF_INET);
    client.send(query_bytes(1), make_addr("127.0.0.1", listener->port()));
    ASSERT_TRUE(run());
    ASSERT_TRUE(pending.has_value());

    listener.reset();
    pending->second(wire::make_response(pending->first));  // must not crash or send
    EXPECT_FALSE(run(50ms));
    EXPECT_TRUE(client.replies.empty());
}

TEST_F(UdpListenerTest, HandlesBurstsLargerThanOneBatch) {
    auto listener = listen("127.0.0.1", answering_handler());
    ASSERT_TRUE(listener);
    TestClient client(*loop, AF_INET);
    client.expected = 100;  // > 64 packets per wakeup
    const auto to   = make_addr("127.0.0.1", listener->port());
    for (uint16_t id = 0; id < 100; ++id) client.send(query_bytes(id), to);
    ASSERT_TRUE(run());
    EXPECT_EQ(client.replies.size(), 100u);
    EXPECT_EQ(listener->stats().queries, 100u);
}

TEST_F(UdpListenerTest, RejectsInvalidAddress) {
    auto l = UdpListener::create(*loop, {.address = "not-an-ip", .port = 0}, answering_handler());
    ASSERT_FALSE(l.has_value());
    EXPECT_EQ(l.error(), std::errc::invalid_argument);
}
