/// @file tests/unit/resolver/test_weak_mode.cpp
/// The lab-only weak-mode knobs (plan §5.10). This whole file compiles to
/// nothing unless the build is configured with -DDNSENTINEL_WEAK_MODE=ON, so
/// a release build can't even be tested for weakness: it has none.

#ifdef DNSENTINEL_WEAK_MODE

#include "dnsentinel/resolver/upstream.h"
#include "dnsentinel/resolver/weak_mode.h"

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
#include <functional>
#include <optional>
#include <set>
#include <span>
#include <vector>

using namespace dnsentinel;
using namespace dnsentinel::resolver;
using namespace dnsentinel::test;
using namespace std::chrono_literals;
using Result = std::expected<Message, UpstreamError>;

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

/// A UDP socket that answers every query and records the source port and ID
/// each one arrived with — what an on-path observer (or the victim) sees.
class RecordingServer {
public:
    explicit RecordingServer(net::EventLoop& loop) : loop_(loop) {
        fd_              = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        sockaddr_in addr = loopback(0);
        EXPECT_EQ(bind(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof addr), 0);
        socklen_t len = sizeof addr;
        getsockname(fd_, reinterpret_cast<sockaddr*>(&addr), &len);
        port = ntohs(addr.sin_port);
        EXPECT_FALSE(loop_.add_fd(fd_, net::kReadable, [this](uint32_t) { on_readable(); }));
    }
    ~RecordingServer() {
        loop_.remove_fd(fd_);
        close(fd_);
    }

    uint16_t                                   port = 0;
    std::vector<uint16_t>                      ids;    // transaction ID of each query seen
    std::vector<uint16_t>                      ports;  // its source port

private:
    void on_readable() {
        std::vector<uint8_t> buf(65535);
        sockaddr_in          peer{};
        socklen_t            len = sizeof peer;
        ssize_t              n;
        while ((n = recvfrom(fd_, buf.data(), buf.size(), 0, reinterpret_cast<sockaddr*>(&peer), &len)) > 0) {
            auto q = wire::parse(std::span<const uint8_t>(buf.data(), static_cast<size_t>(n)));
            ASSERT_TRUE(q.has_value());
            ids.push_back(q->header.id);
            ports.push_back(ntohs(peer.sin_port));
            Message r   = wire::make_response(*q);
            r.header.aa = true;
            r.answers.push_back(make_rr("www.example.test", RRType::A, ipv4("192.0.2.1")));
            const auto bytes = wire::build(r);
            sendto(fd_, bytes.data(), bytes.size(), 0, reinterpret_cast<sockaddr*>(&peer), len);
        }
    }

    net::EventLoop& loop_;
    int             fd_ = -1;
};

class WeakModeTest : public ::testing::Test {
protected:
    std::unique_ptr<net::EventLoop> loop = net::EventLoop::create().value();

    void run_for(std::chrono::milliseconds limit) {
        auto guard = loop->add_timer(limit, [this] { loop->stop(); });
        loop->run();
        loop->cancel_timer(guard);
    }

    /// Send `count` queries, each only after the previous one finishes, as
    /// iterative resolution does (one query to a server at a time).
    void send_n(UpstreamClient& client, RecordingServer& server, int count) {
        int                      done = 0;
        std::function<void()>    next = [&] {
            if (done == count) {
                loop->stop();
                return;
            }
            client.send(loopback(server.port), query_for("www.example.test"), 2s, [&](Result) {
                ++done;
                next();
            });
        };
        next();
        run_for(3s);
        EXPECT_EQ(done, count);
    }
};

}  // namespace

TEST_F(WeakModeTest, OffItBehavesNormally) {
    RecordingServer server(*loop);
    UpstreamClient  client(*loop);
    client.set_weak_mode(WeakMode{});  // weaken == false
    send_n(client, server, 8);

    std::set<uint16_t> ids(server.ids.begin(), server.ids.end());
    std::set<uint16_t> ports(server.ports.begin(), server.ports.end());
    EXPECT_GT(ids.size(), 1u);    // random IDs
    EXPECT_GT(ports.size(), 1u);  // a fresh ephemeral port each time
}

TEST_F(WeakModeTest, KnobsDoNothingUnlessWeakenIsSet) {
    RecordingServer server(*loop);
    UpstreamClient  client(*loop);
    // weaken stays false: the lab knobs must be ignored, not applied.
    client.set_weak_mode({.weaken = false, .sequential_txid = true, .fixed_source_port = 35353});
    send_n(client, server, 5);
    EXPECT_NE(server.ids, (std::vector<uint16_t>{0, 1, 2, 3, 4}));  // not sequential
    std::set<uint16_t> ports(server.ports.begin(), server.ports.end());
    EXPECT_GT(ports.size(), 1u);  // not the fixed port
}

TEST_F(WeakModeTest, SequentialIdsArePredictable) {
    RecordingServer server(*loop);
    UpstreamClient  client(*loop);
    client.set_weak_mode({.weaken = true, .sequential_txid = true});
    send_n(client, server, 5);
    EXPECT_EQ(server.ids, (std::vector<uint16_t>{0, 1, 2, 3, 4}));
}

TEST_F(WeakModeTest, ShrunkIdSpaceStaysWithinItsBits) {
    RecordingServer server(*loop);
    UpstreamClient  client(*loop);
    client.set_weak_mode({.weaken = true, .txid_bits = 6});  // random, but only 0..63
    send_n(client, server, 60);
    for (uint16_t id : server.ids) EXPECT_LT(id, 1u << 6) << id;
    std::set<uint16_t> ids(server.ids.begin(), server.ids.end());
    EXPECT_GT(ids.size(), 1u);  // still random within the small space
}

TEST_F(WeakModeTest, FixedSourcePortIsReused) {
    RecordingServer server(*loop);
    UpstreamClient  client(*loop);
    client.set_weak_mode({.weaken = true, .fixed_source_port = 35353});
    send_n(client, server, 4);
    for (uint16_t p : server.ports) EXPECT_EQ(p, 35353) << "every query from the same port";
}

TEST_F(WeakModeTest, ZeroFixedPortKeepsRandomPorts) {
    RecordingServer server(*loop);
    UpstreamClient  client(*loop);
    client.set_weak_mode({.weaken = true, .sequential_txid = true, .fixed_source_port = 0});
    send_n(client, server, 6);
    std::set<uint16_t> ports(server.ports.begin(), server.ports.end());
    EXPECT_GT(ports.size(), 1u);
}

#endif  // DNSENTINEL_WEAK_MODE
