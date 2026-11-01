#include "dnsentinel/telemetry/metrics_server.h"
#include "dnsentinel/telemetry/query_metrics.h"

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <memory>
#include <string>

using namespace dnsentinel;
using namespace dnsentinel::telemetry;
using namespace std::chrono_literals;

namespace {

TEST(QueryMetrics, CountsByLabelsAndBucketsTheLatency) {
    QueryMetrics m;
    m.record(net::Transport::Udp, 1, 0, Action::Answer, 80us);      // le 0.0001
    m.record(net::Transport::Udp, 1, 0, Action::Answer, 100us);     // le 0.0001: bounds are inclusive
    m.record(net::Transport::Doh, 16, 3, Action::Dynamic, 3ms);     // le 0.005
    m.record(net::Transport::Tcp, 99, 9, Action::Answer, 30s);      // past every bucket: only +Inf
    EXPECT_EQ(m.total(), 4u);

    std::string text;
    m.render(text);
    EXPECT_EQ(text.find("# HELP dnsentinel_queries_total "), 0u) << text;
    EXPECT_NE(text.find("# TYPE dnsentinel_queries_total counter\n"), std::string::npos);
    EXPECT_NE(text.find(R"(dnsentinel_queries_total{transport="udp",qtype="A",rcode="NOERROR",action="answer"} 2)" "\n"),
              std::string::npos)
        << text;
    EXPECT_NE(text.find(R"(dnsentinel_queries_total{transport="doh",qtype="TXT",rcode="NXDOMAIN",action="dynamic_rule"} 1)"),
              std::string::npos)
        << text;
    // types and rcodes outside the fixed sets are counted together
    EXPECT_NE(text.find(R"(dnsentinel_queries_total{transport="tcp",qtype="other",rcode="other",action="answer"} 1)"),
              std::string::npos)
        << text;
    EXPECT_EQ(text.find(R"(action="block")"), std::string::npos);  // only series that happened

    EXPECT_NE(text.find("# TYPE dnsentinel_query_duration_seconds histogram\n"), std::string::npos);
    EXPECT_NE(text.find("dnsentinel_query_duration_seconds_bucket{le=\"0.0001\"} 2\n"), std::string::npos) << text;
    EXPECT_NE(text.find("dnsentinel_query_duration_seconds_bucket{le=\"0.0025\"} 2\n"), std::string::npos);
    EXPECT_NE(text.find("dnsentinel_query_duration_seconds_bucket{le=\"0.005\"} 3\n"), std::string::npos);
    EXPECT_NE(text.find("dnsentinel_query_duration_seconds_bucket{le=\"5\"} 3\n"), std::string::npos);
    EXPECT_NE(text.find("dnsentinel_query_duration_seconds_bucket{le=\"+Inf\"} 4\n"), std::string::npos);
    EXPECT_NE(text.find("dnsentinel_query_duration_seconds_sum 30.003180\n"), std::string::npos) << text;
    EXPECT_NE(text.find("dnsentinel_query_duration_seconds_count 4\n"), std::string::npos);
}

TEST(QueryMetrics, EveryActionHasItsOwnLabel) {
    QueryMetrics m;
    const Action all[] = {Action::Answer,  Action::Block,       Action::CnameBlock, Action::Dynamic,  Action::Dga,
                          Action::Refused, Action::RateLimited, Action::Rejected,   Action::Rebinding};
    for (Action a : all) m.record(net::Transport::Udp, 1, 0, a, 1ms);
    std::string text;
    m.render(text);
    for (Action a : all) {
        EXPECT_NE(text.find("action=\"" + std::string(action_name(a)) + "\"} 1\n"), std::string::npos)
            << action_name(a) << "\n" << text;
    }
}

class MetricsServerTest : public ::testing::Test {
protected:
    void SetUp() override {
        auto made = MetricsServer::create(*loop, {.address = "127.0.0.1", .port = 0}, [this] {
            ++renders;
            return std::string("dnsentinel_test 1\n");
        });
        ASSERT_TRUE(made.has_value()) << made.error();
        server = std::move(*made);
        ASSERT_NE(server->port(), 0);
    }

    void spin(std::chrono::milliseconds time = 50ms) {
        auto guard = loop->add_timer(time, [this] { loop->stop(); });
        loop->run();
        loop->cancel_timer(guard);
    }

    /// Send `request` and return everything the server answers before closing.
    std::string exchange(const std::string& request) {
        const int   fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port   = htons(server->port());
        inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
        EXPECT_EQ(connect(fd, reinterpret_cast<const sockaddr*>(&address), sizeof address), 0) << std::strerror(errno);
        EXPECT_EQ(send(fd, request.data(), request.size(), MSG_NOSIGNAL), static_cast<ssize_t>(request.size()));
        std::string reply;
        char        chunk[4096];
        for (int round = 0; round < 40; ++round) {
            spin(10ms);
            pollfd p{fd, POLLIN, 0};
            if (poll(&p, 1, 0) <= 0) continue;
            const ssize_t n = recv(fd, chunk, sizeof chunk, 0);
            if (n <= 0) break;  // closed: the whole answer is in
            reply.append(chunk, static_cast<size_t>(n));
        }
        close(fd);
        return reply;
    }

    std::unique_ptr<net::EventLoop> loop = net::EventLoop::create().value();
    std::unique_ptr<MetricsServer>  server;
    int                             renders = 0;
};

TEST_F(MetricsServerTest, ServesTheMetricsThenCloses) {
    const std::string reply = exchange("GET /metrics HTTP/1.1\r\nHost: x\r\nAccept: */*\r\n\r\n");
    EXPECT_EQ(reply.find("HTTP/1.1 200 OK\r\n"), 0u) << reply;
    EXPECT_NE(reply.find("Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n"), std::string::npos);
    EXPECT_NE(reply.find("Content-Length: 18\r\n"), std::string::npos) << reply;
    EXPECT_NE(reply.find("Connection: close\r\n"), std::string::npos);
    EXPECT_TRUE(reply.ends_with("\r\n\r\ndnsentinel_test 1\n")) << reply;
    EXPECT_EQ(server->scrapes(), 1u);
    EXPECT_EQ(renders, 1);
}

TEST_F(MetricsServerTest, ARequestInPiecesIsAnsweredWhenComplete) {
    const int   fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port   = htons(server->port());
    inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
    ASSERT_EQ(connect(fd, reinterpret_cast<const sockaddr*>(&address), sizeof address), 0);
    const std::string first = "GET /metrics?x=1 HTTP/1.1\r\nHo";
    ASSERT_EQ(send(fd, first.data(), first.size(), 0), static_cast<ssize_t>(first.size()));
    spin();
    EXPECT_EQ(renders, 0);  // not until the headers end
    const std::string rest = "st: x\r\n\r\n";
    ASSERT_EQ(send(fd, rest.data(), rest.size(), 0), static_cast<ssize_t>(rest.size()));
    spin();
    EXPECT_EQ(renders, 1);  // the query string doesn't matter
    close(fd);
}

TEST_F(MetricsServerTest, AnswersAClientThatShutsItsSideAfterAsking) {
    const int   fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port   = htons(server->port());
    inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
    ASSERT_EQ(connect(fd, reinterpret_cast<const sockaddr*>(&address), sizeof address), 0);
    const std::string request = "GET /metrics HTTP/1.0\r\n\r\n";
    ASSERT_EQ(send(fd, request.data(), request.size(), 0), static_cast<ssize_t>(request.size()));
    shutdown(fd, SHUT_WR);  // as `printf ... | nc` does
    spin();
    char          reply[4096];
    const ssize_t n = recv(fd, reply, sizeof reply, MSG_DONTWAIT);
    ASSERT_GT(n, 0);
    EXPECT_TRUE(std::string(reply, static_cast<size_t>(n)).ends_with("dnsentinel_test 1\n"));
    close(fd);
}

TEST_F(MetricsServerTest, AnswersOtherRequestsWithoutRendering) {
    EXPECT_EQ(exchange("GET / HTTP/1.1\r\n\r\n").find("HTTP/1.1 404 Not Found\r\n"), 0u);
    EXPECT_EQ(exchange("POST /metrics HTTP/1.1\r\nContent-Length: 0\r\n\r\n").find("HTTP/1.1 405 "), 0u);
    EXPECT_EQ(exchange("GET /metrics HTTP/1.1\r\nX: " + std::string(9000, 'a') + "\r\n\r\n").find("HTTP/1.1 431 "),
              0u);
    EXPECT_EQ(renders, 0);
    const std::string head = exchange("HEAD /metrics HTTP/1.1\r\n\r\n");
    EXPECT_EQ(head.find("HTTP/1.1 200 OK\r\n"), 0u) << head;
    EXPECT_TRUE(head.ends_with("\r\n\r\n")) << head;  // headers only
    EXPECT_NE(head.find("Content-Length: 18\r\n"), std::string::npos);
}

TEST_F(MetricsServerTest, RefusesAPortInUseAndABadAddress) {
    auto second = MetricsServer::create(*loop, {.address = "127.0.0.1", .port = server->port()}, [] { return ""; });
    ASSERT_FALSE(second.has_value());
    EXPECT_NE(second.error().find("cannot listen on 127.0.0.1:"), std::string::npos) << second.error();
    auto bad = MetricsServer::create(*loop, {.address = "localhost", .port = 0}, [] { return ""; });
    ASSERT_FALSE(bad.has_value());
    EXPECT_NE(bad.error().find("not an IP address"), std::string::npos);
}

}  // namespace
