#include "dnsentinel/net/tcp_listener.h"

#include "dnsentinel/wire/builder.h"
#include "dnsentinel/wire/parser.h"
#include "../wire/wire_test_util.h"
#include "tls_test_util.h"

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <functional>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <vector>

using namespace dnsentinel;
using namespace dnsentinel::net;
using namespace dnsentinel::test;
using namespace std::chrono_literals;

namespace {

Message query(uint16_t id) {
    Message q;
    q.header.id = id;
    q.header.rd = true;
    q.questions.push_back({name("example.com"), 1, 1});
    return q;
}

std::string base64url(std::span<const uint8_t> data) {
    static constexpr char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    uint32_t    buffer = 0;
    int         bits   = 0;
    for (uint8_t byte : data) {
        buffer = (buffer << 8) | byte;
        bits += 8;
        while (bits >= 6) {
            bits -= 6;
            out += kAlphabet[(buffer >> bits) & 63];
        }
    }
    if (bits > 0) out += kAlphabet[(buffer << (6 - bits)) & 63];
    return out;  // no padding (RFC 8484 §4.1)
}

std::string post(uint16_t id, const std::string& extra_headers = "") {
    const auto body = wire::build(query(id));
    return "POST /dns-query HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/dns-message\r\nContent-Length: " +
           std::to_string(body.size()) + "\r\n" + extra_headers + "\r\n" + std::string(body.begin(), body.end());
}

std::string get(uint16_t id, const std::string& extra_headers = "") {
    return "GET /dns-query?dns=" + base64url(wire::build(query(id))) + " HTTP/1.1\r\nHost: localhost\r\n" +
           extra_headers + "\r\n";
}

struct HttpResponse {
    int                                status = 0;
    std::map<std::string, std::string> headers;  // names in lower case
    std::vector<uint8_t>               body;

    [[nodiscard]] std::optional<Message> dns() const {
        auto message = wire::parse(body);
        return message ? std::optional(std::move(*message)) : std::nullopt;
    }
};

/// HTTP/1.1 responses with Content-Length bodies, as many as are complete.
std::vector<HttpResponse> parse_responses(const std::vector<uint8_t>& bytes) {
    std::vector<HttpResponse> out;
    const std::string         text(bytes.begin(), bytes.end());
    size_t                    at = 0;
    while (true) {
        const size_t end = text.find("\r\n\r\n", at);
        if (end == std::string::npos) break;
        HttpResponse r;
        r.status    = std::stoi(text.substr(at + 9, 3));  // "HTTP/1.1 200 ..."
        size_t line = text.find("\r\n", at) + 2;
        while (line < end + 2) {
            const size_t eol   = text.find("\r\n", line);
            const size_t colon = text.find(':', line);
            std::string  key   = text.substr(line, colon - line);
            for (char& c : key) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            r.headers[key] = text.substr(colon + 2, eol - colon - 2);
            line           = eol + 2;
        }
        const size_t length = std::stoul(r.headers["content-length"]);
        if (text.size() < end + 4 + length) break;
        r.body.assign(bytes.begin() + static_cast<ptrdiff_t>(end + 4),
                      bytes.begin() + static_cast<ptrdiff_t>(end + 4 + length));
        out.push_back(std::move(r));
        at = end + 4 + length;
    }
    return out;
}

/// A plain TCP client speaking raw HTTP on the loop. Stops the loop once
/// `expected` responses are complete, or the server closes.
class HttpClient {
public:
    HttpClient(EventLoop& loop, uint16_t port) : loop_(loop) {
        fd_ = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        sockaddr_in server{};
        server.sin_family = AF_INET;
        server.sin_port   = htons(port);
        inet_pton(AF_INET, "127.0.0.1", &server.sin_addr);
        EXPECT_EQ(connect(fd_, reinterpret_cast<const sockaddr*>(&server), sizeof server), 0);
        fcntl(fd_, F_SETFL, O_NONBLOCK);
        EXPECT_FALSE(loop_.add_fd(fd_, kReadable, [this](uint32_t) { drain(); }));
    }
    ~HttpClient() {
        loop_.remove_fd(fd_);
        close(fd_);
    }

    void send(const std::string& text) {
        ASSERT_EQ(::send(fd_, text.data(), text.size(), MSG_NOSIGNAL), static_cast<ssize_t>(text.size()));
    }

    [[nodiscard]] std::vector<HttpResponse> responses() const { return parse_responses(received_); }

    size_t expected = 1;
    bool   closed   = false;

private:
    void drain() {
        uint8_t buf[4096];
        while (true) {
            const ssize_t n = recv(fd_, buf, sizeof buf, 0);
            if (n > 0) {
                received_.insert(received_.end(), buf, buf + n);
                continue;
            }
            if (n == 0 || errno == ECONNRESET) {
                closed = true;
                loop_.remove_fd(fd_);
            }
            break;
        }
        if (closed || responses().size() >= expected) loop_.stop();
    }

    EventLoop&           loop_;
    int                  fd_ = -1;
    std::vector<uint8_t> received_;
};

class DohListenerTest : public ::testing::Test {
protected:
    void SetUp() override { signal(SIGPIPE, SIG_IGN); }

    std::unique_ptr<EventLoop> loop = EventLoop::create().value();
    std::vector<ClientInfo>    clients;

    /// Answers at once: one A record with TTL 300.
    QueryHandler answering_handler() {
        return [this](Message q, const ClientInfo& client, Responder respond) {
            clients.push_back(client);
            Message r = wire::make_response(q);
            r.answers.push_back(make_rr("example.com", RRType::A, ipv4("192.0.2.1"), 300));
            respond(r);
        };
    }

    std::unique_ptr<TcpListener> listen(QueryHandler handler, std::shared_ptr<const TlsContext> tls = nullptr) {
        auto l = TcpListener::create(*loop, {.address = "127.0.0.1", .port = 0}, std::move(handler),
                                     {.tls = std::move(tls), .doh_path = "/dns-query"});
        EXPECT_TRUE(l.has_value()) << (l ? "" : l.error().message());
        return l ? std::move(*l) : nullptr;
    }

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

TEST_F(DohListenerTest, PostGetsTheAnswer) {
    auto listener = listen(answering_handler());
    ASSERT_TRUE(listener);
    HttpClient client(*loop, listener->port());
    client.send(post(0x1111));
    ASSERT_TRUE(run());

    auto responses = client.responses();
    ASSERT_EQ(responses.size(), 1u);
    EXPECT_EQ(responses[0].status, 200);
    EXPECT_EQ(responses[0].headers["content-type"], "application/dns-message");
    EXPECT_EQ(responses[0].headers["cache-control"], "max-age=300");
    auto dns = responses[0].dns();
    ASSERT_TRUE(dns.has_value());
    EXPECT_EQ(dns->header.id, 0x1111);
    EXPECT_EQ(dns->answers.size(), 1u);
    ASSERT_EQ(clients.size(), 1u);
    EXPECT_EQ(clients[0].transport, Transport::Doh);
    EXPECT_FALSE(client.closed);  // HTTP/1.1 keeps the connection open
}

TEST_F(DohListenerTest, GetGetsTheAnswer) {
    auto listener = listen(answering_handler());
    ASSERT_TRUE(listener);
    HttpClient client(*loop, listener->port());
    client.send(get(0)); // RFC 8484 §4.1: ID 0, so caches can share answers
    ASSERT_TRUE(run());
    auto responses = client.responses();
    ASSERT_EQ(responses.size(), 1u);
    EXPECT_EQ(responses[0].status, 200);
    ASSERT_TRUE(responses[0].dns().has_value());
    EXPECT_EQ(responses[0].dns()->header.id, 0);
}

TEST_F(DohListenerTest, RequestsWeCantServeGetAnErrorAndTheConnectionLivesOn) {
    const auto garbage_body = std::string("not dns at all");
    const auto response_body = [] {
        auto bytes = wire::build(wire::make_response(query(7)));
        return std::string(bytes.begin(), bytes.end());
    }();
    struct Case {
        std::string request;
        int         status;
    };
    const Case cases[] = {
        {"GET /other HTTP/1.1\r\nHost: x\r\n\r\n", 404},
        {"PUT /dns-query HTTP/1.1\r\nContent-Length: 0\r\n\r\n", 405},
        {"POST /dns-query HTTP/1.1\r\nContent-Type: text/plain\r\nContent-Length: 4\r\n\r\nabcd", 415},
        {"GET /dns-query HTTP/1.1\r\n\r\n", 400},
        {"GET /dns-query?dns=!!!! HTTP/1.1\r\n\r\n", 400},
        {"POST /dns-query HTTP/1.1\r\nContent-Type: application/dns-message\r\nContent-Length: " +
             std::to_string(garbage_body.size()) + "\r\n\r\n" + garbage_body, 400},
        {"POST /dns-query HTTP/1.1\r\nContent-Type: application/dns-message\r\nContent-Length: " +
             std::to_string(response_body.size()) + "\r\n\r\n" + response_body, 400},  // a response, not a query
    };
    auto listener = listen(answering_handler());
    ASSERT_TRUE(listener);
    uint64_t errors = 0;
    for (const auto& c : cases) {
        HttpClient client(*loop, listener->port());
        client.expected = 2;
        client.send(c.request + get(9));  // then a good request on the same connection
        ASSERT_TRUE(run()) << c.request;
        auto responses = client.responses();
        ASSERT_EQ(responses.size(), 2u) << c.request;
        EXPECT_EQ(responses[0].status, c.status) << c.request;
        EXPECT_EQ(responses[0].headers["content-type"], "text/plain; charset=utf-8");
        if (c.status == 405) {
            EXPECT_EQ(responses[0].headers["allow"], "GET, POST");
        }
        EXPECT_EQ(responses[1].status, 200) << c.request;
        EXPECT_FALSE(client.closed) << c.request;
        EXPECT_EQ(listener->stats().http_errors, ++errors);
    }
}

TEST_F(DohListenerTest, RequestsThatBreakTheFramingCloseTheConnection) {
    struct Case {
        std::string request;
        int         status;
    };
    const Case cases[] = {
        {"this is not http\r\n\r\n", 400},
        {"GET /dns-query HTTP/2.0\r\n\r\n", 505},
        {"POST /dns-query HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n", 501},
        {"POST /dns-query HTTP/1.1\r\nContent-Length: 70000\r\n\r\n", 413},
        {"GET /dns-query HTTP/1.1\r\nX-Padding: " + std::string(9000, 'a') + "\r\n\r\n", 431},
        {"GET /dns-query HTTP/1.1\r\n folded: header\r\n\r\n", 400},
    };
    auto listener = listen(answering_handler());
    ASSERT_TRUE(listener);
    for (const auto& c : cases) {
        HttpClient client(*loop, listener->port());
        client.expected = 2;  // run until the server closes
        client.send(c.request + get(9));  // never served: nothing after it can be trusted
        ASSERT_TRUE(run()) << c.request.substr(0, 40);
        auto responses = client.responses();
        ASSERT_EQ(responses.size(), 1u) << c.request.substr(0, 40);
        EXPECT_EQ(responses[0].status, c.status) << c.request.substr(0, 40);
        EXPECT_EQ(responses[0].headers["connection"], "close");
        EXPECT_TRUE(client.closed) << c.request.substr(0, 40);
    }
    EXPECT_TRUE(clients.empty());
}

TEST_F(DohListenerTest, ResponsesComeBackInRequestOrder) {
    // The first query is slow, the second fast: HTTP/1.1 must still answer
    // them in the order they were asked.
    auto listener = listen([&](Message q, const ClientInfo&, Responder respond) {
        const auto delay = q.header.id == 1 ? 50ms : 0ms;
        loop->add_timer(delay, [q, respond] { respond(wire::make_response(q)); });
    });
    ASSERT_TRUE(listener);
    HttpClient client(*loop, listener->port());
    client.expected = 2;
    client.send(post(1) + post(2));
    ASSERT_TRUE(run());
    auto responses = client.responses();
    ASSERT_EQ(responses.size(), 2u);
    EXPECT_EQ(responses[0].dns()->header.id, 1);
    EXPECT_EQ(responses[1].dns()->header.id, 2);
}

TEST_F(DohListenerTest, ConnectionCloseAndHttp10AreHonoured) {
    auto listener = listen(answering_handler());
    ASSERT_TRUE(listener);
    for (const std::string& request :
         {post(1, "Connection: close\r\n"), std::string("GET /dns-query?dns=") + base64url(wire::build(query(2))) +
                                                " HTTP/1.0\r\n\r\n"}) {
        HttpClient client(*loop, listener->port());
        client.expected = 2;  // run until the server closes
        client.send(request);
        ASSERT_TRUE(run());
        auto responses = client.responses();
        ASSERT_EQ(responses.size(), 1u);
        EXPECT_EQ(responses[0].status, 200);
        EXPECT_EQ(responses[0].headers["connection"], "close");
        EXPECT_TRUE(client.closed);
    }
}

TEST_F(DohListenerTest, CacheLifetimeFollowsRfc8484) {
    // NXDOMAIN: the SOA's negative TTL, min(TTL, MINIMUM) = 60. SERVFAIL: 0.
    auto listener = listen([](Message q, const ClientInfo&, Responder respond) {
        Message r = wire::make_response(q, q.header.id == 1 ? RCode::NXDomain : RCode::ServFail);
        if (q.header.id == 1) {
            r.authority.push_back(make_rr("com", RRType::SOA, RDataSOA{name("a.com"), name("b.com"), 1, 2, 3, 4, 60}, 300));
        }
        respond(r);
    });
    ASSERT_TRUE(listener);
    HttpClient client(*loop, listener->port());
    client.expected = 2;
    client.send(post(1) + post(2));
    ASSERT_TRUE(run());
    auto responses = client.responses();
    ASSERT_EQ(responses.size(), 2u);
    EXPECT_EQ(responses[0].headers["cache-control"], "max-age=60");
    EXPECT_EQ(responses[1].headers["cache-control"], "max-age=0");
}

TEST_F(DohListenerTest, RequestArrivingInPiecesIsReassembled) {
    auto listener = listen(answering_handler());
    ASSERT_TRUE(listener);
    HttpClient        client(*loop, listener->port());
    const std::string request = post(3);
    client.send(request.substr(0, 10));
    EXPECT_FALSE(run(50ms));
    client.send(request.substr(10, request.size() - 15));  // all but the end of the body
    EXPECT_FALSE(run(50ms));
    client.send(request.substr(request.size() - 5));
    ASSERT_TRUE(run());
    auto responses = client.responses();
    ASSERT_EQ(responses.size(), 1u);
    EXPECT_EQ(responses[0].dns()->header.id, 3);
}

TEST_F(DohListenerTest, OverTls) {
    TestCert cert;
    auto     tls = TlsContext::create_server(cert.cert, cert.key, {"http/1.1"});
    ASSERT_TRUE(tls.has_value()) << tls.error();
    auto listener = listen(answering_handler(), *tls);
    ASSERT_TRUE(listener);
    const std::string request = get(0x4242);
    TlsClient         client(*loop, listener->port(), cert.cert, std::vector<uint8_t>(request.begin(), request.end()),
                             [](const std::vector<uint8_t>& got) { return !parse_responses(got).empty(); }, "http/1.1");
    ASSERT_TRUE(run(5s));
    client.join();
    EXPECT_TRUE(client.result.handshake);
    EXPECT_EQ(client.result.alpn, "http/1.1");
    auto responses = parse_responses(client.result.received);
    ASSERT_EQ(responses.size(), 1u);
    EXPECT_EQ(responses[0].status, 200);
    EXPECT_EQ(responses[0].dns()->header.id, 0x4242);
    ASSERT_EQ(clients.size(), 1u);
    EXPECT_EQ(clients[0].transport, Transport::Doh);
}
