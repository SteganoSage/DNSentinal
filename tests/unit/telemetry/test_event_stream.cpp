#include "dnsentinel/telemetry/event_stream.h"
#include "dnsentinel/telemetry/query_event.h"

#include "../wire/wire_test_util.h"

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <map>
#include <string>
#include <vector>

using namespace dnsentinel;
using namespace dnsentinel::telemetry;
using namespace dnsentinel::test;
using namespace std::chrono_literals;

namespace {

class EventStreamTest : public ::testing::Test {
protected:
    void SetUp() override {
        char dir[] = "/tmp/dnsentinel-test-XXXXXX";
        ASSERT_NE(mkdtemp(dir), nullptr);
        tmp  = dir;
        path = tmp + "/run/events.sock";  // run/ doesn't exist yet: the stream makes it
    }
    void TearDown() override {
        for (int fd : clients) close(fd);
        stream.reset();
        std::filesystem::remove_all(tmp);
    }

    void open_stream(EventStreamConfig config = {}) {
        config.path = path;
        auto made   = EventStream::create(*loop, config, [this](std::string_view line) {
            commands.emplace_back(line);
            return std::string(R"({"type":"reply","echo":)") + json_string(line) + "}";
        });
        ASSERT_TRUE(made.has_value()) << made.error();
        stream = std::move(*made);
    }

    int connect_reader() {
        const int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        sockaddr_un address{};
        address.sun_family = AF_UNIX;
        std::strncpy(address.sun_path, path.c_str(), sizeof address.sun_path - 1);
        EXPECT_EQ(connect(fd, reinterpret_cast<const sockaddr*>(&address), sizeof address), 0) << std::strerror(errno);
        clients.push_back(fd);
        spin();
        return fd;
    }

    void spin(std::chrono::milliseconds time = 50ms) {
        auto guard = loop->add_timer(time, [this] { loop->stop(); });
        loop->run();
        loop->cancel_timer(guard);
    }

    /// The lines `fd` has received so far.
    std::vector<std::string> lines(int fd) {
        std::string& buffer = received[fd];
        char         chunk[65536];
        for (;;) {
            pollfd p{fd, POLLIN, 0};
            if (poll(&p, 1, 20) <= 0) break;
            const ssize_t n = recv(fd, chunk, sizeof chunk, 0);
            if (n <= 0) break;
            buffer.append(chunk, static_cast<size_t>(n));
            spin(5ms);  // let the stream write the rest
        }
        std::vector<std::string> out;
        size_t                   start = 0;
        for (size_t end; (end = buffer.find('\n', start)) != std::string::npos; start = end + 1) {
            out.push_back(buffer.substr(start, end - start));
        }
        buffer.erase(0, start);
        return out;
    }

    std::unique_ptr<net::EventLoop> loop = net::EventLoop::create().value();
    std::string                     tmp, path;
    std::unique_ptr<EventStream>    stream;
    std::vector<int>                clients;
    std::vector<std::string>        commands;
    std::map<int, std::string>      received;
};

}  // namespace

TEST_F(EventStreamTest, ReadersGetEveryEventAndAnswersToTheirCommands) {
    open_stream();
    EXPECT_FALSE(stream->has_readers());
    stream->publish(R"({"n":0})");  // nobody listening: dropped silently, not counted
    const int a = connect_reader();
    const int b = connect_reader();
    EXPECT_EQ(stream->reader_count(), 2u);
    stream->publish(R"({"n":1})");
    stream->publish(R"({"n":2})");
    spin();
    EXPECT_EQ(lines(a), (std::vector<std::string>{R"({"n":1})", R"({"n":2})"}));
    EXPECT_EQ(lines(b), (std::vector<std::string>{R"({"n":1})", R"({"n":2})"}));

    const std::string command = R"({"op":"ping"})" "\n" R"({"op":"list_rules"})" "\n";
    ASSERT_EQ(send(a, command.data(), command.size(), 0), static_cast<ssize_t>(command.size()));
    spin();
    EXPECT_EQ(commands, (std::vector<std::string>{R"({"op":"ping"})", R"({"op":"list_rules"})"}));
    auto replies = lines(a);
    ASSERT_EQ(replies.size(), 2u);
    EXPECT_EQ(replies[0], R"({"type":"reply","echo":"{\"op\":\"ping\"}"})");
    EXPECT_TRUE(lines(b).empty());  // replies go only to whoever asked
    EXPECT_EQ(stream->stats().published, 2u);
    EXPECT_EQ(stream->stats().commands, 2u);

    close(a);
    clients.erase(clients.begin());
    spin();
    EXPECT_EQ(stream->reader_count(), 1u);
}

TEST_F(EventStreamTest, AReaderThatFallsBehindLosesEventsNotTheResolverTime) {
    open_stream({.buffer_bytes = 4096});
    const int  reader = connect_reader();
    const auto event  = std::string(R"({"padding":")") + std::string(200, 'x') + "\"}";
    for (int i = 0; i < 100; ++i) stream->publish(event);  // ~20 KB at once: more than the 4 KB buffer
    EXPECT_GT(stream->stats().dropped, 0u);
    const uint64_t lost = stream->stats().dropped;
    spin();
    auto first = lines(reader);
    EXPECT_EQ(first.size(), 100 - lost);
    stream->publish(R"({"n":"after"})");
    spin();
    EXPECT_EQ(lines(reader), (std::vector<std::string>{R"({"type":"dropped","count":)" + std::to_string(lost) + "}",
                                                       R"({"n":"after"})"}));
}

TEST_F(EventStreamTest, OnlyTheDaemonsUserMayConnect) {
    open_stream();
    struct stat socket_stat{};
    ASSERT_EQ(stat(path.c_str(), &socket_stat), 0);
    EXPECT_TRUE(S_ISSOCK(socket_stat.st_mode));
    EXPECT_EQ(socket_stat.st_mode & 0777, 0600u);
    struct stat dir_stat{};
    ASSERT_EQ(stat((tmp + "/run").c_str(), &dir_stat), 0);
    EXPECT_EQ(dir_stat.st_mode & 0777, 0700u);
    stream.reset();
    EXPECT_FALSE(std::filesystem::exists(path));  // removed on the way out
}

TEST_F(EventStreamTest, ReplacesASocketLeftBehindButNotOneInUse) {
    std::filesystem::create_directories(tmp + "/run");
    {  // a socket file nobody listens on any more, as a crashed daemon leaves
        const int   fd = socket(AF_UNIX, SOCK_STREAM, 0);
        sockaddr_un address{};
        address.sun_family = AF_UNIX;
        std::strncpy(address.sun_path, path.c_str(), sizeof address.sun_path - 1);
        ASSERT_EQ(bind(fd, reinterpret_cast<const sockaddr*>(&address), sizeof address), 0);
        close(fd);
    }
    open_stream();
    auto second = EventStream::create(*loop, {.path = path}, nullptr);
    ASSERT_FALSE(second.has_value());
    EXPECT_NE(second.error().find("in use"), std::string::npos) << second.error();

    std::filesystem::remove(tmp + "/plain");
    { std::FILE* f = std::fopen((tmp + "/plain").c_str(), "w"); std::fclose(f); }
    auto not_socket = EventStream::create(*loop, {.path = tmp + "/plain"}, nullptr);
    ASSERT_FALSE(not_socket.has_value());
    EXPECT_NE(not_socket.error().find("not a socket"), std::string::npos);
}

TEST_F(EventStreamTest, TurnsAwayReadersOverTheLimitAndCommandsWhenOff) {
    open_stream({.max_readers = 1, .commands = false});
    const int first  = connect_reader();
    const int second = connect_reader();
    EXPECT_EQ(stream->reader_count(), 1u);
    EXPECT_EQ(lines(second), (std::vector<std::string>{R"({"type":"error","error":"too many readers"})"}));
    const std::string command = R"({"op":"ping"})" "\n";
    ASSERT_EQ(send(first, command.data(), command.size(), 0), static_cast<ssize_t>(command.size()));
    spin();
    auto reply = lines(first);
    ASSERT_EQ(reply.size(), 1u);
    EXPECT_NE(reply[0].find("commands are off"), std::string::npos) << reply[0];
    EXPECT_TRUE(commands.empty());
}

TEST(QueryEventJson, IsWhatTheTunnelDetectorTrainedOn) {
    QueryEvent event;
    event.time = std::chrono::system_clock::time_point(std::chrono::microseconds(1730400000123456));
    auto* v4   = reinterpret_cast<sockaddr_in*>(&event.client);
    v4->sin_family = AF_INET;
    inet_pton(AF_INET, "192.168.1.23", &v4->sin_addr);
    event.transport     = net::Transport::Doh;
    Name qname;
    qname.append_label("AbC");
    qname.append_label(std::string_view("x\xffy", 3));
    qname.append_label("a.b");
    qname.append_label("Example");
    qname.append_label("com");
    event.question      = {qname, 65399, 1};
    event.rcode         = 3;
    event.answers       = 0;
    event.response_size = 98;
    event.latency_us    = 184;
    event.action        = Action::Dynamic;
    event.rule          = "tunnel.example for everyone";
    event.dga           = 0.25;
    // the name as ml/tunnel/pcap.py writes it: lower case, \DDD and \. escapes, no trailing dot
    EXPECT_EQ(to_json(event),
              R"({"type":"query","timestamp":1730400000.123456,"client":"192.168.1.23","transport":"doh",)"
              R"("qname":"abc.x\\255y.a\\.b.example.com","qtype":"TYPE65399","rcode":"NXDOMAIN","answers":0,)"
              R"("response_size":98,"latency_us":184,"action":"dynamic_rule","rule":"tunnel.example for everyone",)"
              R"("dga":0.250000})");
    EXPECT_EQ(type_name(16), "TXT");
    EXPECT_EQ(type_name(10), "NULL");
    EXPECT_EQ(type_name(65), "HTTPS");
    EXPECT_EQ(rcode_name(2), "SERVFAIL");
    EXPECT_EQ(json_string("a\"b\\c\n"), R"("a\"b\\c\u000a")");
}
