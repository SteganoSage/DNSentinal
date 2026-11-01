#include "dnsentinel/telemetry/query_log.h"

#include "../wire/wire_test_util.h"

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <unistd.h>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace dnsentinel;
using namespace dnsentinel::telemetry;
using namespace dnsentinel::test;
using namespace std::chrono_literals;

namespace {

namespace fs = std::filesystem;

/// 2026-11-01 00:00:00 UTC.
constexpr std::chrono::sys_seconds kNov1{std::chrono::seconds(1793491200)};

QueryEvent event_from(const char* ip, std::chrono::system_clock::time_point time, const char* qname = "www.example.com") {
    QueryEvent event;
    event.time = time;
    if (std::string_view(ip).find(':') != std::string_view::npos) {
        auto* v6        = reinterpret_cast<sockaddr_in6*>(&event.client);
        v6->sin6_family = AF_INET6;
        inet_pton(AF_INET6, ip, &v6->sin6_addr);
    } else {
        auto* v4       = reinterpret_cast<sockaddr_in*>(&event.client);
        v4->sin_family = AF_INET;
        inet_pton(AF_INET, ip, &v4->sin_addr);
    }
    event.question = {name(qname), 1, 1};
    return event;
}

std::vector<std::string> read_lines(const std::string& path) {
    std::vector<std::string> lines;
    std::ifstream            in(path);
    for (std::string line; std::getline(in, line);) lines.push_back(line);
    return lines;
}

class QueryLogTest : public ::testing::Test {
protected:
    void SetUp() override {
        char dir[] = "/tmp/dnsentinel-test-XXXXXX";
        ASSERT_NE(mkdtemp(dir), nullptr);
        tmp = dir;
    }
    void TearDown() override { fs::remove_all(tmp); }

    std::unique_ptr<QueryLog> open(QueryLogConfig config = {}) {
        config.enabled = true;
        if (config.path == QueryLogConfig{}.path) config.path = tmp + "/logs/queries.jsonl";
        auto made = QueryLog::open(config);
        EXPECT_TRUE(made.has_value()) << made.error();
        return made ? std::move(*made) : nullptr;
    }

    std::string tmp;
};

TEST_F(QueryLogTest, WritesEachQueryToItsUtcDaysFile) {
    auto log = open();  // logs/ doesn't exist yet: the log makes it
    ASSERT_TRUE(log);
    log->write(event_from("192.0.2.1", kNov1 - 1s, "late.example.com"));  // 31 October, 23:59:59
    log->write(event_from("192.0.2.1", kNov1, "early.example.com"));
    log->write(event_from("2001:db8::7", kNov1 + 3h));
    log.reset();  // writes everything queued before it returns

    const auto october  = read_lines(tmp + "/logs/queries-2026-10-31.jsonl");
    const auto november = read_lines(tmp + "/logs/queries-2026-11-01.jsonl");
    ASSERT_EQ(october.size(), 1u);
    ASSERT_EQ(november.size(), 2u);
    EXPECT_NE(october[0].find(R"("qname":"late.example.com")"), std::string::npos) << october[0];
    EXPECT_EQ(november[0], to_json(event_from("192.0.2.1", kNov1, "early.example.com")));  // the event stream's line
    EXPECT_NE(november[1].find(R"("client":"2001:db8::7")"), std::string::npos) << november[1];
}

TEST_F(QueryLogTest, AppendsAcrossRestarts) {
    auto log = open();
    log->write(event_from("192.0.2.1", kNov1));
    log = open();
    log->write(event_from("192.0.2.2", kNov1));
    EXPECT_EQ(log->file_for("2026-11-01"), tmp + "/logs/queries-2026-11-01.jsonl");
    log.reset();
    EXPECT_EQ(read_lines(tmp + "/logs/queries-2026-11-01.jsonl").size(), 2u);
}

TEST_F(QueryLogTest, RemovesDayFilesPastTheRetention) {
    fs::create_directories(tmp + "/logs");
    for (const char* day : {"2026-10-24", "2026-10-25", "2026-10-26"}) {
        std::ofstream(tmp + "/logs/queries-" + day + ".jsonl") << "{}\n";
    }
    std::ofstream(tmp + "/logs/queries-notes.jsonl") << "kept\n";  // not a day file
    std::ofstream(tmp + "/logs/other-2026-10-01.jsonl") << "kept\n";
    auto log = open({.retention_days = 7});
    log->write(event_from("192.0.2.1", kNov1));  // 1 November: keeps 26 October to 1 November
    log.reset();
    EXPECT_FALSE(fs::exists(tmp + "/logs/queries-2026-10-24.jsonl"));
    EXPECT_FALSE(fs::exists(tmp + "/logs/queries-2026-10-25.jsonl"));
    EXPECT_TRUE(fs::exists(tmp + "/logs/queries-2026-10-26.jsonl"));
    EXPECT_TRUE(fs::exists(tmp + "/logs/queries-notes.jsonl"));
    EXPECT_TRUE(fs::exists(tmp + "/logs/other-2026-10-01.jsonl"));

    auto forever = open({.retention_days = 0});
    forever->write(event_from("192.0.2.1", kNov1 + 24h * 30));
    forever.reset();
    EXPECT_TRUE(fs::exists(tmp + "/logs/queries-2026-10-26.jsonl"));
}

TEST_F(QueryLogTest, AnonymisedClientsKeepTheirLabelAcrossRestarts) {
    auto log = open({.anonymise_clients = true});
    const auto a = event_from("192.0.2.1", kNov1), b = event_from("192.0.2.2", kNov1);
    const std::string label = log->client_label(a.client);
    EXPECT_TRUE(label.starts_with("anon-")) << label;
    EXPECT_EQ(label.size(), 5u + 12u);
    EXPECT_NE(label, log->client_label(b.client));
    log->write(a);
    log = open({.anonymise_clients = true});
    EXPECT_EQ(log->client_label(a.client), label);  // the key is kept beside the log
    log->write(a);
    log.reset();

    for (const auto& line : read_lines(tmp + "/logs/queries-2026-11-01.jsonl")) {
        EXPECT_NE(line.find(R"("client":")" + label + '"'), std::string::npos) << line;
        EXPECT_EQ(line.find("192.0.2.1"), std::string::npos) << line;
    }
    struct stat key{};
    ASSERT_EQ(stat((tmp + "/logs/.anonymise-key").c_str(), &key), 0);
    EXPECT_EQ(key.st_mode & 0777, 0600u);
    EXPECT_EQ(key.st_size, 32);

    auto plain = open();
    EXPECT_EQ(plain->client_label(a.client), "192.0.2.1");
}

TEST_F(QueryLogTest, ExcludedClientsAreNeverWritten) {
    auto log = open({.exclude = {policy::parse_subnet("10.0.5.0/24").value(), policy::parse_subnet("fd00::/8").value()}});
    log->write(event_from("10.0.5.9", kNov1));
    log->write(event_from("fd12::1", kNov1));
    log->write(event_from("10.0.6.1", kNov1));
    EXPECT_TRUE(log->excluded(event_from("10.0.5.200", kNov1).client));
    log.reset();
    const auto lines = read_lines(tmp + "/logs/queries-2026-11-01.jsonl");
    ASSERT_EQ(lines.size(), 1u);
    EXPECT_NE(lines[0].find("10.0.6.1"), std::string::npos);
}

TEST_F(QueryLogTest, CountsWhatItWritesAndWhatItDrops) {
    auto log = open({.ring_buffer_size = 16});
    for (int i = 0; i < 5000; ++i) log->write(event_from("192.0.2.1", kNov1));
    for (int i = 0; i < 200; ++i) {  // the writer catches up within a second or so
        const auto s = log->stats();
        if (s.written + s.dropped == 5000) break;
        std::this_thread::sleep_for(10ms);
    }
    const auto s = log->stats();
    EXPECT_EQ(s.written + s.dropped, 5000u);  // every line is one or the other
    log->write(event_from("192.0.2.1", kNov1));
    log->close();
    EXPECT_EQ(log->stats().written, s.written + 1);  // close() writes what is queued
    log->write(event_from("192.0.2.1", kNov1));      // ...and after it nothing more
    EXPECT_EQ(log->stats().dropped, s.dropped + 1);
    log.reset();
    EXPECT_EQ(read_lines(tmp + "/logs/queries-2026-11-01.jsonl").size(), s.written + 1);
}

TEST_F(QueryLogTest, SaysWhenItCannotWrite) {
    std::ofstream(tmp + "/file") << "x";
    auto under_a_file = QueryLog::open({.enabled = true, .path = tmp + "/file/queries.jsonl"});
    ASSERT_FALSE(under_a_file.has_value());
    EXPECT_NE(under_a_file.error().find("cannot create"), std::string::npos) << under_a_file.error();
    auto no_name = QueryLog::open({.enabled = true, .path = tmp + "/logs/"});
    ASSERT_FALSE(no_name.has_value());
    EXPECT_NE(no_name.error().find("needs a file name"), std::string::npos) << no_name.error();
    if (geteuid() != 0) {  // root can write anywhere
        fs::create_directories(tmp + "/locked");
        fs::permissions(tmp + "/locked", fs::perms::owner_read | fs::perms::owner_exec);
        auto locked = QueryLog::open({.enabled = true, .path = tmp + "/locked/queries.jsonl"});
        ASSERT_FALSE(locked.has_value());
        EXPECT_NE(locked.error().find("cannot write in"), std::string::npos) << locked.error();
        fs::permissions(tmp + "/locked", fs::perms::owner_all);
    }
}

}  // namespace
