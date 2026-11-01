#include "dnsentinel/server/rule_commands.h"

#include "../wire/wire_test_util.h"

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <string>

using namespace dnsentinel;
using namespace dnsentinel::policy;
using namespace dnsentinel::server;
using namespace dnsentinel::test;
using namespace std::chrono_literals;

namespace {

bool has(const std::string& text, const std::string& part) { return text.find(part) != std::string::npos; }

sockaddr_storage at(const char* ip) {
    sockaddr_storage address{};
    auto*            v4 = reinterpret_cast<sockaddr_in*>(&address);
    v4->sin_family      = AF_INET;
    inet_pton(AF_INET, ip, &v4->sin_addr);
    return address;
}

const auto kNow = DynamicRules::Clock::now();

}  // namespace

TEST(RuleCommands, AddListAndRemove) {
    DynamicRules rules;
    RuleCommands commands(&rules);
    std::vector<std::pair<uint64_t, bool>> changes;
    commands.on_change([&](const DynamicRule& rule, bool renewed) { changes.emplace_back(rule.id, renewed); });

    auto added = commands.handle(
        R"({"op":"add_rule","domain":"tunnel.example","client":"192.168.1.23","ttl":3600,"reason":"tunnel","score":0.97,"source":"analyzer"})",
        kNow);
    EXPECT_TRUE(has(added, R"("type":"reply","op":"add_rule","ok":true,"id":1,"ttl":3600,"renewed":false)")) << added;
    EXPECT_NE(rules.match(name("x.tunnel.example"), at("192.168.1.23"), kNow), nullptr);
    EXPECT_EQ(rules.match(name("x.tunnel.example"), at("192.168.1.24"), kNow), nullptr);

    auto renewed = commands.handle(R"({"op":"add_rule","domain":"tunnel.example","client":"192.168.1.23","ttl":60})", kNow);
    EXPECT_TRUE(has(renewed, R"("id":1,"ttl":60,"renewed":true)")) << renewed;
    EXPECT_EQ(changes, (std::vector<std::pair<uint64_t, bool>>{{1, false}, {1, true}}));

    auto list = commands.handle(R"({"op":"list_rules"})", kNow + 10s);
    EXPECT_TRUE(has(list, R"("rules":[{"id":1,"domain":"tunnel.example","client":"192.168.1.23/32","expires_in":50)"))
        << list;

    EXPECT_TRUE(has(commands.handle(R"({"op":"remove_rule","id":1})", kNow), R"("ok":true)"));
    EXPECT_TRUE(has(commands.handle(R"({"op":"remove_rule","id":1})", kNow), R"("ok":false,"error":"no rule 1")"));
    EXPECT_TRUE(has(commands.handle(R"({"op":"list_rules"})", kNow), R"("rules":[])"));
}

TEST(RuleCommands, ARuleForEveryone) {
    DynamicRules rules;
    RuleCommands commands(&rules);
    auto reply = commands.handle(R"({"op":"add_rule","domain":"tunnel.example.","ttl":10})", kNow);
    EXPECT_TRUE(has(reply, R"("ok":true)")) << reply;
    EXPECT_NE(rules.match(name("tunnel.example"), at("10.9.9.9"), kNow), nullptr);
    reply = commands.handle(R"({"op":"add_rule","domain":"other.example","client":null,"ttl":10})", kNow);
    EXPECT_TRUE(has(reply, R"("ok":true)")) << reply;
    EXPECT_NE(rules.match(name("other.example"), at("10.9.9.9"), kNow), nullptr);
}

TEST(RuleCommands, RejectWhatTheyCannotUse) {
    DynamicRules rules;
    RuleCommands commands(&rules);
    EXPECT_TRUE(has(commands.handle("not json {", kNow), R"("ok":false)"));
    EXPECT_TRUE(has(commands.handle("[1,2]", kNow), R"("error":"a command is a JSON object")"));
    EXPECT_TRUE(has(commands.handle(R"({"op":"drop_tables"})", kNow), "unknown op"));
    EXPECT_TRUE(has(commands.handle(R"({"op":"add_rule","ttl":10})", kNow), "needs a domain"));
    EXPECT_TRUE(has(commands.handle(R"({"op":"add_rule","domain":"a..b","ttl":10})", kNow), "not a domain name"));
    EXPECT_TRUE(has(commands.handle(R"({"op":"add_rule","domain":"a.example"})", kNow), "needs a ttl"));
    EXPECT_TRUE(has(commands.handle(R"({"op":"add_rule","domain":"a.example","ttl":-5})", kNow), "needs a ttl"));
    EXPECT_TRUE(has(commands.handle(R"({"op":"add_rule","domain":"a.example","ttl":5,"client":"10.0.0.1/8"})", kNow),
                    "client:"));
    EXPECT_TRUE(has(commands.handle(R"({"op":"add_rule","domain":"a.example","ttl":5,"score":"high"})", kNow),
                    "score must be a number"));
    EXPECT_EQ(rules.size(), 0u);
    EXPECT_TRUE(has(commands.handle(R"({"op":"ping"})", kNow), R"("op":"ping","ok":true)"));
}

TEST(RuleCommands, SayWhenDynamicRulesAreOff) {
    RuleCommands commands(nullptr);
    EXPECT_TRUE(has(commands.handle(R"({"op":"list_rules"})", kNow), "dynamic rules are off"));
    EXPECT_TRUE(has(commands.handle(R"({"op":"ping"})", kNow), R"("ok":true)"));
}
