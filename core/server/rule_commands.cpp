/// @file server/rule_commands.cpp
/// Commands are JSON, which YAML parses (it is a superset), so yaml-cpp,
/// already used for the config, reads them.

#include "dnsentinel/server/rule_commands.h"

#include "dnsentinel/telemetry/query_event.h"

#include <yaml-cpp/yaml.h>

#include <cmath>
#include <cstdio>
#include <optional>

namespace dnsentinel::server {

namespace {

using telemetry::json_string;

std::string reply(std::string_view op, std::string_view rest = "") {
    return R"({"type":"reply","op":)" + json_string(op) + R"(,"ok":true)" + std::string(rest) + "}";
}

std::string error(std::string_view op, std::string_view what) {
    return R"({"type":"reply","op":)" + json_string(op) + R"(,"ok":false,"error":)" + json_string(what) + "}";
}

std::optional<std::string> text(const YAML::Node& command, const char* key) {
    const YAML::Node value = command[key];
    if (!value.IsDefined() || !value.IsScalar()) return std::nullopt;
    return value.Scalar();
}

std::optional<uint64_t> whole(const YAML::Node& command, const char* key) {
    auto value = text(command, key);
    if (!value || value->empty() || value->find_first_not_of("0123456789") != std::string::npos) return std::nullopt;
    try {
        return std::stoull(*value);
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

std::string number(double value) {
    char out[32];
    std::snprintf(out, sizeof out, "%.6g", value);
    return out;
}

}  // namespace

std::string rule_json(const policy::DynamicRule& rule, std::chrono::steady_clock::time_point now) {
    const auto left = std::chrono::duration_cast<std::chrono::seconds>(rule.expires - now).count();
    const auto added =
        std::chrono::duration_cast<std::chrono::seconds>(rule.added.time_since_epoch()).count();
    std::string domain = rule.domain.to_string();
    if (domain.size() > 1) domain.pop_back();
    return R"({"id":)" + std::to_string(rule.id) + R"(,"domain":)" + json_string(domain) + R"(,"client":)" +
           (rule.client ? json_string(rule.client->to_string()) : std::string("null")) + R"(,"expires_in":)" +
           std::to_string(left > 0 ? left : 0) + R"(,"added":)" + std::to_string(added) + R"(,"reason":)" +
           json_string(rule.reason) + R"(,"score":)" + number(rule.score) + R"(,"source":)" + json_string(rule.source) +
           R"(,"hits":)" + std::to_string(rule.hits) + "}";
}

std::string RuleCommands::handle(std::string_view line, std::chrono::steady_clock::time_point now) {
    YAML::Node command;
    try {
        command = YAML::Load(std::string(line));
    } catch (const YAML::Exception&) {
        return error("?", "not JSON");
    }
    if (!command.IsMap()) return error("?", "a command is a JSON object");
    const std::string op = text(command, "op").value_or("");
    if (op == "ping") return reply(op);
    if (op != "add_rule" && op != "remove_rule" && op != "list_rules") {
        return error(op.empty() ? "?" : op, "unknown op (add_rule, remove_rule, list_rules, ping)");
    }
    if (rules_ == nullptr) return error(op, "dynamic rules are off (policy.dynamic_rules.enabled)");

    if (op == "list_rules") {
        std::string list;
        for (const auto& rule : rules_->active(now)) list += (list.empty() ? "" : ",") + rule_json(rule, now);
        return reply(op, R"(,"rules":[)" + list + "]");
    }
    if (op == "remove_rule") {
        auto id = whole(command, "id");
        if (!id) return error(op, "remove_rule needs the rule's id");
        return rules_->remove(*id) ? reply(op) : error(op, "no rule " + std::to_string(*id));
    }

    // add_rule
    auto domain_text = text(command, "domain");
    if (!domain_text || domain_text->empty()) return error(op, "add_rule needs a domain");
    auto domain = Name::from_string(*domain_text);
    if (!domain) return error(op, "not a domain name: " + *domain_text);
    std::optional<policy::Subnet> client;
    if (auto client_text = text(command, "client"); client_text && !client_text->empty() && *client_text != "~") {
        auto subnet = policy::parse_subnet(*client_text);
        if (!subnet) return error(op, "client: " + subnet.error());
        client = *subnet;
    }
    auto ttl = whole(command, "ttl");
    if (!ttl || *ttl == 0 || *ttl > 0xFFFFFFFFull) return error(op, "add_rule needs a ttl in seconds (1 or more)");
    double score = 0;
    if (auto score_text = text(command, "score")) {
        try {
            score = std::stod(*score_text);
        } catch (const std::exception&) {
            return error(op, "score must be a number");
        }
        if (!std::isfinite(score)) return error(op, "score must be a number");
    }
    const size_t before = rules_->added();
    auto added = rules_->add(std::move(*domain), client, static_cast<uint32_t>(*ttl),
                             text(command, "reason").value_or(""), score, text(command, "source").value_or(""), now);
    if (!added) return error(op, added.error());
    const policy::DynamicRule& rule    = **added;
    const bool                 renewed = rules_->added() == before;
    const auto granted = std::chrono::duration_cast<std::chrono::seconds>(rule.expires - now).count();
    if (on_change_) on_change_(rule, renewed);
    return reply(op, R"(,"id":)" + std::to_string(rule.id) + R"(,"ttl":)" + std::to_string(granted) +
                         R"(,"renewed":)" + (renewed ? "true" : "false"));
}

}  // namespace dnsentinel::server
