#pragma once
/// @file server/rule_commands.h
/// What a reader of the event stream may ask of the policy engine (README
/// §7.6.6): add, remove and list dynamic rules. One JSON object per line in,
/// one JSON object per line back:
///
///   {"op":"add_rule","domain":"attacker.example","client":"192.168.1.23","ttl":3600,
///    "reason":"tunnel","score":0.97,"source":"analyzer"}
///       -> {"type":"reply","op":"add_rule","ok":true,"id":7,"ttl":3600,"renewed":false}
///   {"op":"remove_rule","id":7}   -> {"type":"reply","op":"remove_rule","ok":true}
///   {"op":"list_rules"}           -> {"type":"reply","op":"list_rules","ok":true,"rules":[...]}
///   {"op":"ping"}                 -> {"type":"reply","op":"ping","ok":true}
///
/// `client` is an address or a subnet ("192.168.1.0/24"); without it the rule
/// is everyone's. A failure is {"ok":false,"error":"..."}.

#include "dnsentinel/policy/dynamic_rules.h"

#include <chrono>
#include <functional>
#include <string>
#include <string_view>

namespace dnsentinel::server {

class RuleCommands {
public:
    /// Told about every rule added or renewed (for the log).
    using ChangeFn = std::function<void(const policy::DynamicRule& rule, bool renewed)>;

    /// `rules` none: dynamic rules are off, and every command but ping says so.
    explicit RuleCommands(policy::DynamicRules* rules) : rules_(rules) {}

    void on_change(ChangeFn fn) { on_change_ = std::move(fn); }

    /// The reply to one command line.
    [[nodiscard]] std::string handle(std::string_view line, std::chrono::steady_clock::time_point now);

private:
    policy::DynamicRules* rules_;
    ChangeFn              on_change_;
};

/// A rule as a JSON object (for list_rules and the log).
[[nodiscard]] std::string rule_json(const policy::DynamicRule& rule, std::chrono::steady_clock::time_point now);

}  // namespace dnsentinel::server
