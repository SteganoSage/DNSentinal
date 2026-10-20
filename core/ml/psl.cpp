/// @file ml/psl.cpp
/// The Public Suffix List algorithm over ASCII rules.

#include "dnsentinel/ml/psl.h"

#include <fstream>

namespace dnsentinel::ml {

namespace {

std::string_view trim(std::string_view text) {
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t' || text.front() == '\r')) text.remove_prefix(1);
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t' || text.back() == '\r')) text.remove_suffix(1);
    return text;
}

}  // namespace

void PublicSuffixList::add(std::string_view rule) {
    if (rule.starts_with('!')) {
        exceptions_.emplace(rule.substr(1));
    } else if (rule.starts_with("*.")) {
        wildcards_.emplace(rule.substr(2));
    } else if (!rule.empty()) {
        rules_.emplace(rule);
    }
}

std::expected<PublicSuffixList, std::string> PublicSuffixList::load(const std::string& path) {
    std::ifstream in(path);
    if (!in) return std::unexpected(path + ": cannot open");
    PublicSuffixList list;
    std::string      line;
    while (std::getline(in, line)) {
        std::string_view text = trim(line);
        if (text.starts_with("# VERSION:")) {
            list.version_ = std::string(trim(text.substr(10)));
            continue;
        }
        if (text.empty() || text.starts_with('#')) continue;
        list.add(text);
    }
    if (list.size() == 0) return std::unexpected(path + ": no rules");
    return list;
}

PublicSuffixList PublicSuffixList::from_rules(const std::vector<std::string>& rules) {
    PublicSuffixList list;
    for (const auto& rule : rules) list.add(rule);
    return list;
}

std::string_view PublicSuffixList::public_suffix(std::string_view name) const {
    // Candidates from the longest (the whole name) down, so the first match
    // is the longest; each is the name from a label's start to the end.
    size_t start = 0;
    while (true) {
        const std::string_view candidate = name.substr(start);
        const size_t           dot       = candidate.find('.');
        if (exceptions_.contains(candidate)) {
            return dot == std::string_view::npos ? std::string_view{} : candidate.substr(dot + 1);
        }
        if (rules_.contains(candidate)) return candidate;
        if (dot == std::string_view::npos) return candidate;  // the last label: rule "*"
        if (wildcards_.contains(candidate.substr(dot + 1))) return candidate;
        start += dot + 1;
    }
}

}  // namespace dnsentinel::ml
