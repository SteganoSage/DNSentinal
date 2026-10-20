/// @file ml/dga_check.cpp
/// Choosing names to score, the allowlist, and the verdict cache (LRU).

#include "dnsentinel/ml/dga_check.h"

#include <algorithm>
#include <array>
#include <fstream>

namespace dnsentinel::ml {

namespace {

/// Top-level domains no DGA registers under: special-use (RFC 6761, 6762,
/// 7686, 9476), reverse lookups, and the private ones networks use.
constexpr std::array<std::string_view, 12> kSpecialUse = {
    "arpa", "local", "localhost", "test", "example", "invalid", "onion", "alt", "internal", "lan", "home", "localdomain",
};

std::string_view trim(std::string_view text) {
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) text.remove_prefix(1);
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t' || text.back() == '\r')) text.remove_suffix(1);
    return text;
}

}  // namespace

bool DgaCheck::special_use(std::string_view tld) {
    return std::find(kSpecialUse.begin(), kSpecialUse.end(), tld) != kSpecialUse.end();
}

std::expected<StringSet, std::string> DgaCheck::read_allowlist(const std::string& path) {
    std::ifstream in(path);
    if (!in) return std::unexpected(path + ": cannot open");
    StringSet   out;
    std::string line;
    while (std::getline(in, line)) {
        std::string_view text = trim(line);
        if (text.empty() || text.front() == '#') continue;
        if (const size_t comma = text.find(','); comma != std::string_view::npos) {
            text = trim(text.substr(comma + 1));  // Tranco's "rank,domain"
        }
        while (!text.empty() && text.back() == '.') text.remove_suffix(1);
        std::string domain(text);
        for (char& c : domain) {
            if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
        }
        if (!domain.empty()) out.insert(std::move(domain));
    }
    if (out.empty()) return std::unexpected(path + ": no domains");
    return out;
}

DgaCheck::DgaCheck(DgaClassifier model, StringSet allowlist, const DgaConfig& config)
    : model_(std::move(model)),
      allowlist_(std::move(allowlist)),
      mode_(config.mode),
      verdicts_(config.cache_size),
      names_(config.cache_size) {
    if (config.threshold > 0) model_.set_threshold(config.threshold);
}

std::expected<DgaCheck, std::string> DgaCheck::load(const DgaConfig& config) {
    auto model = DgaClassifier::load(config.model, config.words);
    if (!model) return std::unexpected(model.error());
    if (config.allowlist.empty()) return DgaCheck(std::move(*model), StringSet{}, config);
    auto allowlist = read_allowlist(config.allowlist);
    if (!allowlist) return std::unexpected(allowlist.error());
    return DgaCheck(std::move(*model), std::move(*allowlist), config);
}

std::optional<DgaResult> DgaCheck::recall(Outcome& outcome) {
    switch (outcome.kind) {
    case Outcome::Kind::Skipped: ++stats_.skipped; return std::nullopt;
    case Outcome::Kind::Popular: ++stats_.allowlisted; return std::nullopt;
    case Outcome::Kind::Judged: break;
    }
    verdicts_.find(outcome.verdict.registrable);  // its domain is in use too: keep the two caches ageing together
    ++stats_.cache_hits;
    if (outcome.verdict.dga) ++stats_.flagged;
    return DgaResult{outcome.verdict, true};
}

std::optional<DgaResult> DgaCheck::check(const Name& qname) {
    ++stats_.queries;
    if (qname.labels.size() < 2 || special_use(qname.labels.back())) {
        ++stats_.skipped;
        return std::nullopt;
    }
    std::string text;
    for (const auto& label : qname.labels) {
        if (label.find('.') != std::string::npos) {  // an escaped dot: no host name has one
            ++stats_.skipped;
            return std::nullopt;
        }
        if (!text.empty()) text.push_back('.');
        text += label;
    }
    if (Outcome* seen = names_.find(text)) return recall(*seen);  // asked before: one lookup

    const auto name = model_.split(text);
    if (!name) {
        ++stats_.skipped;
        names_.insert(std::move(text), Outcome{Outcome::Kind::Skipped, {}});
        return std::nullopt;
    }
    std::string registrable = name->registrable();
    if (allowlist_.contains(registrable)) {
        ++stats_.allowlisted;
        names_.insert(std::move(text), Outcome{Outcome::Kind::Popular, {}});
        return std::nullopt;
    }

    DgaResult result;
    if (const DgaVerdict* known = verdicts_.find(registrable)) {  // another name of a domain judged already
        ++stats_.cache_hits;
        result = {*known, true};
    } else {
        result = {model_.classify(*name), false};
        ++stats_.scored;
        verdicts_.insert(std::move(registrable), result.verdict);
    }
    if (result.verdict.dga) {
        ++stats_.flagged;
        stats_.flagged_new += !result.cached;
    }
    names_.insert(std::move(text), Outcome{Outcome::Kind::Judged, result.verdict});
    return result;
}

}  // namespace dnsentinel::ml
