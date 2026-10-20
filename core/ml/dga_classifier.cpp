/// @file ml/dga_classifier.cpp
/// Loading models/dga and scoring a name.
///
/// features.txt (ml/dga/export.py) is whitespace-separated lines:
/// "threshold <x>", "feature <name>" per input in order, "words_sha256 <hex>",
/// "ngram <table> <n> <alpha> <total> <alphabet> <entries>" followed by that
/// many "<gram> <count>" lines, and "tld <alpha> <total> <entries>" followed
/// by that many "<tld> <count>" lines.

#include "dnsentinel/ml/dga_classifier.h"

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <fstream>
#include <memory>
#include <sstream>

namespace dnsentinel::ml {

namespace {

std::vector<std::string_view> fields(std::string_view line) {
    std::vector<std::string_view> out;
    size_t                        i = 0;
    while (i < line.size()) {
        while (i < line.size() && (line[i] == ' ' || line[i] == '\t' || line[i] == '\r')) ++i;
        const size_t start = i;
        while (i < line.size() && line[i] != ' ' && line[i] != '\t' && line[i] != '\r') ++i;
        if (i > start) out.push_back(line.substr(start, i - start));
    }
    return out;
}

template <typename T>
bool to_number(std::string_view text, T& out) {
    auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), out);
    return ec == std::errc{} && end == text.data() + text.size();
}

/// Reads "<key> <count>" lines into `counts`.
template <typename Map>
bool read_counts(std::istream& in, size_t entries, Map& counts, size_t& line_number) {
    std::string line;
    for (size_t i = 0; i < entries; ++i) {
        if (!std::getline(in, line)) return false;
        ++line_number;
        const auto f = fields(line);
        uint64_t   count = 0;
        if (f.size() != 2 || !to_number(f[1], count)) return false;
        counts.emplace(std::string(f[0]), count);
    }
    return true;
}

}  // namespace

std::optional<std::string> sha256_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::nullopt;
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx || EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1) return std::nullopt;
    std::array<char, 65536> buffer{};
    while (in) {
        in.read(buffer.data(), buffer.size());
        if (in.gcount() > 0 && EVP_DigestUpdate(ctx.get(), buffer.data(), static_cast<size_t>(in.gcount())) != 1) {
            return std::nullopt;
        }
    }
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int                               size = 0;
    if (EVP_DigestFinal_ex(ctx.get(), digest.data(), &size) != 1) return std::nullopt;
    std::string hex;
    for (unsigned int i = 0; i < size; ++i) {
        constexpr char kDigits[] = "0123456789abcdef";
        hex.push_back(kDigits[digest[i] >> 4]);
        hex.push_back(kDigits[digest[i] & 15]);
    }
    return hex;
}

std::expected<DgaClassifier, std::string> DgaClassifier::load(const std::string& folder, const std::string& words) {
    auto psl = PublicSuffixList::load(folder + "/public_suffixes.txt");
    if (!psl) return std::unexpected(psl.error());
    auto trees = GradientBoostedTrees::load(folder + "/dga_lgbm.txt");
    if (!trees) return std::unexpected(trees.error());
    DgaClassifier model(std::move(*psl), std::move(*trees));

    const std::string path = folder + "/features.txt";
    std::ifstream     in(path);
    if (!in) return std::unexpected(path + ": cannot open");
    auto        fail = [&](size_t line, const std::string& what) {
        return std::unexpected(path + ": line " + std::to_string(line) + ": " + what);
    };
    std::string line, words_sha256;
    size_t      number = 0;
    bool        format = false, threshold = false;
    while (std::getline(in, line)) {
        ++number;
        const auto f = fields(line);
        if (f.empty() || f[0].starts_with('#')) continue;
        if (f[0] == "dnsentinel-dga") {
            if (f.size() != 2 || f[1] != "1") return fail(number, "a format this build doesn't read");
            format = true;
        } else if (f[0] == "threshold") {
            if (f.size() != 2 || !to_number(f[1], model.threshold_)) return fail(number, "bad threshold");
            threshold = true;
        } else if (f[0] == "feature") {
            if (f.size() != 2) return fail(number, "bad feature line");
            const auto at = std::find(kFeatureNames.begin(), kFeatureNames.end(), f[1]);
            if (at == kFeatureNames.end()) return fail(number, "unknown feature " + std::string(f[1]));
            if (f[1] == "label_in_allowlist") return fail(number, "label_in_allowlist (group F) is not supported");
            model.names_.emplace_back(f[1]);
            model.columns_.push_back(static_cast<size_t>(at - kFeatureNames.begin()));
        } else if (f[0] == "words_sha256") {
            if (f.size() != 2) return fail(number, "bad words_sha256");
            words_sha256 = f[1];
        } else if (f[0] == "ngram") {
            NgramTable table;
            size_t     entries = 0;
            if (f.size() != 7 || !to_number(f[2], table.n) || !to_number(f[3], table.alpha) ||
                !to_number(f[4], table.total) || !to_number(f[6], entries) || table.n < 1) {
                return fail(number, "bad ngram line");
            }
            table.alphabet = f[5].size();
            const std::string name(f[1]);
            if (!read_counts(in, entries, table.counts, number)) return fail(number, "bad or missing n-gram counts");
            if (name == "ngram") model.tables_.ngram = std::move(table);
            else if (name == "bigram") model.tables_.bigram = std::move(table);
            else if (name == "dga_ngram") model.tables_.dga_ngram = std::move(table);
            else if (name == "rhythm") model.tables_.rhythm = std::move(table);
            else return fail(number, "unknown n-gram table " + name);
        } else if (f[0] == "tld") {
            TldPrior prior;
            size_t   entries = 0;
            if (f.size() != 4 || !to_number(f[1], prior.alpha) || !to_number(f[2], prior.total) ||
                !to_number(f[3], entries)) {
                return fail(number, "bad tld line");
            }
            if (!read_counts(in, entries, prior.counts, number)) return fail(number, "bad or missing TLD counts");
            model.tables_.tld = std::move(prior);
        } else {
            return fail(number, "unknown line \"" + std::string(f[0]) + "\"");
        }
    }
    if (!format || !threshold || model.names_.empty()) return std::unexpected(path + ": incomplete model description");
    if (model.names_.size() != model.trees_.feature_count()) {
        return std::unexpected(path + ": " + std::to_string(model.names_.size()) + " features, but the trees use " +
                               std::to_string(model.trees_.feature_count()));
    }

    const bool needs_words = std::find(model.names_.begin(), model.names_.end(), "word_coverage") != model.names_.end() ||
                             std::find(model.names_.begin(), model.names_.end(), "longest_word") != model.names_.end();
    if (needs_words) {
        if (!words_sha256.empty() && sha256_file(words) != words_sha256) {
            return std::unexpected(words + " is not the word list this model was trained with (SHA-256 differs)");
        }
        std::ifstream list(words);
        if (!list) return std::unexpected(words + ": cannot open");
        WordTrie trie;
        while (std::getline(list, line)) {
            const auto f = fields(line);
            if (f.empty() || f[0].starts_with('#')) continue;
            trie.add(f[0]);
        }
        model.tables_.words = std::move(trie);
    }
    return model;
}

std::vector<double> DgaClassifier::select(const FeatureVector& all) const {
    std::vector<double> out;
    out.reserve(columns_.size());
    for (const size_t column : columns_) out.push_back(all[column]);
    return out;
}

std::optional<std::vector<double>> DgaClassifier::inputs(std::string_view domain) const {
    const auto name = split_name(domain, psl_);
    if (!name) return std::nullopt;
    return select(label_features(name->label, name->suffix, tables_));
}

std::optional<std::string> DgaClassifier::registrable(std::string_view domain) const {
    const auto name = split_name(domain, psl_);
    if (!name) return std::nullopt;
    return name->registrable();
}

DgaVerdict DgaClassifier::classify(const SplitName& name) const {
    const double score = trees_.predict(select(label_features(name.label, name.suffix, tables_)));
    return DgaVerdict{name.registrable(), score, score > threshold_};
}

std::optional<DgaVerdict> DgaClassifier::classify(std::string_view domain) const {
    const auto name = split_name(domain, psl_);
    if (!name) return std::nullopt;
    return classify(*name);
}

}  // namespace dnsentinel::ml
