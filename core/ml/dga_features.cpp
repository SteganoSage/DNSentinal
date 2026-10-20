/// @file ml/dga_features.cpp
/// features.py in C++. Every formula keeps Python's evaluation order and
/// its summation (sum() of floats is compensated since Python 3.12;
/// PythonSum does the same), and turns integer counts into doubles where
/// Python divides, so the values are identical, not merely close.

#include "dnsentinel/ml/dga_features.h"

#include <algorithm>
#include <cmath>

namespace dnsentinel::ml {

namespace {

bool is_vowel(char c) { return c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u'; }
bool is_letter(char c) { return c >= 'a' && c <= 'z'; }  // labels are lower-cased ASCII by now
bool is_digit(char c) { return c >= '0' && c <= '9'; }
bool is_hex(char c) { return is_digit(c) || (c >= 'a' && c <= 'f'); }
bool is_name_char(char c) { return is_letter(c) || is_digit(c) || c == '_' || c == '-' || c == '.'; }

/// Python's sum() of floats (3.12+): Neumaier's compensated summation, the
/// compensation added once at the end, as in CPython's builtin_sum_impl.
class PythonSum {
public:
    void add(double x) {
        const double t = sum_ + x;
        compensation_ += std::fabs(sum_) >= std::fabs(x) ? (sum_ - t) + x : (x - t) + sum_;
        sum_ = t;
    }
    [[nodiscard]] double result() const {
        return compensation_ != 0.0 && std::isfinite(compensation_) ? sum_ + compensation_ : sum_;
    }

private:
    double sum_ = 0.0, compensation_ = 0.0;
};

double entropy(std::string_view value) {
    if (value.empty()) return 0.0;
    // Counter(value) iterates in order of first appearance; so does this.
    std::array<int, 256> count{};
    std::string          order;
    for (char c : value) {
        if (count[static_cast<unsigned char>(c)]++ == 0) order.push_back(c);
    }
    const double length = static_cast<double>(value.size());
    PythonSum    sum;
    for (char c : order) {
        const double p = count[static_cast<unsigned char>(c)] / length;
        sum.add(p * std::log2(p));
    }
    return -sum.result();
}

template <typename Pred>
int longest_run(std::string_view value, Pred belongs) {
    int best = 0, current = 0;
    for (char c : value) {
        current = belongs(c) ? current + 1 : 0;
        best    = std::max(best, current);
    }
    return best;
}

}  // namespace

double NgramTable::score(std::string_view label) const {
    uint64_t vocabulary = 1;
    for (int i = 0; i < n; ++i) vocabulary *= alphabet;
    vocabulary                = std::max<uint64_t>(vocabulary, 1);
    const double denominator  = static_cast<double>(total) + alpha * static_cast<double>(vocabulary);
    std::string  padded(static_cast<size_t>(n - 1), '^');
    padded.append(label);
    padded.push_back('$');
    PythonSum sum;
    for (size_t i = 0; i + static_cast<size_t>(n) <= padded.size(); ++i) {
        const auto     it    = counts.find(std::string_view(padded).substr(i, static_cast<size_t>(n)));
        const uint64_t count = it == counts.end() ? 0 : it->second;
        sum.add(std::log((static_cast<double>(count) + alpha) / denominator));
    }
    return sum.result() / static_cast<double>(std::max<size_t>(label.size(), 1));
}

double TldPrior::score(std::string_view suffix) const {
    const size_t           dot   = suffix.rfind('.');
    const std::string_view tld   = dot == std::string_view::npos ? suffix : suffix.substr(dot + 1);
    const auto             it    = counts.find(tld);
    const uint64_t         count = it == counts.end() ? 0 : it->second;
    return std::log10((static_cast<double>(count) + alpha) /
                      (static_cast<double>(total) + alpha * static_cast<double>(counts.size() + 1)));
}

int32_t WordTrie::child(int32_t node, char letter) const {
    for (int32_t c = nodes_[static_cast<size_t>(node)].first_child; c != -1; c = nodes_[static_cast<size_t>(c)].next) {
        if (nodes_[static_cast<size_t>(c)].letter == letter) return c;
    }
    return -1;
}

void WordTrie::add(std::string_view word) {
    // features.WordList keeps ASCII letters only, three or more of them.
    if (word.size() < 3 || !std::all_of(word.begin(), word.end(), is_letter)) return;
    int32_t node = 0;
    for (auto it = word.rbegin(); it != word.rend(); ++it) {
        int32_t next = child(node, *it);
        if (next == -1) {
            next = static_cast<int32_t>(nodes_.size());
            Node fresh;
            fresh.letter = *it;
            fresh.next   = nodes_[static_cast<size_t>(node)].first_child;
            nodes_.push_back(fresh);
            nodes_[static_cast<size_t>(node)].first_child = next;
        }
        node = next;
    }
    if (!nodes_[static_cast<size_t>(node)].terminal) ++words_;
    nodes_[static_cast<size_t>(node)].terminal = true;
}

std::pair<int, int> WordTrie::cover(std::string_view label) const {
    // best[i]: the most letters of label[:i] whole words can cover.
    std::vector<int> best(label.size() + 1, 0);
    int              longest = 0;
    for (size_t end = 1; end <= label.size(); ++end) {
        best[end]    = best[end - 1];
        int32_t node = 0;
        for (size_t length = 1; length <= end; ++length) {  // label[end - length : end], growing leftwards
            node = child(node, label[end - length]);
            if (node == -1) break;
            if (length >= 3 && nodes_[static_cast<size_t>(node)].terminal) {
                best[end] = std::max(best[end], best[end - length] + static_cast<int>(length));
                longest   = std::max(longest, static_cast<int>(length));
            }
        }
    }
    return {best.back(), longest};
}

std::optional<SplitName> split_name(std::string_view domain, const PublicSuffixList& psl) {
    // features.normalise: strip, lower-case, drop the trailing dot(s), then validate.
    while (!domain.empty() && (domain.front() == ' ' || domain.front() == '\t')) domain.remove_prefix(1);
    while (!domain.empty() && (domain.back() == ' ' || domain.back() == '\t')) domain.remove_suffix(1);
    std::string value(domain);
    for (char& c : value) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    while (!value.empty() && value.back() == '.') value.pop_back();
    if (value.empty() || value.size() > 253) return std::nullopt;
    if (!std::all_of(value.begin(), value.end(), is_name_char)) return std::nullopt;
    if (value.front() == '.' || value.front() == '-' || value.back() == '-') return std::nullopt;
    std::vector<std::string_view> labels;
    for (size_t start = 0;;) {
        const size_t dot   = value.find('.', start);
        const auto   label = std::string_view(value).substr(start, dot == std::string::npos ? std::string::npos : dot - start);
        if (label.empty() || label.size() > 63) return std::nullopt;
        labels.push_back(label);
        if (dot == std::string::npos) break;
        start = dot + 1;
    }

    const std::string_view suffix = psl.public_suffix(value);
    const size_t suffix_labels = suffix.empty() ? 0 : static_cast<size_t>(std::count(suffix.begin(), suffix.end(), '.')) + 1;
    // split_name: Python computes keep from suffix.count(".") + 1, which is 1
    // for an empty suffix too.
    const ptrdiff_t keep = static_cast<ptrdiff_t>(labels.size()) - static_cast<ptrdiff_t>(std::max<size_t>(suffix_labels, 1));
    if (keep <= 0) {  // the name is itself a public suffix: its first label stands in
        const std::string rest = labels.size() > 1 ? value.substr(labels[0].size() + 1) : std::string{};
        return SplitName{std::string(labels[0]), rest};
    }
    return SplitName{std::string(labels[static_cast<size_t>(keep) - 1]), std::string(suffix)};
}

std::string shape(std::string_view label) {
    std::string out;
    out.reserve(label.size());
    for (char c : label) out.push_back(is_vowel(c) ? 'v' : is_letter(c) ? 'c' : is_digit(c) ? 'd' : '-');
    return out;
}

FeatureVector label_features(std::string_view label, std::string_view suffix, const FeatureTables& tables) {
    const size_t length = label.size();
    const double denom  = static_cast<double>(std::max<size_t>(length, 1));
    int          letters = 0, digits = 0, vowels = 0, consonants = 0, hex = 0, hyphens = 0;
    std::array<bool, 256> seen{};
    int                   distinct = 0;
    for (char c : label) {
        letters += is_letter(c);
        digits += is_digit(c);
        vowels += is_vowel(c);
        consonants += is_letter(c) && !is_vowel(c);
        hex += is_hex(c);
        hyphens += c == '-';
        if (!seen[static_cast<unsigned char>(c)]) {
            seen[static_cast<unsigned char>(c)] = true;
            ++distinct;
        }
    }
    const double letter_denom = static_cast<double>(std::max(letters, 1));

    // letter_digit_switches: letters and digits only, hyphens and underscores skipped.
    int  switches = 0, previous = -1;
    for (char c : label) {
        if (!is_letter(c) && !is_digit(c)) continue;
        const int kind = is_digit(c) ? 1 : 0;
        if (previous != -1 && kind != previous) ++switches;
        previous = kind;
    }
    // cv_alternation: neighbouring letters (anything else skipped) that switch consonant <-> vowel.
    int alternations = 0, letter_count = 0, last = -1;
    for (char c : label) {
        if (!is_letter(c)) continue;
        const int vowel = is_vowel(c) ? 1 : 0;
        if (last != -1 && vowel != last) ++alternations;
        last = vowel;
        ++letter_count;
    }

    const double ngram         = tables.ngram ? tables.ngram->score(label) : 0.0;
    const auto [covered, word] = tables.words ? tables.words->cover(label) : std::pair<int, int>{0, 0};

    FeatureVector f{};
    f[0]  = static_cast<double>(length);
    f[1]  = entropy(label);
    f[2]  = digits / denom;
    f[3]  = vowels / letter_denom;
    f[4]  = consonants / letter_denom;
    f[5]  = longest_run(label, [](char c) { return is_letter(c) && !is_vowel(c); });
    f[6]  = hex / denom;
    f[7]  = distinct / denom;
    f[8]  = ngram;
    f[9]  = tables.tld ? tables.tld->score(suffix) : 0.0;
    f[10] = label.starts_with("xn--") ? 1.0 : 0.0;
    f[11] = switches;
    f[12] = hyphens;
    f[13] = longest_run(label, is_digit);
    f[14] = covered / denom;
    f[15] = word;
    f[16] = tables.bigram ? tables.bigram->score(label) : 0.0;
    f[17] = tables.ngram && tables.dga_ngram ? ngram - tables.dga_ngram->score(label) : 0.0;
    f[18] = 0.0;  // label_in_allowlist (group F): not used by the shipped model
    f[19] = alternations / static_cast<double>(std::max(letter_count - 1, 1));
    f[20] = tables.rhythm ? tables.rhythm->score(shape(label)) : 0.0;
    return f;
}

}  // namespace dnsentinel::ml
