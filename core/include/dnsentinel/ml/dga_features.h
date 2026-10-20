#pragma once
/// @file ml/dga_features.h
/// The DGA classifier's features (README §7.8.2), a port of
/// ml/dga/features.py: same names, same order, same arithmetic, so the
/// resolver gives the scores training measured. tests/unit/ml checks that
/// on names scored by the Python code (ml/dga/export.py --parity).
///
/// Everything is computed on the registrable label (the label left of the
/// public suffix). Sums run in the same order as Python's, so results match
/// to the last bit, not just approximately.

#include "dnsentinel/ml/psl.h"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace dnsentinel::ml {

/// Every feature features.py defines, in its DomainFeatures order. A model
/// uses some of them (features.txt lists which, in its own order).
inline constexpr std::array<std::string_view, 21> kFeatureNames = {
    "label_length",          "entropy",          "digit_ratio",      "vowel_ratio",
    "consonant_ratio",       "longest_consonant_run", "hex_ratio",   "distinct_ratio",
    "ngram_log_likelihood",  "tld_log_share",    "is_idn",           "letter_digit_switches",
    "hyphens",               "longest_digit_run", "word_coverage",   "longest_word",
    "bigram_log_likelihood", "dga_likelihood_ratio", "label_in_allowlist", "cv_alternation",
    "rhythm_log_likelihood",
};
using FeatureVector = std::array<double, kFeatureNames.size()>;

/// A Laplace-smoothed character n-gram model (features.NgramModel): the
/// mean log-likelihood per character of a label.
struct NgramTable {
    int                                                                 n     = 3;
    double                                                              alpha = 1.0;
    uint64_t                                                            total = 0;
    size_t                                                              alphabet = 0;  // distinct characters fitted on
    std::unordered_map<std::string, uint64_t, StringHash, std::equal_to<>> counts;

    [[nodiscard]] double score(std::string_view label) const;
};

/// How common each top-level domain is among benign names (features.TldPrior).
struct TldPrior {
    double                                                              alpha = 1.0;
    uint64_t                                                            total = 0;
    std::unordered_map<std::string, uint64_t, StringHash, std::equal_to<>> counts;

    [[nodiscard]] double score(std::string_view suffix) const;  // log10 share of the suffix's last label
};

/// English words of 3+ letters, as a trie of the words written backwards:
/// walking back from each position finds every word that ends there.
class WordTrie {
public:
    void add(std::string_view word);
    /// (letters covered by non-overlapping words, length of the longest word
    /// in the label): features.WordList.cover.
    [[nodiscard]] std::pair<int, int> cover(std::string_view label) const;
    [[nodiscard]] size_t              words() const { return words_; }

private:
    struct Node {
        char    letter      = 0;
        bool    terminal    = false;  // a word ends here
        int32_t first_child = -1;
        int32_t next        = -1;  // next sibling
    };
    [[nodiscard]] int32_t child(int32_t node, char letter) const;

    std::vector<Node> nodes_{Node{}};  // the root
    size_t            words_ = 0;
};

/// The fitted tables and word list the features read. A missing table
/// leaves its feature at 0, as in features.py.
struct FeatureTables {
    std::optional<NgramTable> ngram;      // benign 3-gram (group B)
    std::optional<NgramTable> bigram;     // benign 2-gram (E)
    std::optional<NgramTable> dga_ngram;  // DGA 3-gram (E)
    std::optional<NgramTable> rhythm;     // benign consonant/vowel shapes, 4-gram (G)
    std::optional<TldPrior>   tld;        // (B)
    std::optional<WordTrie>   words;      // (D)
};

/// A name as the classifier sees it: the registrable label and its public suffix.
struct SplitName {
    std::string label;   // "example" in www.example.co.uk
    std::string suffix;  // "co.uk"
    [[nodiscard]] std::string registrable() const { return suffix.empty() ? label : label + "." + suffix; }
};

/// features.normalise + split_name: lower case, no trailing dot, only the
/// characters names are made of ([a-z0-9_.-], no empty or over-long label).
/// nullopt for anything else: such names are not scored.
[[nodiscard]] std::optional<SplitName> split_name(std::string_view domain, const PublicSuffixList& psl);

/// The consonant/vowel shape of a label (features.shape): c, v, d, or -.
[[nodiscard]] std::string shape(std::string_view label);

/// Every feature of one label, in kFeatureNames order (label_in_allowlist is 0:
/// the shipped model doesn't use it).
[[nodiscard]] FeatureVector label_features(std::string_view label, std::string_view suffix, const FeatureTables& tables);

}  // namespace dnsentinel::ml
