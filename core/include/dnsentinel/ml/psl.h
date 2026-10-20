#pragma once
/// @file ml/psl.h
/// The Public Suffix List: which part of a name is its registrable domain
/// (README §7.8.2). The DGA classifier scores the label just left of the
/// public suffix, and caches its verdict per registrable domain.
///
/// Reads the ASCII rules ml/dga/export.py writes (models/dga/public_suffixes.txt),
/// converted from config/public_suffix_list.dat exactly as the training
/// code converts them, so the two always split a name the same way. The
/// algorithm is https://publicsuffix.org/list/'s, as in ml/dga/psl.py:
/// the longest matching rule wins; an exception (!www.ck) beats the wildcard
/// it excepts (*.ck) and its suffix is the rule minus its first label; a
/// wildcard matches any one label; no match means the last label (rule *).

#include <expected>
#include <functional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace dnsentinel::ml {

/// Hashing that lets a set of strings be searched with a string_view.
struct StringHash {
    using is_transparent = void;
    size_t operator()(std::string_view text) const noexcept { return std::hash<std::string_view>{}(text); }
};
using StringSet = std::unordered_set<std::string, StringHash, std::equal_to<>>;

class PublicSuffixList {
public:
    /// One rule per line ("co.uk", "*.ck", "!www.ck"); "#" starts a comment,
    /// and a "# VERSION: ..." line names the list's version.
    [[nodiscard]] static std::expected<PublicSuffixList, std::string> load(const std::string& path);
    [[nodiscard]] static PublicSuffixList from_rules(const std::vector<std::string>& rules);

    /// The public suffix of a normalised name (lower case, no trailing dot):
    /// "co.uk" for "www.example.co.uk". A view into `name`.
    [[nodiscard]] std::string_view public_suffix(std::string_view name) const;

    [[nodiscard]] const std::string& version() const { return version_; }
    [[nodiscard]] size_t             size() const { return rules_.size() + wildcards_.size() + exceptions_.size(); }

private:
    void add(std::string_view rule);

    StringSet   rules_;       // "co.uk"
    StringSet   wildcards_;   // "*.ck", stored as "ck"
    StringSet   exceptions_;  // "!www.ck", stored as "www.ck"
    std::string version_;
};

}  // namespace dnsentinel::ml
