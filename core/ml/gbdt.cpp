/// @file ml/gbdt.cpp
/// Reading LightGBM's text model and walking its trees.
///
/// The file is "key=value" lines: a header (objective, max_feature_idx, ...),
/// then a "Tree=<i>" section per tree with space-separated arrays. In a
/// tree, split i tests feature split_feature[i] against threshold[i];
/// left_child/right_child hold the next split's index, or ~leaf (negative)
/// for a leaf. Missing values follow decision_type, as in LightGBM's
/// Tree::NumericalDecision.

#include "dnsentinel/ml/gbdt.h"

#include <charconv>
#include <cmath>
#include <fstream>
#include <map>
#include <optional>
#include <sstream>
#include <string_view>

namespace dnsentinel::ml {

namespace {

constexpr uint8_t kCategoricalMask = 1;
constexpr uint8_t kDefaultLeftMask = 2;
constexpr int     kMissingNone     = 0;
constexpr int     kMissingZero     = 1;
constexpr int     kMissingNaN      = 2;
constexpr double  kZeroThreshold   = 1e-35;  // LightGBM's: smaller magnitudes count as zero

template <typename T>
std::optional<std::vector<T>> numbers(std::string_view text) {
    std::vector<T> out;
    while (!text.empty()) {
        while (!text.empty() && text.front() == ' ') text.remove_prefix(1);
        if (text.empty()) break;
        T value{};
        auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
        if (ec != std::errc{}) return std::nullopt;
        out.push_back(value);
        text.remove_prefix(static_cast<size_t>(end - text.data()));
    }
    return out;
}

}  // namespace

std::expected<GradientBoostedTrees, std::string> GradientBoostedTrees::load(const std::string& path) {
    std::ifstream in(path);
    if (!in) return std::unexpected(path + ": cannot open");
    std::stringstream text;
    text << in.rdbuf();
    auto trees = parse(text.str());
    if (!trees) return std::unexpected(path + ": " + trees.error());
    return trees;
}

std::expected<GradientBoostedTrees, std::string> GradientBoostedTrees::parse(const std::string& text) {
    GradientBoostedTrees model;
    std::map<std::string, std::string, std::less<>> header, tree;
    bool                                            in_header = true;
    bool                                            objective = false;

    auto finish_tree = [&](size_t line) -> std::optional<std::string> {
        if (tree.empty()) return std::nullopt;
        const auto where = "tree ending at line " + std::to_string(line);
        auto       count = numbers<int>(tree["num_leaves"]);
        if (!count || count->size() != 1 || count->front() < 1) return where + ": bad num_leaves";
        if (tree.contains("num_cat") && tree["num_cat"] != "0") return where + ": categorical splits are not supported";
        if (tree.contains("is_linear") && tree["is_linear"] != "0") return where + ": linear trees are not supported";
        const auto leaves = numbers<double>(tree["leaf_value"]);
        const auto splits = static_cast<size_t>(count->front() - 1);
        if (!leaves || leaves->size() != splits + 1) return where + ": leaf_value doesn't match num_leaves";
        const auto leaf_base  = static_cast<int32_t>(model.leaves_.size());
        const auto split_base = static_cast<int32_t>(model.nodes_.size());
        model.leaves_.insert(model.leaves_.end(), leaves->begin(), leaves->end());
        if (splits == 0) {
            model.roots_.push_back(~leaf_base);
            tree.clear();
            return std::nullopt;
        }
        auto feature   = numbers<int32_t>(tree["split_feature"]);
        auto threshold = numbers<double>(tree["threshold"]);
        auto decision  = numbers<int>(tree["decision_type"]);
        auto left      = numbers<int32_t>(tree["left_child"]);
        auto right     = numbers<int32_t>(tree["right_child"]);
        for (const auto* field : {&feature, &left, &right}) {
            if (!*field || (*field)->size() != splits) return where + ": split arrays don't match num_leaves";
        }
        if (!threshold || threshold->size() != splits || !decision || decision->size() != splits) {
            return where + ": split arrays don't match num_leaves";
        }
        // Children are relative to this tree: rebase them onto the shared arrays.
        auto rebase = [&](int32_t child) { return child >= 0 ? child + split_base : ~(~child + leaf_base); };
        for (size_t i = 0; i < splits; ++i) {
            Split split;
            split.feature   = (*feature)[i];
            split.threshold = (*threshold)[i];
            split.decision  = static_cast<uint8_t>((*decision)[i]);
            split.left      = rebase((*left)[i]);
            split.right     = rebase((*right)[i]);
            if (split.decision & kCategoricalMask) return where + ": categorical splits are not supported";
            if (split.feature < 0 || static_cast<size_t>(split.feature) >= model.features_) {
                return where + ": a split uses feature " + std::to_string(split.feature);
            }
            const bool bad_left  = (*left)[i] >= 0 ? static_cast<size_t>((*left)[i]) >= splits
                                                   : static_cast<size_t>(~(*left)[i]) > splits;
            const bool bad_right = (*right)[i] >= 0 ? static_cast<size_t>((*right)[i]) >= splits
                                                    : static_cast<size_t>(~(*right)[i]) > splits;
            if (bad_left || bad_right) return where + ": a child points outside the tree";
            model.nodes_.push_back(split);
        }
        model.roots_.push_back(split_base);
        tree.clear();
        return std::nullopt;
    };

    std::istringstream lines(text);
    std::string        line;
    size_t             number = 0;
    while (std::getline(lines, line)) {
        ++number;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.starts_with("Tree=")) {
            if (in_header) {
                in_header = false;
                auto features = numbers<size_t>(header["max_feature_idx"]);
                if (!features || features->size() != 1) return std::unexpected("no max_feature_idx");
                model.features_ = features->front() + 1;
                const std::string& kind = header["objective"];
                if (!kind.starts_with("binary")) return std::unexpected("objective is \"" + kind + "\", not binary");
                if (auto at = kind.find("sigmoid:"); at != std::string::npos) {
                    auto value = numbers<double>(std::string_view(kind).substr(at + 8));
                    if (!value || value->size() != 1) return std::unexpected("bad sigmoid in objective");
                    model.sigmoid_ = value->front();
                }
                objective = true;
            }
            if (auto error = finish_tree(number)) return std::unexpected(*error);
            tree["num_leaves"] = "";  // marks a tree as begun
            continue;
        }
        if (line == "end of trees") {
            if (auto error = finish_tree(number)) return std::unexpected(*error);
            break;
        }
        const size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        (in_header ? header : tree)[line.substr(0, eq)] = line.substr(eq + 1);
    }
    if (!objective || model.roots_.empty()) return std::unexpected("no trees");
    return model;
}

int32_t GradientBoostedTrees::next(const Split& split, double value) const {
    const int missing = (split.decision >> 2) & 3;
    if (std::isnan(value) && missing != kMissingNaN) value = 0.0;
    if ((missing == kMissingZero && value >= -kZeroThreshold && value <= kZeroThreshold) ||
        (missing == kMissingNaN && std::isnan(value))) {
        return (split.decision & kDefaultLeftMask) ? split.left : split.right;
    }
    return value <= split.threshold ? split.left : split.right;
}

double GradientBoostedTrees::raw_score(std::span<const double> features) const {
    double sum = 0.0;
    for (const int32_t root : roots_) {
        int32_t node = root;
        while (node >= 0) {
            const Split& split = nodes_[static_cast<size_t>(node)];
            node               = next(split, features[static_cast<size_t>(split.feature)]);
        }
        sum += leaves_[static_cast<size_t>(~node)];
    }
    return sum;
}

double GradientBoostedTrees::predict(std::span<const double> features) const {
    return 1.0 / (1.0 + std::exp(-sigmoid_ * raw_score(features)));
}

}  // namespace dnsentinel::ml
