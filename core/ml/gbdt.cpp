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

#include <algorithm>
#include <array>
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
        if (splits > 32767) return where + ": too many leaves for 16-bit offsets";
        Tree entry{static_cast<int32_t>(model.nodes_.size()), static_cast<int32_t>(model.leaves_.size())};
        model.leaves_.insert(model.leaves_.end(), leaves->begin(), leaves->end());
        if (splits == 0) {
            entry.splits = -1;
            model.trees_.push_back(entry);
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
        // Children stay relative to this tree, as in the file.
        for (size_t i = 0; i < splits; ++i) {
            if ((*feature)[i] < 0 || static_cast<size_t>((*feature)[i]) >= model.features_ || (*feature)[i] > 255) {
                return where + ": a split uses feature " + std::to_string((*feature)[i]);
            }
            Split split;
            split.feature   = static_cast<uint8_t>((*feature)[i]);
            split.threshold = (*threshold)[i];
            split.decision  = static_cast<uint8_t>((*decision)[i]);
            split.left      = static_cast<int16_t>((*left)[i]);
            split.right     = static_cast<int16_t>((*right)[i]);
            if (split.decision & kCategoricalMask) return where + ": categorical splits are not supported";
            if (((split.decision >> 2) & 3) != kMissingNone) model.plain_ = false;
            const bool bad_left  = (*left)[i] >= 0 ? static_cast<size_t>((*left)[i]) >= splits
                                                   : static_cast<size_t>(~(*left)[i]) > splits;
            const bool bad_right = (*right)[i] >= 0 ? static_cast<size_t>((*right)[i]) >= splits
                                                    : static_cast<size_t>(~(*right)[i]) > splits;
            if (bad_left || bad_right) return where + ": a child points outside the tree";
            model.nodes_.push_back(split);
        }
        model.trees_.push_back(entry);
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
    if (!objective || model.trees_.empty()) return std::unexpected("no trees");
    model.quantise();
    return model;
}

void GradientBoostedTrees::quantise() {
    if (!plain_) return;
    thresholds_.assign(features_, {});
    for (const Split& split : nodes_) thresholds_[split.feature].push_back(split.threshold);
    for (auto& t : thresholds_) {
        std::sort(t.begin(), t.end());
        t.erase(std::unique(t.begin(), t.end()), t.end());  // -0.0 == 0.0: one rank, as <= treats them
        if (t.size() > 65535) {  // ranks wouldn't fit 16 bits: keep the plain walk
            plain_ = false;
            thresholds_.clear();
            return;
        }
    }
    quantised_.assign(nodes_.size(), {});
    std::vector<int32_t> depth(trees_.size(), 0);  // splits on the longest root-to-leaf path
    for (size_t t = 0; t < trees_.size(); ++t) {
        const Tree& tree = trees_[t];
        if (tree.splits < 0) continue;
        {
            std::vector<std::pair<int32_t, int32_t>> todo{{0, 1}};  // (split, its depth)
            while (!todo.empty()) {
                const auto [node, d] = todo.back();
                todo.pop_back();
                depth[t]           = std::max(depth[t], d);
                const Split& split = nodes_[static_cast<size_t>(tree.splits + node)];
                if (split.left >= 0) todo.emplace_back(split.left, d + 1);
                if (split.right >= 0) todo.emplace_back(split.right, d + 1);
            }
        }
        // Depth-first order: new index -> old, then old -> new.
        std::vector<int32_t> order, renamed;
        std::vector<int32_t> stack{0};
        while (!stack.empty()) {
            const int32_t old = stack.back();
            stack.pop_back();
            order.push_back(old);
            const Split& split = nodes_[static_cast<size_t>(tree.splits + old)];
            if (split.right >= 0) stack.push_back(split.right);  // pushed first, so visited after the left subtree
            if (split.left >= 0) stack.push_back(split.left);
        }
        renamed.assign(order.size(), 0);
        for (size_t i = 0; i < order.size(); ++i) renamed[static_cast<size_t>(order[i])] = static_cast<int32_t>(i);
        for (size_t i = 0; i < order.size(); ++i) {
            const Split& split = nodes_[static_cast<size_t>(tree.splits + order[i])];
            const auto&  t     = thresholds_[split.feature];
            Quantised    q;
            q.rank    = static_cast<uint16_t>(std::lower_bound(t.begin(), t.end(), split.threshold) - t.begin());
            q.feature = split.feature;
            q.left    = static_cast<int16_t>(split.left >= 0 ? renamed[static_cast<size_t>(split.left)] : split.left);
            q.right   = static_cast<int16_t>(split.right >= 0 ? renamed[static_cast<size_t>(split.right)] : split.right);
            quantised_[static_cast<size_t>(tree.splits) + i] = q;
        }
    }
    // Blocks of kLanes trees of about the same depth, so few steps are wasted.
    std::vector<int32_t> by_depth(trees_.size());
    for (size_t t = 0; t < trees_.size(); ++t) by_depth[t] = static_cast<int32_t>(t);
    std::stable_sort(by_depth.begin(), by_depth.end(), [&](int32_t a, int32_t b) {
        return depth[static_cast<size_t>(a)] < depth[static_cast<size_t>(b)];
    });
    blocks_.clear();
    for (size_t i = 0; i < by_depth.size(); i += kLanes) {
        Block block;
        block.trees.fill(-1);
        for (size_t k = 0; k < kLanes && i + k < by_depth.size(); ++k) {
            block.trees[k] = by_depth[i + k];
            block.steps    = std::max(block.steps, depth[static_cast<size_t>(by_depth[i + k])]);
        }
        blocks_.push_back(block);
    }
}

int32_t GradientBoostedTrees::next(const Split& split, double value) {
    const int missing = (split.decision >> 2) & 3;
    if (std::isnan(value) && missing != kMissingNaN) value = 0.0;
    if ((missing == kMissingZero && value >= -kZeroThreshold && value <= kZeroThreshold) ||
        (missing == kMissingNaN && std::isnan(value))) {
        return (split.decision & kDefaultLeftMask) ? split.left : split.right;
    }
    return value <= split.threshold ? split.left : split.right;
}

double GradientBoostedTrees::raw_score_plain(std::span<const double> features) const {
    // Missing type None: LightGBM reads a NaN as 0, then compares. Then each
    // value becomes its rank among its feature's thresholds (the number of
    // them below it): value <= t[k] exactly when rank <= k.
    constexpr size_t                   kMaxFeatures = 256;
    std::array<uint16_t, kMaxFeatures> values{};
    for (size_t i = 0; i < features_; ++i) {
        const double value = std::isnan(features[i]) ? 0.0 : features[i];
        const auto&  t     = thresholds_[i];
        values[i]          = static_cast<uint16_t>(std::lower_bound(t.begin(), t.end(), value) - t.begin());
    }

    // Each tree's leaf value, found block by block, then summed in tree order.
    std::vector<double> leaf(trees_.size());
    for (const Block& block : blocks_) {
        std::array<const Quantised*, kLanes> splits{};
        std::array<int32_t, kLanes>          node{};
        for (size_t k = 0; k < kLanes; ++k) {
            const int32_t t = block.trees[k];
            const bool    real = t >= 0 && trees_[static_cast<size_t>(t)].splits >= 0;
            splits[k] = quantised_.data() + (real ? trees_[static_cast<size_t>(t)].splits : 0);
            node[k]   = real ? 0 : ~0;  // a one-leaf tree or an unused lane starts at its leaf
        }
        for (int32_t step = 0; step < block.steps; ++step) {
            int32_t walking = 0;
            for (size_t k = 0; k < kLanes; ++k) {
                // No branches: a lane at a leaf (node < 0) reads split 0 and keeps its node.
                const int32_t    n     = node[k];
                const int32_t    done  = n >> 31;  // all ones at a leaf
                const Quantised& split = splits[k][n & ~done];
                const int32_t    left  = -static_cast<int32_t>(values[split.feature] <= split.rank);
                const int32_t    next  = (split.left & left) | (split.right & ~left);
                node[k]                = (n & done) | (next & ~done);
                walking |= ~(node[k] >> 31);
            }
            if (!walking) break;  // every lane at its leaf: the one branch that can be mispredicted
        }
        for (size_t k = 0; k < kLanes; ++k) {
            const int32_t t = block.trees[k];
            if (t >= 0) leaf[static_cast<size_t>(t)] = leaves_[static_cast<size_t>(trees_[static_cast<size_t>(t)].leaves + ~node[k])];
        }
    }
    double sum = 0.0;
    for (const double value : leaf) sum += value;
    return sum;
}

double GradientBoostedTrees::raw_score(std::span<const double> features) const {
    if (plain_ && features_ <= 256) return raw_score_plain(features);
    double sum = 0.0;
    for (const Tree& tree : trees_) {
        int32_t node = tree.splits < 0 ? ~0 : 0;
        if (tree.splits >= 0) {
            const Split* splits = nodes_.data() + tree.splits;
            while (node >= 0) {
                const Split& split = splits[node];
                node               = next(split, features[split.feature]);
            }
        }
        sum += leaves_[static_cast<size_t>(tree.leaves + ~node)];
    }
    return sum;
}

double GradientBoostedTrees::predict(std::span<const double> features) const {
    return 1.0 / (1.0 + std::exp(-sigmoid_ * raw_score(features)));
}

}  // namespace dnsentinel::ml
