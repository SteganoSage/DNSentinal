#pragma once
/// @file ml/gbdt.h
/// Gradient-boosted trees from LightGBM's text model format (the
/// dga_lgbm.txt Booster.save_model writes), evaluated the way LightGBM
/// predicts: sum each tree's leaf, then the binary objective's sigmoid.
///
/// The README planned to compile the trees into C++ code (m2cgen,
/// Treelite); reading LightGBM's own file instead keeps the model a data
/// file, replaced without rebuilding, with the same arithmetic. Numerical
/// splits only (no categorical features, no linear trees): the DGA model
/// has neither, and anything else is refused at load.
///
/// Laid out for speed (E9). Walking 450 trees is ~4,300 dependent memory
/// reads per name, so when every split compares plainly (no missing-value
/// rule, as in the shipped model):
/// - thresholds are quantised: each feature's distinct thresholds, sorted;
///   a value becomes its rank among them (one binary search per feature),
///   and value <= threshold is exactly rank(value) <= rank(threshold), so a
///   split shrinks to 8 bytes (~385 KB for the shipped forest);
/// - each tree's splits are stored depth first, a left child next to its parent;
/// - the walk has no branches to mispredict, the cost that dominated (a
///   name's ~4,300 left-or-right turns are as good as random): eight trees
///   of about the same depth are walked side by side, each step picking the
///   child with masks, a tree that reached its leaf staying there, until
///   all eight have (one branch per block that can be mispredicted).
/// Leaves are still summed in tree order: the result is the same to the last bit.

#include <array>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <vector>

namespace dnsentinel::ml {

class GradientBoostedTrees {
public:
    /// Read a LightGBM text model ("objective=binary").
    [[nodiscard]] static std::expected<GradientBoostedTrees, std::string> load(const std::string& path);
    [[nodiscard]] static std::expected<GradientBoostedTrees, std::string> parse(const std::string& text);

    /// The probability of the positive class: sigmoid(sum of the trees' leaves).
    [[nodiscard]] double predict(std::span<const double> features) const;
    /// The sum of the trees' leaves, before the sigmoid.
    [[nodiscard]] double raw_score(std::span<const double> features) const;

    [[nodiscard]] size_t feature_count() const { return features_; }
    [[nodiscard]] size_t tree_count() const { return trees_.size(); }
    [[nodiscard]] size_t node_count() const { return nodes_.size() + leaves_.size(); }

private:
    struct Split {
        double  threshold = 0;
        int16_t left      = 0;  // >= 0: a split of the same tree; < 0: ~its leaf
        int16_t right     = 0;
        uint8_t feature   = 0;
        uint8_t decision  = 0;  // LightGBM's decision_type bits: default left, missing type
    };
    static_assert(sizeof(Split) == 16);
    struct Tree {
        int32_t splits = -1;  // its first split in nodes_; -1: a single leaf
        int32_t leaves = 0;   // its first leaf in leaves_
    };
    /// A split of the quantised forest: rank(value) <= rank decides left.
    struct Quantised {
        uint16_t rank    = 0;
        uint8_t  feature = 0;
        uint8_t  unused  = 0;
        int16_t  left    = 0;  // >= 0: a split of the same tree (depth-first order); < 0: ~its leaf
        int16_t  right   = 0;
    };
    static_assert(sizeof(Quantised) == 8);
    [[nodiscard]] static int32_t next(const Split& split, double value);
    [[nodiscard]] double         raw_score_plain(std::span<const double> features) const;
    void                         quantise();

    std::vector<Split>  nodes_;   // every tree's splits, tree after tree
    std::vector<double> leaves_;  // every tree's leaf values
    std::vector<Tree>   trees_;
    size_t              features_ = 0;
    double              sigmoid_  = 1.0;
    bool                plain_    = true;  // every split: missing type None, so value <= threshold decides
    static constexpr size_t kLanes = 8;  // trees walked side by side (16 measured slower)
    struct Block {
        std::array<int32_t, kLanes> trees{};  // indices into trees_; -1: an unused lane
        int32_t                steps = 0;  // the deepest of its trees: steps enough for all
    };
    std::vector<Quantised>           quantised_;   // nodes_ again, quantised and depth first (plain_ only)
    std::vector<std::vector<double>> thresholds_;  // per feature: its distinct thresholds, sorted
    std::vector<Block>               blocks_;      // the trees in groups of kLanes, by depth
};

}  // namespace dnsentinel::ml
