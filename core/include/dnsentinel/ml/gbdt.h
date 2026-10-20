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
    [[nodiscard]] size_t tree_count() const { return roots_.size(); }
    [[nodiscard]] size_t node_count() const { return nodes_.size() + leaves_.size(); }

private:
    struct Split {
        double  threshold = 0;
        int32_t feature   = 0;
        int32_t left      = 0;  // >= 0: a split in nodes_; < 0: ~index into leaves_
        int32_t right     = 0;
        uint8_t decision  = 0;  // LightGBM's decision_type bits: default left, missing type
    };
    [[nodiscard]] int32_t next(const Split& split, double value) const;

    std::vector<Split>   nodes_;   // every tree's splits, tree after tree
    std::vector<double>  leaves_;  // every tree's leaf values
    std::vector<int32_t> roots_;   // each tree's root: a split, or ~leaf for a one-leaf tree
    size_t               features_ = 0;
    double               sigmoid_  = 1.0;
};

}  // namespace dnsentinel::ml
