#include "dnsentinel/ml/dga_classifier.h"

#include <gtest/gtest.h>

#include <cmath>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

using namespace dnsentinel::ml;

namespace {

const std::string kSource = DNSENTINEL_SOURCE_DIR;

std::vector<std::string> split(const std::string& line, char separator) {
    std::vector<std::string> out;
    std::stringstream        in(line);
    std::string              part;
    while (std::getline(in, part, separator)) out.push_back(part);
    return out;
}

}  // namespace

// ─── Public Suffix List: the spec's corner cases (as tests/ml/test_psl.py) ──

TEST(PublicSuffixList, LongestRuleWildcardsAndExceptions) {
    const auto psl = PublicSuffixList::from_rules(
        {"com", "uk", "co.uk", "*.ck", "!www.ck", "jp", "*.kawasaki.jp", "!city.kawasaki.jp"});
    EXPECT_EQ(psl.public_suffix("example.com"), "com");
    EXPECT_EQ(psl.public_suffix("www.example.co.uk"), "co.uk");
    EXPECT_EQ(psl.public_suffix("co.uk"), "co.uk");
    EXPECT_EQ(psl.public_suffix("foo.bar.ck"), "bar.ck");    // wildcard: any one label
    EXPECT_EQ(psl.public_suffix("www.ck"), "ck");            // the exception beats it
    EXPECT_EQ(psl.public_suffix("a.b.kawasaki.jp"), "b.kawasaki.jp");
    EXPECT_EQ(psl.public_suffix("a.city.kawasaki.jp"), "kawasaki.jp");
    EXPECT_EQ(psl.public_suffix("example.unknowntld"), "unknowntld");  // the implicit "*" rule
}

TEST(PublicSuffixList, ShippedListHasPrivateAndIdnRules) {
    auto psl = PublicSuffixList::load(kSource + "/models/dga/public_suffixes.txt");
    ASSERT_TRUE(psl) << psl.error();
    EXPECT_FALSE(psl->version().empty());
    EXPECT_EQ(psl->public_suffix("x7k2.ddns.net"), "ddns.net");  // private section
    EXPECT_EQ(psl->public_suffix("example.xn--55qx5d.cn"), "xn--55qx5d.cn");
}

TEST(SplitName, RegistrableLabel) {
    const auto psl = PublicSuffixList::from_rules({"com", "uk", "co.uk", "br", "com.br", "blogspot.com.br"});
    auto       a   = split_name("x7kq2.Example.CO.UK.", psl);
    ASSERT_TRUE(a);
    EXPECT_EQ(a->label, "example");
    EXPECT_EQ(a->suffix, "co.uk");
    EXPECT_EQ(a->registrable(), "example.co.uk");
    auto bare = split_name("blogspot.com.br", psl);  // a public suffix itself: its first label stands in
    ASSERT_TRUE(bare);
    EXPECT_EQ(bare->label, "blogspot");
    EXPECT_EQ(bare->suffix, "com.br");
}

TEST(SplitName, RejectsWhatIsNotAHostName) {
    const auto psl = PublicSuffixList::from_rules({"com"});
    for (const char* bad : {"", ".", "bad..example.com", "-x.com", "spaces in.com", "ünïcode.com"}) {
        EXPECT_FALSE(split_name(bad, psl)) << bad;
    }
    // features.normalise checks only the name's first and last character, so
    // a label may end in a hyphen: x-.com is scored, as in Python.
    EXPECT_TRUE(split_name("x-.com", psl));
    EXPECT_FALSE(split_name(std::string(64, 'a') + ".com", psl));
    EXPECT_TRUE(split_name(std::string(63, 'a') + ".com", psl));
    EXPECT_TRUE(split_name("_dmarc.example.com", psl));
}

// ─── Feature pieces ─────────────────────────────────────────────────────────

TEST(WordTrie, CoversWithWholeWords) {
    WordTrie words;
    for (const char* w : {"plastic", "bags", "bag", "river", "ab", "Upper"}) words.add(w);
    EXPECT_EQ(words.words(), 4u);  // under three letters, or not lower-case letters: left out
    EXPECT_EQ(words.cover("plasticbags"), (std::pair<int, int>{11, 7}));
    EXPECT_EQ(words.cover("xkqzvtrw"), (std::pair<int, int>{0, 0}));
    EXPECT_EQ(words.cover("bag9river"), (std::pair<int, int>{8, 5}));
}

TEST(Features, Shape) {
    EXPECT_EQ(shape("a3k-vo"), "vdc-cv");
    EXPECT_EQ(shape("nafojeivo"), "cvcvcvvcv");
}

TEST(Features, WithoutTablesTheFittedOnesAreZero) {
    const FeatureVector f = label_features("a3kvau184uea-x", "com", FeatureTables{});
    EXPECT_EQ(f[0], 14);  // label_length
    EXPECT_EQ(f[8], 0);   // ngram_log_likelihood
    EXPECT_EQ(f[11], 4);  // letter_digit_switches
    EXPECT_EQ(f[12], 1);  // hyphens
    EXPECT_EQ(f[13], 3);  // longest_digit_run
}

// ─── Gradient-boosted trees ─────────────────────────────────────────────────

namespace {

const char* kTinyModel = R"(tree
version=v4
num_class=1
max_feature_idx=1
objective=binary sigmoid:1

Tree=0
num_leaves=3
num_cat=0
split_feature=0 1
threshold=0.5 2.25
decision_type=2 2
left_child=-1 -2
right_child=1 -3
leaf_value=-1 0.5 2
shrinkage=1

Tree=1
num_leaves=1
num_cat=0
leaf_value=0.25
shrinkage=1

end of trees
)";

}  // namespace

TEST(GradientBoostedTrees, WalksTreesAndAppliesTheSigmoid) {
    auto model = GradientBoostedTrees::parse(kTinyModel);
    ASSERT_TRUE(model) << model.error();
    EXPECT_EQ(model->tree_count(), 2u);
    EXPECT_EQ(model->feature_count(), 2u);
    const double a[] = {0.1, 0.0};  // feature 0 <= 0.5: leaf 0
    const double b[] = {0.9, 2.0};  // > 0.5, then feature 1 <= 2.25: leaf 1
    const double c[] = {0.9, 3.0};  // leaf 2
    EXPECT_DOUBLE_EQ(model->raw_score(a), -1 + 0.25);
    EXPECT_DOUBLE_EQ(model->raw_score(b), 0.5 + 0.25);
    EXPECT_DOUBLE_EQ(model->raw_score(c), 2 + 0.25);
    EXPECT_DOUBLE_EQ(model->predict(c), 1 / (1 + std::exp(-2.25)));
}

TEST(GradientBoostedTrees, RefusesWhatItCannotEvaluate) {
    std::string categorical = kTinyModel;
    categorical.replace(categorical.find("num_cat=0"), 9, "num_cat=1");
    EXPECT_FALSE(GradientBoostedTrees::parse(categorical));
    std::string regression = kTinyModel;
    regression.replace(regression.find("binary sigmoid:1"), 16, "regression");
    EXPECT_FALSE(GradientBoostedTrees::parse(regression));
    EXPECT_FALSE(GradientBoostedTrees::parse("tree\nversion=v4\n"));
}

// ─── The shipped model, against the Python scorer ───────────────────────────

class ShippedModel : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        auto loaded = DgaClassifier::load(kSource + "/models/dga", kSource + "/config/english_words.txt");
        ASSERT_TRUE(loaded) << loaded.error();
        model = new DgaClassifier(std::move(*loaded));
    }
    static void TearDownTestSuite() {
        delete model;
        model = nullptr;
    }
    static inline DgaClassifier* model = nullptr;
};

TEST_F(ShippedModel, Loads) {
    EXPECT_EQ(model->features().size(), 20u);
    EXPECT_EQ(model->trees().tree_count(), 450u);
    EXPECT_GT(model->threshold(), 0.9);
}

TEST_F(ShippedModel, ClearCases) {
    for (const char* ok : {"google.com", "wikipedia.org", "plasticbags.com", "travelinsurance.co.uk"}) {
        auto verdict = model->classify(ok);
        ASSERT_TRUE(verdict) << ok;
        EXPECT_FALSE(verdict->dga) << ok << " " << verdict->score;
    }
    for (const char* dga : {"mdexmtiwmjia.info", "vsknusavcbmhkfvkfeqhrpbdql.biz", "lcafyatwxd.sc"}) {
        auto verdict = model->classify(dga);
        ASSERT_TRUE(verdict) << dga;
        EXPECT_TRUE(verdict->dga) << dga << " " << verdict->score;
    }
    EXPECT_EQ(model->classify("WWW.Sub.Example.co.uk.")->registrable, "example.co.uk");
    EXPECT_FALSE(model->classify("not a name"));
}

// Every name in the fixture (ml/dga/export.py --parity): the same inputs,
// score and verdict as the Python scorer, to the last bit.
TEST_F(ShippedModel, MatchesThePythonScorer) {
    std::ifstream in(kSource + "/tests/unit/ml/dga_parity.tsv");
    ASSERT_TRUE(in);
    std::string line;
    size_t      names = 0, inexact_inputs = 0, inexact_scores = 0;
    while (std::getline(in, line)) {
        if (line.empty() || line.front() == '#') continue;
        const auto cells = split(line, '\t');
        ASSERT_EQ(cells.size(), 3 + model->features().size()) << line;
        const std::string& name = cells[0];
        auto               inputs = model->inputs(name);
        ASSERT_TRUE(inputs) << name;
        for (size_t i = 0; i < inputs->size(); ++i) {
            const double expected = std::stod(cells[3 + i]);
            EXPECT_NEAR((*inputs)[i], expected, 1e-12 * std::max(1.0, std::abs(expected)))
                << name << " " << model->features()[i];
            inexact_inputs += (*inputs)[i] != expected;
        }
        auto verdict = model->classify(name);
        ASSERT_TRUE(verdict) << name;
        const double expected = std::stod(cells[1]);
        EXPECT_NEAR(verdict->score, expected, 1e-12) << name;
        inexact_scores += verdict->score != expected;
        EXPECT_EQ(verdict->dga, cells[2] == "1") << name << " " << verdict->score;
        ++names;
    }
    EXPECT_GT(names, 500u);
    // Same arithmetic in the same order: not just close, identical.
    EXPECT_EQ(inexact_inputs, 0u);
    EXPECT_EQ(inexact_scores, 0u);
}
