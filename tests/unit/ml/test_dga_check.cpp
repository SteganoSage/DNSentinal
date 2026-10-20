#include "dnsentinel/ml/dga_check.h"

#include "../policy/list_file.h"
#include "../wire/wire_test_util.h"

#include <gtest/gtest.h>

#include <string>

using namespace dnsentinel;
using namespace dnsentinel::ml;
using namespace dnsentinel::test;

namespace {

const std::string kSource = DNSENTINEL_SOURCE_DIR;

/// The shipped model, loaded once; each test gets a copy.
class DgaCheckTest : public ::testing::Test {
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
    static DgaCheck make(StringSet allowlist = {}, DgaConfig config = {}) {
        return DgaCheck(*model, std::move(allowlist), config);
    }
    static inline DgaClassifier* model = nullptr;
};

}  // namespace

TEST(DgaAllowlist, ReadsTrancoCsvAndPlainLines) {
    const ListFile file("# popular sites\n1,google.com\n2, Example.COM.\n\nwikipedia.org\n");
    auto           set = DgaCheck::read_allowlist(file.path());
    ASSERT_TRUE(set) << set.error();
    EXPECT_EQ(set->size(), 3u);
    EXPECT_TRUE(set->contains("google.com"));
    EXPECT_TRUE(set->contains("example.com"));
    EXPECT_TRUE(set->contains("wikipedia.org"));
    EXPECT_FALSE(DgaCheck::read_allowlist("/nonexistent/allow.txt"));
    const ListFile empty("# nothing\n");
    EXPECT_FALSE(DgaCheck::read_allowlist(empty.path()));
}

TEST(DgaAllowlist, SpecialUseNames) {
    for (const char* tld : {"arpa", "local", "localhost", "test", "invalid", "onion", "internal", "lan", "home"}) {
        EXPECT_TRUE(DgaCheck::special_use(tld)) << tld;
    }
    EXPECT_FALSE(DgaCheck::special_use("com"));
    EXPECT_FALSE(DgaCheck::special_use("biz"));
}

TEST_F(DgaCheckTest, FlagsGeneratedNamesAndPassesRealOnes) {
    auto check = make();
    auto bad   = check.check(name("www.mdexmtiwmjia.info"));
    ASSERT_TRUE(bad);
    EXPECT_TRUE(bad->verdict.dga);
    EXPECT_EQ(bad->verdict.registrable, "mdexmtiwmjia.info");
    EXPECT_FALSE(bad->cached);
    auto good = check.check(name("plasticbags.com"));
    ASSERT_TRUE(good);
    EXPECT_FALSE(good->verdict.dga);
}

TEST_F(DgaCheckTest, SkipsWhatNoDgaRegisters) {
    auto check = make();
    for (const char* skipped : {"localhost", "wpad", "4.3.2.1.in-addr.arpa", "printer.local", "x7kq2bzvdq.test",
                                "router.lan"}) {
        EXPECT_FALSE(check.check(name(skipped))) << skipped;
    }
    Name dotted;  // a label with a dot in it (\. on the wire): no host name
    dotted.append_label("a.b");
    dotted.append_label("com");
    EXPECT_FALSE(check.check(dotted));
    EXPECT_EQ(check.stats().skipped, 7u);
    EXPECT_EQ(check.stats().scored, 0u);
}

TEST_F(DgaCheckTest, PopularSitesAreNeverScored) {
    auto check = make({"mdexmtiwmjia.info"});  // pretend it is popular
    EXPECT_FALSE(check.check(name("mail.mdexmtiwmjia.info")));
    EXPECT_FALSE(check.check(name("mail.mdexmtiwmjia.info")));  // asked again: recalled, not split again
    EXPECT_EQ(check.stats().allowlisted, 2u);
    EXPECT_EQ(check.stats().scored, 0u);
    EXPECT_EQ(check.cached(), 0u);  // no verdict: nothing was judged
}

TEST_F(DgaCheckTest, VerdictsAreKeptPerRegistrableDomain) {
    auto check = make();
    ASSERT_TRUE(check.check(name("a.lcafyatwxd.sc")));
    auto again = check.check(name("b.LCAFYATWXD.sc"));  // another host, the same domain
    ASSERT_TRUE(again);
    EXPECT_TRUE(again->cached);
    EXPECT_TRUE(again->verdict.dga);
    const DgaStats& s = check.stats();
    EXPECT_EQ(s.queries, 2u);
    EXPECT_EQ(s.scored, 1u);
    EXPECT_EQ(s.cache_hits, 1u);
    EXPECT_EQ(s.flagged, 2u);
    EXPECT_EQ(s.flagged_new, 1u);
}

TEST_F(DgaCheckTest, TheCacheForgetsTheLeastRecentlyUsed) {
    DgaConfig config;
    config.cache_size = 2;
    auto check        = make({}, config);
    ASSERT_TRUE(check.check(name("one.com")));
    ASSERT_TRUE(check.check(name("two.com")));
    ASSERT_TRUE(check.check(name("one.com")));    // one.com is now the most recent
    ASSERT_TRUE(check.check(name("three.com")));  // so two.com goes
    EXPECT_EQ(check.cached(), 2u);
    EXPECT_TRUE(check.check(name("one.com"))->cached);
    EXPECT_FALSE(check.check(name("two.com"))->cached);
    config.cache_size = 0;  // no cache at all
    auto uncached     = make({}, config);
    ASSERT_TRUE(uncached.check(name("one.com")));
    EXPECT_FALSE(uncached.check(name("one.com"))->cached);
    EXPECT_EQ(uncached.cached(), 0u);
}

TEST_F(DgaCheckTest, ThresholdCanBeOverridden) {
    DgaConfig config;
    config.threshold = 0.5;
    auto check       = make({}, config);
    EXPECT_DOUBLE_EQ(check.classifier().threshold(), 0.5);
    EXPECT_EQ(make().classifier().threshold(), model->threshold());  // 0: the model's own
}

TEST_F(DgaCheckTest, LoadsFromConfig) {
    const ListFile allow("1,google.com\n");
    DgaConfig      config;
    config.model     = kSource + "/models/dga";
    config.words     = kSource + "/config/english_words.txt";
    config.allowlist = allow.path();
    config.mode      = DgaMode::Enforce;
    auto check       = DgaCheck::load(config);
    ASSERT_TRUE(check) << check.error();
    EXPECT_EQ(check->mode(), DgaMode::Enforce);
    EXPECT_EQ(check->allowlist_size(), 1u);
    config.allowlist = "/nonexistent/top100k.txt";
    auto missing     = DgaCheck::load(config);
    ASSERT_FALSE(missing);
    EXPECT_NE(missing.error().find("/nonexistent/top100k.txt"), std::string::npos);
    config.allowlist = "";
    config.model     = "/nonexistent/model";
    EXPECT_FALSE(DgaCheck::load(config));
}
