#include "dnsentinel/policy/blocklists.h"

#include "../wire/wire_test_util.h"
#include "list_file.h"

#include <gtest/gtest.h>

#include <fcntl.h>
#include <sys/stat.h>

#include <chrono>
#include <cstdio>
#include <optional>
#include <thread>

using namespace dnsentinel;
using namespace dnsentinel::policy;
using namespace dnsentinel::test;
using namespace std::chrono_literals;

namespace {

bool blocks(const Blocklists& lists, const char* domain) {
    auto r = lists.lookup(name(domain));
    return r.matched && r.action == ListAction::Block;
}

/// Wait for a background reload to finish and return its outcome.
std::expected<LoadReport, std::string> wait_for_reload(Blocklists& lists) {
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while (std::chrono::steady_clock::now() < deadline) {
        if (auto outcome = lists.finish_reload()) return *outcome;
        std::this_thread::sleep_for(1ms);
    }
    ADD_FAILURE() << "the reload never finished";
    return std::unexpected("timeout");
}

}  // namespace

TEST(Blocklists, NothingIsBlockedBeforeLoading) {
    const ListFile block("ads.example\n");
    Blocklists     lists(ListsConfig{.blocklists = {block.path()}});
    EXPECT_FALSE(lists.lookup(name("ads.example")).matched);
    EXPECT_EQ(lists.size(), 0u);
}

TEST(Blocklists, LoadsEveryList) {
    const ListFile ads("ads.example\n0.0.0.0 shared.example\n");
    const ListFile trackers("t.example\nshared.example\nnot a domain\n");
    const ListFile allow("ok.ads.example\n");
    Blocklists     lists(ListsConfig{.blocklists = {ads.path(), trackers.path()}, .allowlists = {allow.path()}});

    auto report = lists.load();
    ASSERT_TRUE(report.has_value()) << report.error();
    ASSERT_EQ(report->files.size(), 3u);
    EXPECT_EQ(report->files[0].path, ads.path());
    EXPECT_EQ(report->files[0].action, ListAction::Block);
    EXPECT_EQ(report->files[0].stats.rules, 2u);
    EXPECT_EQ(report->files[1].stats.rules, 2u);
    EXPECT_EQ(report->files[1].stats.skipped, 1u);
    EXPECT_EQ(report->files[2].action, ListAction::Allow);
    EXPECT_EQ(report->domains, 4u);  // shared.example is on two lists
    EXPECT_GT(report->memory_bytes, 0u);
    EXPECT_EQ(lists.size(), 4u);

    EXPECT_TRUE(blocks(lists, "x.ads.example"));
    EXPECT_TRUE(blocks(lists, "t.example"));
    EXPECT_EQ(lists.lookup(name("shared.example")).source, ads.path());
    EXPECT_EQ(lists.lookup(name("ok.ads.example")).action, ListAction::Allow);
    EXPECT_FALSE(lists.lookup(name("example")).matched);
}

TEST(Blocklists, AFailedLoadKeepsTheListsInUse) {
    const ListFile ads("ads.example\n");
    const ListFile allow("");
    Blocklists     lists(ListsConfig{.blocklists = {ads.path()}, .allowlists = {allow.path()}});
    ASSERT_TRUE(lists.load().has_value());

    allow.remove();  // the second list: the first one was read fine
    ads.write("other.example\n");
    auto report = lists.load();
    ASSERT_FALSE(report.has_value());
    EXPECT_NE(report.error().find(allow.path()), std::string::npos) << report.error();
    EXPECT_TRUE(blocks(lists, "ads.example"));
    EXPECT_FALSE(lists.lookup(name("other.example")).matched);
}

TEST(Blocklists, NoticesChangedFiles) {
    const ListFile ads("ads.example\n");
    const ListFile allow("aaa.example\n");
    Blocklists     lists(ListsConfig{.blocklists = {ads.path()}, .allowlists = {allow.path()}});
    ASSERT_TRUE(lists.load().has_value());
    EXPECT_FALSE(lists.files_changed());

    // Modified twice within one timestamp tick: only the size gives it away.
    struct stat before{};
    ASSERT_EQ(::stat(ads.path().c_str(), &before), 0);
    ads.append("more.example\n");
    const timespec same[2] = {before.st_atim, before.st_mtim};
    ASSERT_EQ(::utimensat(AT_FDCWD, ads.path().c_str(), same, 0), 0);
    EXPECT_TRUE(lists.files_changed());
    ASSERT_TRUE(lists.load().has_value());
    EXPECT_FALSE(lists.files_changed());

    // Replaced by a different file of the same size and modification time,
    // as an editor saving through a temporary file might leave it.
    const ListFile replacement("bbb.example\n");
    struct stat    old_file{};
    ASSERT_EQ(::stat(allow.path().c_str(), &old_file), 0);
    const timespec times[2] = {old_file.st_atim, old_file.st_mtim};
    ASSERT_EQ(::utimensat(AT_FDCWD, replacement.path().c_str(), times, 0), 0);
    ASSERT_EQ(std::rename(replacement.path().c_str(), allow.path().c_str()), 0);
    EXPECT_TRUE(lists.files_changed());
    ASSERT_TRUE(lists.load().has_value());
    EXPECT_FALSE(lists.files_changed());

    allow.remove();  // removed
    EXPECT_TRUE(lists.files_changed());
}

TEST(Blocklists, ReloadsInTheBackground) {
    const ListFile ads("ads.example\n");
    Blocklists     lists(ListsConfig{.blocklists = {ads.path()}});
    ASSERT_TRUE(lists.load().has_value());
    EXPECT_FALSE(lists.finish_reload().has_value());  // none started

    ads.write("new.example\n");
    ASSERT_TRUE(lists.start_reload());
    EXPECT_FALSE(lists.start_reload());  // one at a time
    auto outcome = wait_for_reload(lists);
    ASSERT_TRUE(outcome.has_value()) << outcome.error();
    EXPECT_EQ(outcome->domains, 1u);
    EXPECT_TRUE(blocks(lists, "new.example"));
    EXPECT_FALSE(lists.lookup(name("ads.example")).matched);
    EXPECT_FALSE(lists.files_changed());
    EXPECT_FALSE(lists.finish_reload().has_value());  // collected once

    ads.write("third.example\n");  // and again: the worker can be restarted
    ASSERT_TRUE(lists.start_reload());
    ASSERT_TRUE(wait_for_reload(lists).has_value());
    EXPECT_TRUE(blocks(lists, "third.example"));
}

TEST(Blocklists, AFailedReloadKeepsTheListsInUseUntilTheFilesChangeAgain) {
    const ListFile ads("ads.example\n");
    const ListFile custom("custom.example\n");
    Blocklists     lists(ListsConfig{.blocklists = {ads.path(), custom.path()}});
    ASSERT_TRUE(lists.load().has_value());

    custom.remove();
    ASSERT_TRUE(lists.files_changed());
    ASSERT_TRUE(lists.start_reload());
    auto outcome = wait_for_reload(lists);
    ASSERT_FALSE(outcome.has_value());
    EXPECT_NE(outcome.error().find(custom.path()), std::string::npos) << outcome.error();
    EXPECT_TRUE(blocks(lists, "ads.example"));
    EXPECT_TRUE(blocks(lists, "custom.example"));
    EXPECT_FALSE(lists.files_changed());  // no retrying the same broken files every check

    custom.write("fixed.example\n");
    EXPECT_TRUE(lists.files_changed());
    ASSERT_TRUE(lists.start_reload());
    ASSERT_TRUE(wait_for_reload(lists).has_value());
    EXPECT_TRUE(blocks(lists, "fixed.example"));
    EXPECT_FALSE(lists.lookup(name("custom.example")).matched);
}

TEST(Blocklists, CanBeDestroyedMidReload) {
    std::string big;
    for (int i = 0; i < 20000; ++i) big += "host" + std::to_string(i) + ".example\n";
    const ListFile file(big);
    std::optional<Blocklists> lists(ListsConfig{.blocklists = {file.path(), file.path() + ".missing"}});
    ASSERT_TRUE(lists->start_reload());
    lists.reset();  // joins the worker; sanitizers check nothing is touched afterwards
}
