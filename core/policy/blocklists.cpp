/// @file policy/blocklists.cpp
/// Loading the configured lists, and reloading them on a worker thread.

#include "dnsentinel/policy/blocklists.h"

#include <sys/stat.h>

#include <utility>

namespace dnsentinel::policy {

Blocklists::Blocklists(ListsConfig config)
    : config_(std::move(config)), trie_(std::make_shared<const BlocklistTrie>()) {}

std::vector<Blocklists::FileStamp> Blocklists::stamp_files(const ListsConfig& config) {
    std::vector<FileStamp> stamps;
    for (const auto* paths : {&config.blocklists, &config.allowlists}) {
        for (const auto& path : *paths) {
            FileStamp   stamp;
            struct stat st{};
            if (::stat(path.c_str(), &st) == 0) {
                stamp = {true, st.st_dev, st.st_ino, st.st_size, st.st_mtim};
            }
            stamps.push_back(stamp);
        }
    }
    return stamps;
}

Blocklists::Attempt Blocklists::read_lists(const ListsConfig& config, std::stop_token stop) {
    const auto start = std::chrono::steady_clock::now();
    Attempt    attempt{stamp_files(config), std::unexpected(std::string("reload cancelled"))};

    BlocklistTrie::Builder builder;
    LoadReport             report;
    for (const auto& [paths, action] : {std::pair{&config.blocklists, ListAction::Block},
                                        std::pair{&config.allowlists, ListAction::Allow}}) {
        for (const auto& path : *paths) {
            if (stop.stop_requested()) return attempt;
            auto stats = builder.load_file(path, action);
            if (!stats) {
                attempt.result = std::unexpected(stats.error());
                return attempt;
            }
            report.files.push_back({path, action, *stats});
        }
    }

    auto trie           = std::make_shared<const BlocklistTrie>(builder.build());
    report.domains      = trie->size();
    report.memory_bytes = trie->memory_bytes();
    report.took = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);
    attempt.result = Loaded{std::move(trie), std::move(report)};
    return attempt;
}

std::expected<LoadReport, std::string> Blocklists::use(Attempt attempt) {
    stamps_ = std::move(attempt.stamps);  // even on failure: don't retry until the files change again
    if (!attempt.result) return std::unexpected(std::move(attempt.result.error()));
    trie_ = std::move(attempt.result->trie);
    return std::move(attempt.result->report);
}

std::expected<LoadReport, std::string> Blocklists::load() { return use(read_lists(config_, {})); }

bool Blocklists::start_reload() {
    if (reloading_) return false;
    reloading_ = true;
    // The previous worker finished before its outcome was collected, so
    // this assignment's join returns at once.
    worker_ = std::jthread([this, config = config_](std::stop_token stop) {
        Attempt                attempt = read_lists(config, stop);
        const std::lock_guard  lock(mutex_);
        finished_ = std::move(attempt);
    });
    return true;
}

std::optional<std::expected<LoadReport, std::string>> Blocklists::finish_reload() {
    std::optional<Attempt> attempt;
    {
        const std::lock_guard lock(mutex_);
        attempt.swap(finished_);
    }
    if (!attempt) return std::nullopt;
    reloading_ = false;
    return use(std::move(*attempt));
}

bool Blocklists::files_changed() const { return stamp_files(config_) != stamps_; }

}  // namespace dnsentinel::policy
