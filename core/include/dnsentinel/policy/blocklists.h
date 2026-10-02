#pragma once
/// @file policy/blocklists.h
/// The block and allow lists the config names, merged into one
/// BlocklistTrie, and reloading them without a restart (plan §5.6).
///
/// Lookups, and swapping in a reloaded trie, happen on the event-loop
/// thread. Only reading the files runs on a worker thread, so a reload of
/// a million-line feed never stalls queries.

#include "dnsentinel/policy/blocklist_trie.h"

#include <sys/types.h>

#include <chrono>
#include <cstdint>
#include <ctime>
#include <expected>
#include <memory>
#include <mutex>
#include <optional>
#include <stop_token>
#include <string>
#include <thread>
#include <vector>

namespace dnsentinel::policy {

/// What a blocked name gets back (README §7.6.2).
enum class BlockResponse : uint8_t {
    NullIp,    // A → 0.0.0.0, AAAA → ::, other types: no records
    NxDomain,  // the name doesn't exist
};

struct ListsConfig {
    std::vector<std::string> blocklists{};
    std::vector<std::string> allowlists{};
    BlockResponse            response  = BlockResponse::NullIp;
    uint32_t                 block_ttl = 60;  // short, so unblocking a name takes effect quickly
    /// How often to check the list files for changes, reloading them if any
    /// changed. 0 = reload only on SIGHUP.
    uint32_t reload_check_seconds = 60;
};

struct ListReport {
    std::string   path;
    ListAction    action = ListAction::Block;
    ListFileStats stats;
};

/// What reading the lists found.
struct LoadReport {
    std::vector<ListReport>   files;
    size_t                    domains      = 0;  // distinct domains with a rule
    size_t                    memory_bytes = 0;
    std::chrono::milliseconds took{0};
};

class Blocklists {
public:
    /// Starts with no lists in use: nothing is blocked until load().
    explicit Blocklists(ListsConfig config);
    Blocklists(const Blocklists&)            = delete;
    Blocklists& operator=(const Blocklists&) = delete;

    /// Read every list now and use them. For startup: a list that can't be
    /// read is an error, and then the lists in use stay as they were.
    std::expected<LoadReport, std::string> load();

    /// Start reading the lists again on a worker thread. False if a reload
    /// is already under way.
    bool start_reload();

    /// The outcome of the reload, once it has finished. On success the new
    /// lists are in use from now on; on failure the old ones still are.
    std::optional<std::expected<LoadReport, std::string>> finish_reload();

    /// Whether a list file was modified, replaced, removed or created since
    /// the lists were last read (successfully or not).
    [[nodiscard]] bool files_changed() const;

    [[nodiscard]] TrieLookupResult lookup(const Name& name) const { return trie_->lookup(name); }
    [[nodiscard]] size_t           size() const { return trie_->size(); }
    [[nodiscard]] const ListsConfig& config() const { return config_; }

private:
    struct FileStamp {
        bool     exists = false;
        dev_t    device = 0;
        ino_t    inode  = 0;
        off_t    size   = 0;
        timespec mtime{};
        bool     operator==(const FileStamp& o) const {
            return exists == o.exists && device == o.device && inode == o.inode && size == o.size &&
                   mtime.tv_sec == o.mtime.tv_sec && mtime.tv_nsec == o.mtime.tv_nsec;
        }
    };
    struct Loaded {
        std::shared_ptr<const BlocklistTrie> trie;
        LoadReport                           report;
    };
    struct Attempt {
        std::vector<FileStamp>               stamps;  // the files as they were before reading
        std::expected<Loaded, std::string>   result;
    };

    [[nodiscard]] static std::vector<FileStamp> stamp_files(const ListsConfig& config);
    [[nodiscard]] static Attempt read_lists(const ListsConfig& config, std::stop_token stop);
    std::expected<LoadReport, std::string> use(Attempt attempt);

    ListsConfig                          config_;
    std::shared_ptr<const BlocklistTrie> trie_;
    std::vector<FileStamp>               stamps_;
    bool                                 reloading_ = false;

    std::mutex             mutex_;
    std::optional<Attempt> finished_;  // guarded by mutex_
    std::jthread           worker_;    // declared last, so joined before the rest is destroyed
};

}  // namespace dnsentinel::policy
