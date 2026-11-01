/// @file telemetry/query_log.cpp

#include "dnsentinel/telemetry/query_log.h"

#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <system_error>

namespace dnsentinel::telemetry {

namespace fs = std::filesystem;

namespace {

std::string errno_text() { return std::error_code(errno, std::system_category()).message(); }

/// "2026-11-01", the UTC day of `time`.
std::string utc_day(std::chrono::system_clock::time_point time) {
    const std::time_t seconds = std::chrono::system_clock::to_time_t(time);
    std::tm           tm{};
    gmtime_r(&seconds, &tm);
    char text[16];
    std::strftime(text, sizeof text, "%Y-%m-%d", &tm);
    return text;
}

/// Days since the epoch of a "YYYY-MM-DD" day, or -1.
long day_number(const std::string& day) {
    std::tm tm{};
    if (day.size() != 10 || strptime(day.c_str(), "%Y-%m-%d", &tm) == nullptr) return -1;
    return static_cast<long>(timegm(&tm) / 86400);
}

/// The hash key kept beside the log, made on first use.
std::expected<std::array<unsigned char, 32>, std::string> anonymise_key(const fs::path& directory) {
    const fs::path              path = directory / ".anonymise-key";
    std::array<unsigned char, 32> key{};
    if (std::ifstream in(path, std::ios::binary); in) {
        in.read(reinterpret_cast<char*>(key.data()), key.size());
        if (in.gcount() == static_cast<std::streamsize>(key.size())) return key;
        return std::unexpected(path.string() + " is not a 32-byte key: remove it to make a new one");
    }
    if (RAND_bytes(key.data(), static_cast<int>(key.size())) != 1) return std::unexpected("no random bytes for the key");
    const mode_t before = umask(0177);  // 0600
    std::ofstream out(path, std::ios::binary);
    out.write(reinterpret_cast<const char*>(key.data()), key.size());
    umask(before);
    if (!out) return std::unexpected("cannot write " + path.string());
    return key;
}

}  // namespace

std::expected<std::unique_ptr<QueryLog>, std::string> QueryLog::open(QueryLogConfig config) {
    const fs::path path(config.path);
    if (path.filename().empty() || path.stem().empty()) {
        return std::unexpected("telemetry.query_log.path needs a file name: " + config.path);
    }
    std::unique_ptr<QueryLog> log(new QueryLog(std::move(config)));
    std::error_code           error;
    fs::create_directories(log->directory_, error);
    if (error) return std::unexpected("cannot create " + log->directory_ + " for the query log: " + error.message());
    if (log->config_.anonymise_clients) {
        auto key = anonymise_key(log->directory_);
        if (!key) return std::unexpected("telemetry.query_log: " + key.error());
        log->key_ = *key;
    }
    // check now that the directory can be written, so a mistake stops startup instead of every line
    if (access(log->directory_.c_str(), W_OK | X_OK) != 0) {
        return std::unexpected("cannot write in " + log->directory_ + " for the query log: " + errno_text());
    }
    log->writer_ = std::thread([raw = log.get()] { raw->run(); });
    return log;
}

QueryLog::QueryLog(QueryLogConfig config) : config_(std::move(config)) {
    const fs::path path(config_.path);
    stem_      = path.stem().string();
    extension_ = path.extension().string();
    directory_ = path.parent_path().empty() ? "." : path.parent_path().string();
}

QueryLog::~QueryLog() { close(); }

void QueryLog::close() {
    {
        std::lock_guard lock(mutex_);
        stopping_ = true;
    }
    wake_.notify_one();
    if (writer_.joinable()) writer_.join();
    if (file_ != nullptr) {
        std::fclose(file_);
        file_ = nullptr;
    }
}

std::string QueryLog::file_for(const std::string& day) const {
    return (fs::path(directory_) / (stem_ + "-" + day + extension_)).string();
}

bool QueryLog::excluded(const sockaddr_storage& client) const {
    return std::any_of(config_.exclude.begin(), config_.exclude.end(),
                       [&](const policy::Subnet& subnet) { return subnet.contains(client); });
}

std::string QueryLog::client_label(const sockaddr_storage& client) const {
    if (!config_.anonymise_clients) return address_text(client);
    const unsigned char* bytes = nullptr;
    size_t               size  = 0;
    if (client.ss_family == AF_INET) {
        bytes = reinterpret_cast<const unsigned char*>(&reinterpret_cast<const sockaddr_in*>(&client)->sin_addr);
        size  = 4;
    } else if (client.ss_family == AF_INET6) {
        bytes = reinterpret_cast<const unsigned char*>(&reinterpret_cast<const sockaddr_in6*>(&client)->sin6_addr);
        size  = 16;
    }
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int  length = 0;
    HMAC(EVP_sha256(), key_.data(), static_cast<int>(key_.size()), bytes, size, digest, &length);
    static constexpr char kHex[] = "0123456789abcdef";
    std::string           label  = "anon-";
    for (int i = 0; i < 6; ++i) {
        label += kHex[digest[i] >> 4];
        label += kHex[digest[i] & 0xF];
    }
    return label;
}

void QueryLog::write(const QueryEvent& event) {
    if (excluded(event.client)) return;
    std::string line = config_.anonymise_clients ? to_json(event, client_label(event.client)) : to_json(event);
    {
        std::lock_guard lock(mutex_);
        if (stopping_ || queue_.size() >= config_.ring_buffer_size) {
            ++dropped_;
            return;
        }
        queue_.emplace_back(utc_day(event.time), std::move(line));
    }
    wake_.notify_one();
}

QueryLog::Stats QueryLog::stats() const { return {written_.load(), dropped_.load(), removed_.load()}; }

void QueryLog::run() {
    std::deque<std::pair<std::string, std::string>> batch;
    for (;;) {
        bool stop = false;
        {
            std::unique_lock lock(mutex_);
            wake_.wait_for(lock, std::chrono::seconds(1), [this] { return stopping_ || !queue_.empty(); });
            batch.swap(queue_);
            stop = stopping_;
        }
        flush(batch);
        batch.clear();
        if (stop) {
            std::lock_guard lock(mutex_);
            if (queue_.empty()) return;
        }
    }
}

void QueryLog::flush(std::deque<std::pair<std::string, std::string>>& batch) {
    for (auto& [day, line] : batch) {
        if (day != day_ || file_ == nullptr) {  // a new day: a new file, and the oldest ones go
            if (file_ != nullptr) std::fclose(file_);
            file_ = std::fopen(file_for(day).c_str(), "a");
            day_  = day;
            remove_old(day);
        }
        if (file_ == nullptr) continue;  // the directory went away: nothing to do but count nothing
        line.push_back('\n');
        if (std::fwrite(line.data(), 1, line.size(), file_) == line.size()) ++written_;
    }
    if (file_ != nullptr) std::fflush(file_);
}

void QueryLog::remove_old(const std::string& newest_day) {
    if (config_.retention_days == 0) return;
    const long newest = day_number(newest_day);
    if (newest < 0) return;
    std::error_code error;
    for (const auto& entry : fs::directory_iterator(directory_, error)) {
        const std::string name = entry.path().filename().string();
        const std::string head = stem_ + "-";
        if (!name.starts_with(head) || !name.ends_with(extension_)) continue;
        const std::string day = name.substr(head.size(), name.size() - head.size() - extension_.size());
        const long        n   = day_number(day);
        if (n >= 0 && newest - n >= static_cast<long>(config_.retention_days)) {
            if (fs::remove(entry.path(), error)) ++removed_;
        }
    }
}

}  // namespace dnsentinel::telemetry
