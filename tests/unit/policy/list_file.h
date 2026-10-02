#pragma once
/// A list file in the test temp directory, removed when the test ends.

#include <gtest/gtest.h>

#include <unistd.h>

#include <atomic>
#include <fstream>
#include <string>

namespace dnsentinel::test {

class ListFile {
public:
    explicit ListFile(const std::string& contents) : path_(unique_path()) { write(contents); }
    ~ListFile() { ::unlink(path_.c_str()); }
    ListFile(const ListFile&)            = delete;
    ListFile& operator=(const ListFile&) = delete;

    void write(const std::string& contents) const { std::ofstream(path_, std::ios::trunc) << contents; }
    void append(const std::string& contents) const { std::ofstream(path_, std::ios::app) << contents; }
    void remove() const { ::unlink(path_.c_str()); }
    [[nodiscard]] const std::string& path() const { return path_; }

private:
    static std::string unique_path() {
        static std::atomic<int> next{0};
        return ::testing::TempDir() + "dnsentinel-list-" + std::to_string(::getpid()) + "-" +
               std::to_string(next++) + ".txt";
    }
    std::string path_;
};

}  // namespace dnsentinel::test
