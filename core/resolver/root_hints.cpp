/// @file resolver/root_hints.cpp
/// Root hints file parsing.

#include "dnsentinel/resolver/root_hints.h"

#include <arpa/inet.h>

#include <cerrno>
#include <charconv>
#include <cstring>
#include <fstream>
#include <sstream>

namespace dnsentinel::resolver {

namespace {

bool iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        auto lower = [](char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c; };
        if (lower(a[i]) != lower(b[i])) return false;
    }
    return true;
}

bool all_digits(std::string_view s) {
    return !s.empty() && s.find_first_not_of("0123456789") == std::string_view::npos;
}

std::vector<std::string_view> split_fields(std::string_view line) {
    std::vector<std::string_view> fields;
    size_t i = 0;
    while (i < line.size()) {
        while (i < line.size() && (line[i] == ' ' || line[i] == '\t' || line[i] == '\r')) ++i;
        size_t start = i;
        while (i < line.size() && line[i] != ' ' && line[i] != '\t' && line[i] != '\r') ++i;
        if (i > start) fields.push_back(line.substr(start, i - start));
    }
    return fields;
}

}  // namespace

std::expected<RootHints, std::string> parse_root_hints(std::string_view text) {
    RootHints hints;
    size_t    line_no = 0;

    while (!text.empty()) {
        ++line_no;
        const size_t eol  = text.find('\n');
        std::string_view line = text.substr(0, eol);
        text = eol == std::string_view::npos ? std::string_view{} : text.substr(eol + 1);

        if (const size_t comment = line.find(';'); comment != std::string_view::npos) {
            line = line.substr(0, comment);
        }
        auto fields = split_fields(line);
        if (fields.empty()) continue;

        auto error = [&](std::string_view what) {
            return std::unexpected("line " + std::to_string(line_no) + ": " + std::string(what));
        };

        // <owner> [ttl] [IN] <type> <data>
        size_t f = 0;
        auto owner = Name::from_string(fields[f++]);
        if (!owner) return error("invalid owner name");

        RR rr;
        rr.name = std::move(*owner);
        if (f < fields.size() && all_digits(fields[f])) {
            auto [ptr, ec] = std::from_chars(fields[f].data(), fields[f].data() + fields[f].size(), rr.ttl);
            if (ec != std::errc{}) return error("TTL out of range");
            ++f;
        }
        if (f < fields.size() && iequals(fields[f], "IN")) ++f;
        if (fields.size() - f != 2) return error("expected '<owner> [ttl] [IN] <type> <data>'");
        const std::string_view type = fields[f];
        const std::string      data(fields[f + 1]);

        if (iequals(type, "NS")) {
            if (rr.name.label_count() != 0) return error("NS records must belong to the root '.'");
            auto target = Name::from_string(data);
            if (!target) return error("invalid NS target");
            rr.type  = RRType::NS;
            rr.rdata = RDataNS{std::move(*target)};
            hints.ns.push_back(std::move(rr));
        } else if (iequals(type, "A")) {
            RDataA a;
            if (inet_pton(AF_INET, data.c_str(), &a.addr) != 1) return error("invalid IPv4 address");
            rr.type  = RRType::A;
            rr.rdata = a;
            hints.addresses.push_back(std::move(rr));
        } else if (iequals(type, "AAAA")) {
            RDataAAAA aaaa;
            if (inet_pton(AF_INET6, data.c_str(), aaaa.addr) != 1) return error("invalid IPv6 address");
            rr.type  = RRType::AAAA;
            rr.rdata = aaaa;
            hints.addresses.push_back(std::move(rr));
        } else {
            return error("unsupported record type '" + std::string(type) + "' (only NS, A, AAAA)");
        }
    }

    if (hints.ns.empty()) return std::unexpected("no root NS records");
    if (hints.addresses.empty()) return std::unexpected("no root server addresses");
    return hints;
}

std::expected<RootHints, std::string> load_root_hints(const std::string& path) {
    std::ifstream file(path);
    if (!file) return std::unexpected("cannot open " + path + ": " + std::strerror(errno));
    std::ostringstream contents;
    contents << file.rdbuf();
    auto hints = parse_root_hints(contents.str());
    if (!hints) return std::unexpected(path + ": " + hints.error());
    return hints;
}

}  // namespace dnsentinel::resolver
