/// @file wire/name.cpp
/// Name construction, presentation format, and hashing.

#include "dnsentinel/types.h"

namespace dnsentinel {

namespace {

/// DNS case folding is ASCII-only (RFC 4343 §3). std::tolower is
/// locale-dependent and would fold bytes >= 0x80 under some locales.
char ascii_lower(char c) {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

bool is_digit(char c) { return c >= '0' && c <= '9'; }

/// Characters that are special in presentation format and get a
/// backslash prefix when printed.
bool needs_backslash(char c) {
    switch (c) {
        case '.': case '\\': case '"': case '(': case ')':
        case ';': case '@':  case '$':
            return true;
        default:
            return false;
    }
}

}  // namespace

void Name::append_label(std::string_view raw) {
    original_case.emplace_back(raw);
    std::string lower(raw);
    for (char& c : lower) c = ascii_lower(c);
    labels.push_back(std::move(lower));
}

std::optional<Name> Name::from_string(std::string_view text) {
    Name name;
    if (text == ".") return name;
    if (text.empty()) return std::nullopt;

    size_t wire_len = 1;  // trailing root label
    std::string label;

    auto finish_label = [&]() -> bool {
        if (label.empty()) return false;  // "a..b", ".a"
        wire_len += 1 + label.size();
        if (wire_len > kMaxNameWireLength) return false;
        name.append_label(label);
        label.clear();
        return true;
    };

    for (size_t i = 0; i < text.size(); ++i) {
        char c = text[i];
        if (c == '.') {
            if (!finish_label()) return std::nullopt;
            continue;
        }
        if (c == '\\') {
            if (++i == text.size()) return std::nullopt;  // dangling backslash
            if (is_digit(text[i])) {
                // \DDD: exactly three decimal digits, value 0-255
                if (i + 2 >= text.size() || !is_digit(text[i + 1]) ||
                    !is_digit(text[i + 2])) {
                    return std::nullopt;
                }
                int value = (text[i] - '0') * 100 + (text[i + 1] - '0') * 10 +
                            (text[i + 2] - '0');
                if (value > 255) return std::nullopt;
                c = static_cast<char>(value);
                i += 2;
            } else {
                c = text[i];
            }
        }
        if (label.size() == kMaxLabelLength) return std::nullopt;
        label.push_back(c);
    }

    // Relative form ("example.com") leaves the last label unterminated.
    if (!label.empty() && !finish_label()) return std::nullopt;
    return name;
}

std::string Name::to_string() const {
    if (labels.empty()) return ".";

    std::string out;
    out.reserve(wire_length());
    for (const auto& label : labels) {
        for (char c : label) {
            auto byte = static_cast<unsigned char>(c);
            if (needs_backslash(c)) {
                out += '\\';
                out += c;
            } else if (byte < 0x21 || byte > 0x7E) {
                out += '\\';
                out += static_cast<char>('0' + byte / 100);
                out += static_cast<char>('0' + byte / 10 % 10);
                out += static_cast<char>('0' + byte % 10);
            } else {
                out += c;
            }
        }
        out += '.';
    }
    return out;
}

size_t Name::wire_length() const {
    size_t len = 1;  // trailing root label
    for (const auto& label : labels) len += 1 + label.size();
    return len;
}

size_t Name::hash() const noexcept {
    // 64-bit FNV-1a over length-prefixed canonical labels, so that
    // ["ab", "c"] and ["a", "bc"] hash differently.
    uint64_t h = 14695981039346656037ULL;
    auto mix = [&h](unsigned char b) {
        h ^= b;
        h *= 1099511628211ULL;
    };
    for (const auto& label : labels) {
        mix(static_cast<unsigned char>(label.size()));
        for (char c : label) mix(static_cast<unsigned char>(c));
    }
    return static_cast<size_t>(h);
}

}  // namespace dnsentinel
