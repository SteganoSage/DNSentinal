/// @file net/doh.cpp
/// DNS over HTTPS (RFC 8484) on HTTP/1.1. Requests come in; DNS queries go
/// to the handler; answers go back as HTTP responses, in request order
/// (HTTP/1.1 has no other way to match them up).
///
/// A request we can't serve gets the right status and the connection lives
/// on; a request whose end we can't find (a bad request line, oversized
/// headers or body, chunked encoding) gets its status and then the
/// connection closes, since nothing after it can be trusted to be framed.

#include "framing.h"

#include "dnsentinel/wire/builder.h"
#include "dnsentinel/wire/parser.h"

#include <algorithm>
#include <charconv>
#include <climits>
#include <expected>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace dnsentinel::net::detail {

namespace {

constexpr size_t kMaxHead    = 8 * 1024;  // request line and headers
constexpr size_t kMaxHeaders = 64;
constexpr size_t kMaxBody    = 65535;  // the largest DNS message

constexpr std::string_view kDnsMessage = "application/dns-message";

std::string lower(std::string_view s) {
    std::string out(s);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(c >= 'A' && c <= 'Z' ? c + 32 : c); });
    return out;
}

std::string_view trim(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.remove_suffix(1);
    return s;
}

/// RFC 4648 §5 base64url. RFC 8484 sends no padding; a little is tolerated.
std::optional<std::vector<uint8_t>> base64url_decode(std::string_view text) {
    while (!text.empty() && text.back() == '=') text.remove_suffix(1);
    if (text.size() % 4 == 1) return std::nullopt;
    std::vector<uint8_t> out;
    out.reserve(text.size() * 3 / 4);
    uint32_t bits_buffer = 0;
    int      bits        = 0;
    for (const char ch : text) {
        uint32_t value;
        if (ch >= 'A' && ch <= 'Z') {
            value = static_cast<uint32_t>(ch - 'A');
        } else if (ch >= 'a' && ch <= 'z') {
            value = static_cast<uint32_t>(ch - 'a' + 26);
        } else if (ch >= '0' && ch <= '9') {
            value = static_cast<uint32_t>(ch - '0' + 52);
        } else if (ch == '-') {
            value = 62;
        } else if (ch == '_') {
            value = 63;
        } else {
            return std::nullopt;
        }
        bits_buffer = (bits_buffer << 6) | value;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>(bits_buffer >> bits));
        }
    }
    return out;
}

/// The value of `key` in a query string ("dns=...&ct=..."), if present.
std::optional<std::string_view> query_param(std::string_view query, std::string_view key) {
    while (!query.empty()) {
        const size_t     amp  = query.find('&');
        std::string_view pair = query.substr(0, amp);
        query                 = amp == std::string_view::npos ? std::string_view{} : query.substr(amp + 1);
        const size_t eq       = pair.find('=');
        if (pair.substr(0, eq) == key) return eq == std::string_view::npos ? std::string_view{} : pair.substr(eq + 1);
    }
    return std::nullopt;
}

/// RFC 8484 §5.1: cache for as long as the shortest answer TTL, or for a
/// negative answer the SOA's negative TTL; errors aren't to be cached.
uint32_t max_age(const Message& response) {
    const auto rcode = static_cast<RCode>(response.header.rcode);
    if (rcode != RCode::NoError && rcode != RCode::NXDomain) return 0;
    if (!response.answers.empty()) {
        uint32_t least = UINT32_MAX;
        for (const RR& rr : response.answers) least = std::min(least, rr.ttl);
        return least;
    }
    for (const RR& rr : response.authority) {
        if (const auto* soa = std::get_if<RDataSOA>(&rr.rdata)) return std::min(rr.ttl, soa->minimum);
    }
    return 0;
}

std::string_view reason(int status) {
    switch (status) {
        case 200: return "OK";
        case 400: return "Bad Request";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 413: return "Content Too Large";
        case 415: return "Unsupported Media Type";
        case 431: return "Request Header Fields Too Large";
        case 501: return "Not Implemented";
        case 505: return "HTTP Version Not Supported";
        default:  return "Error";
    }
}

std::vector<uint8_t> http_response(int status, std::string_view content_type, std::span<const uint8_t> body,
                                   std::string_view extra_headers, bool close) {
    std::string head = "HTTP/1.1 " + std::to_string(status) + " " + std::string(reason(status)) + "\r\n";
    head += "Content-Type: " + std::string(content_type) + "\r\n";
    head += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    head += extra_headers;
    if (close) head += "Connection: close\r\n";
    head += "\r\n";
    std::vector<uint8_t> out(head.begin(), head.end());
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

struct Request {
    std::string                        method, target, version;
    std::map<std::string, std::string> headers;  // names in lower case
    size_t                             content_length = 0;
};

struct HeadError {
    int         status;
    std::string why;
};

/// The request line and headers, without the blank line that ends them.
std::expected<Request, HeadError> parse_head(std::string_view head) {
    const size_t     eol  = head.find("\r\n");
    std::string_view line = head.substr(0, eol);
    std::string_view rest = eol == std::string_view::npos ? std::string_view{} : head.substr(eol + 2);

    // method SP request-target SP HTTP-version
    const size_t sp1 = line.find(' ');
    const size_t sp2 = sp1 == std::string_view::npos ? sp1 : line.find(' ', sp1 + 1);
    if (sp2 == std::string_view::npos || line.find(' ', sp2 + 1) != std::string_view::npos || sp1 == 0 ||
        sp2 == sp1 + 1) {
        return std::unexpected(HeadError{400, "malformed request line"});
    }
    Request r;
    r.method  = line.substr(0, sp1);
    r.target  = line.substr(sp1 + 1, sp2 - sp1 - 1);
    r.version = line.substr(sp2 + 1);
    if (r.version != "HTTP/1.1" && r.version != "HTTP/1.0") {
        if (r.version.starts_with("HTTP/")) return std::unexpected(HeadError{505, "only HTTP/1.1 and HTTP/1.0"});
        return std::unexpected(HeadError{400, "malformed request line"});
    }
    if (!r.target.starts_with('/')) return std::unexpected(HeadError{400, "the target must be a path"});

    size_t count = 0;
    while (!rest.empty()) {
        const size_t     end    = rest.find("\r\n");
        std::string_view header = rest.substr(0, end);
        rest = end == std::string_view::npos ? std::string_view{} : rest.substr(end + 2);
        if (++count > kMaxHeaders) return std::unexpected(HeadError{431, "too many header fields"});
        if (!header.empty() && (header.front() == ' ' || header.front() == '\t')) {
            return std::unexpected(HeadError{400, "obsolete header line folding"});
        }
        const size_t colon = header.find(':');
        if (colon == 0 || colon == std::string_view::npos ||
            header.substr(0, colon).find_first_of(" \t") != std::string_view::npos) {
            return std::unexpected(HeadError{400, "malformed header field"});
        }
        const std::string      name  = lower(header.substr(0, colon));
        const std::string_view value = trim(header.substr(colon + 1));

        if (name == "transfer-encoding") {
            return std::unexpected(HeadError{501, "chunked request bodies are not supported; send Content-Length"});
        }
        if (name == "content-length") {
            uint64_t length = 0;
            auto [end_ptr, ec] = std::from_chars(value.data(), value.data() + value.size(), length);
            if (value.empty() || end_ptr != value.data() + value.size()) {
                return std::unexpected(HeadError{400, "malformed Content-Length"});
            }
            if (ec == std::errc::result_out_of_range) length = UINT64_MAX;
            if (r.headers.contains(name) && r.content_length != length) {
                return std::unexpected(HeadError{400, "conflicting Content-Length"});
            }
            r.content_length = length > SIZE_MAX ? SIZE_MAX : static_cast<size_t>(length);
        }
        auto [it, fresh] = r.headers.try_emplace(name, value);
        if (!fresh && name != "content-length") it->second += ", " + std::string(value);
    }
    return r;
}

/// Does the client want the connection closed after this request?
bool wants_close(const Request& r) {
    const auto  it     = r.headers.find("connection");
    std::string tokens = it == r.headers.end() ? "" : lower(it->second);
    if (tokens.find("close") != std::string::npos) return true;
    return r.version == "HTTP/1.0" && tokens.find("keep-alive") == std::string::npos;
}

class Http1Framing final : public Framing {
public:
    Http1Framing(FramingHost host, std::string path) : host_(std::move(host)), path_(std::move(path)) {}

    void feed(std::span<const uint8_t> bytes) override {
        if (!close_after_) in_.insert(in_.end(), bytes.begin(), bytes.end());  // after a closing request: ignored
    }

    bool process(size_t budget) override {
        while (budget > 0 && !close_after_) {
            const std::string_view data(reinterpret_cast<const char*>(in_.data()), in_.size());
            const size_t           end = data.find("\r\n\r\n");
            if (end == std::string_view::npos || end + 4 > kMaxHead) {
                if (in_.size() > kMaxHead) refuse(431, "request headers too large");
                break;
            }
            auto request = parse_head(data.substr(0, end));
            if (!request) {
                refuse(request.error().status, request.error().why);
                break;
            }
            if (request->content_length > kMaxBody) {
                refuse(413, "a DNS message is at most 65535 bytes");
                break;
            }
            const size_t size = end + 4 + request->content_length;
            if (in_.size() < size) break;  // the body is still on its way

            std::vector<uint8_t> body(in_.begin() + static_cast<ptrdiff_t>(end + 4),
                                      in_.begin() + static_cast<ptrdiff_t>(size));
            in_.erase(in_.begin(), in_.begin() + static_cast<ptrdiff_t>(size));
            const uint64_t tag = next_tag_++;
            if (wants_close(*request)) close_after_ = tag;
            if (serve(tag, *request, body)) --budget;
        }
        return true;  // HTTP errors are answered, never a reason to drop silently
    }

    void answer(uint64_t tag, const Message& response) override {
        const std::vector<uint8_t> body  = wire::build(response, {.max_size = 65535});
        const std::string          cache = "Cache-Control: max-age=" + std::to_string(max_age(response)) + "\r\n";
        release(tag, http_response(200, kDnsMessage, body, cache, close_after_ == tag));
    }

    [[nodiscard]] bool   done() const override { return done_; }
    [[nodiscard]] size_t buffered() const override { return in_.size(); }

private:
    /// Route one complete request. True if it became a query.
    bool serve(uint64_t tag, const Request& r, const std::vector<uint8_t>& body) {
        const size_t           mark   = r.target.find('?');
        const std::string_view target = r.target;
        if (target.substr(0, mark) != path_) {
            fail(tag, 404, "DNS queries go to " + path_);
            return false;
        }
        std::optional<std::vector<uint8_t>> message;
        if (r.method == "GET") {
            const auto dns = query_param(mark == std::string::npos ? "" : target.substr(mark + 1), "dns");
            if (!dns) {
                fail(tag, 400, "missing the dns query parameter");
                return false;
            }
            message = base64url_decode(*dns);
            if (!message) {
                fail(tag, 400, "the dns parameter is not base64url");
                return false;
            }
        } else if (r.method == "POST") {
            const auto it   = r.headers.find("content-type");
            const auto type = it == r.headers.end() ? std::string{} : lower(trim(it->second.substr(0, it->second.find(';'))));
            if (type != kDnsMessage) {
                fail(tag, 415, "send the query as application/dns-message");
                return false;
            }
            message = body;
        } else {
            fail(tag, 405, "only GET and POST", "Allow: GET, POST\r\n");
            return false;
        }

        auto query = wire::parse(*message);
        if (!query || query->header.qr) {
            fail(tag, 400, "not a DNS query");
            return false;
        }
        host_.query(std::move(*query), tag);
        return true;
    }

    /// A request whose end can't be found: answer it, then close.
    void refuse(int status, const std::string& why) {
        in_.clear();
        const uint64_t tag = next_tag_++;
        close_after_       = tag;
        fail(tag, status, why);
    }

    void fail(uint64_t tag, int status, const std::string& why, std::string_view extra_headers = {}) {
        if (host_.stats) ++host_.stats->http_errors;
        const std::string body = why + "\n";
        release(tag, http_response(status, "text/plain; charset=utf-8",
                                   std::span(reinterpret_cast<const uint8_t*>(body.data()), body.size()), extra_headers,
                                   close_after_ == tag));
    }

    /// Responses leave in request order: one ready early waits its turn.
    void release(uint64_t tag, std::vector<uint8_t> response) {
        ready_.emplace(tag, std::move(response));
        for (auto it = ready_.find(next_to_send_); it != ready_.end(); it = ready_.find(next_to_send_)) {
            host_.send(std::move(it->second));
            ready_.erase(it);
            if (close_after_ == next_to_send_) done_ = true;
            ++next_to_send_;
        }
    }

    FramingHost                              host_;
    std::string                              path_;
    std::vector<uint8_t>                     in_;
    uint64_t                                 next_tag_     = 0;
    uint64_t                                 next_to_send_ = 0;
    std::map<uint64_t, std::vector<uint8_t>> ready_;        // responses waiting for earlier ones
    std::optional<uint64_t>                  close_after_;  // the last request served before closing
    bool                                     done_ = false;
};

}  // namespace

std::unique_ptr<Framing> make_http_framing(FramingHost host, std::string path) {
    return std::make_unique<Http1Framing>(std::move(host), std::move(path));
}

}  // namespace dnsentinel::net::detail
