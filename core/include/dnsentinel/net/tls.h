#pragma once
/// @file net/tls.h
/// Server-side TLS for DNS over TLS and DNS over HTTPS (plan §6.2, §6.3),
/// on OpenSSL, for nonblocking sockets driven by the event loop.

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <string>
#include <vector>

struct ssl_ctx_st;  // OpenSSL's SSL_CTX
struct ssl_st;      // OpenSSL's SSL

namespace dnsentinel::net {

/// A certificate and its key, loaded once and shared by every connection.
/// TLS 1.2 or newer only.
class TlsContext {
public:
    /// Load a PEM certificate (chain) and the matching private key. `alpn`
    /// lists the application protocols to agree on, in our order of
    /// preference ("dot", or "h2" and "http/1.1"); a client offering none of
    /// them still gets a connection, just without ALPN. Errors name the file
    /// and say what is wrong with it.
    [[nodiscard]] static std::expected<std::shared_ptr<TlsContext>, std::string>
    create_server(const std::string& cert_path, const std::string& key_path, std::vector<std::string> alpn = {});

    ~TlsContext();
    TlsContext(const TlsContext&)            = delete;
    TlsContext& operator=(const TlsContext&) = delete;

    [[nodiscard]] ssl_ctx_st* native() const { return ctx_; }

private:
    TlsContext(ssl_ctx_st* ctx, std::vector<uint8_t> alpn_wire);

    ssl_ctx_st*          ctx_;
    std::vector<uint8_t> alpn_wire_;  // length-prefixed protocol names, for the ALPN callback
};

/// One connection's TLS, server side. The handshake happens inside the
/// first read() and write() calls; like the socket underneath, either can
/// say "try again when the socket is readable (or writable)".
class TlsSession {
public:
    enum class Status {
        Ok,         // `bytes` were read or written
        WantRead,   // retry the same call once the socket is readable
        WantWrite,  // retry the same call once the socket is writable
        Closed,     // the peer closed the connection (cleanly or not)
        Error,      // a TLS failure: a bad handshake, or garbage; close
    };
    struct Result {
        Status status = Status::Ok;
        size_t bytes  = 0;
    };

    /// `fd` stays owned by the caller and must outlive the session.
    TlsSession(const TlsContext& context, int fd);
    ~TlsSession();
    TlsSession(const TlsSession&)            = delete;
    TlsSession& operator=(const TlsSession&) = delete;

    Result read(uint8_t* buffer, size_t size);
    Result write(const uint8_t* data, size_t size);  // may write less than `size`

    /// Decrypted bytes are waiting inside TLS. No socket event will announce
    /// them, so the caller must read again without waiting for one.
    [[nodiscard]] bool has_buffered() const;

    [[nodiscard]] bool handshake_done() const;

    /// The protocol agreed by ALPN, or "" if none was.
    [[nodiscard]] std::string alpn() const;

    /// Send close_notify, without waiting for the peer's.
    void shutdown();

private:
    ssl_st* ssl_;
};

}  // namespace dnsentinel::net
