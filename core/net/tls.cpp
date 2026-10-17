/// @file net/tls.cpp
/// OpenSSL glue: the server context, ALPN, and nonblocking reads and writes.

#include "dnsentinel/net/tls.h"

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstring>
#include <fstream>

namespace dnsentinel::net {

namespace {

/// The oldest error on OpenSSL's queue (usually the root cause), as text.
/// Empties the queue.
std::string openssl_error() {
    std::string first;
    while (const unsigned long code = ERR_get_error()) {
        if (!first.empty()) continue;
        const char* reason = ERR_reason_error_string(code);
        first              = reason ? reason : "error " + std::to_string(code);
    }
    return first.empty() ? "unknown TLS error" : first;
}

/// Agree on the first protocol in our list that the client also offers.
int select_alpn(SSL*, const unsigned char** out, unsigned char* out_len, const unsigned char* in, unsigned int in_len,
                void* arg) {
    const auto*    ours     = static_cast<const std::vector<uint8_t>*>(arg);
    unsigned char* selected = nullptr;
    unsigned char  length   = 0;
    if (SSL_select_next_proto(&selected, &length, ours->data(), static_cast<unsigned int>(ours->size()), in,
                              in_len) != OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_NOACK;  // carry on without ALPN
    }
    *out     = selected;
    *out_len = length;
    return SSL_TLSEXT_ERR_OK;
}

}  // namespace

// ─── TlsContext ─────────────────────────────────────────────────────────────

std::expected<std::shared_ptr<TlsContext>, std::string>
TlsContext::create_server(const std::string& cert_path, const std::string& key_path, std::vector<std::string> alpn) {
    for (const std::string* path : {&cert_path, &key_path}) {
        if (!std::ifstream(*path)) return std::unexpected("cannot open " + *path + ": " + std::strerror(errno));
    }
    std::vector<uint8_t> alpn_wire;
    for (const auto& protocol : alpn) {
        if (protocol.empty() || protocol.size() > 255) return std::unexpected("bad ALPN protocol name '" + protocol + "'");
        alpn_wire.push_back(static_cast<uint8_t>(protocol.size()));
        alpn_wire.insert(alpn_wire.end(), protocol.begin(), protocol.end());
    }

    ERR_clear_error();
    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) return std::unexpected("cannot create a TLS context: " + openssl_error());
    auto fail = [ctx](std::string what) {
        what += " (" + openssl_error() + ")";
        SSL_CTX_free(ctx);
        return std::unexpected(std::move(what));
    };

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    // A client that drops the connection without close_notify is just gone,
    // not an error; and no renegotiation, which only adds attack surface.
    SSL_CTX_set_options(ctx, SSL_OP_IGNORE_UNEXPECTED_EOF | SSL_OP_NO_RENEGOTIATION | SSL_OP_CIPHER_SERVER_PREFERENCE);
    // An encrypted key must fail here, not stop the daemon at a password prompt.
    SSL_CTX_set_default_passwd_cb(ctx, [](char*, int, int, void*) { return 0; });

    if (SSL_CTX_use_certificate_chain_file(ctx, cert_path.c_str()) != 1) {
        return fail(cert_path + ": not a usable PEM certificate");
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key_path.c_str(), SSL_FILETYPE_PEM) != 1) {
        // Loading checks the key against the certificate already.
        if (ERR_GET_REASON(ERR_peek_error()) == X509_R_KEY_VALUES_MISMATCH ||
            ERR_GET_REASON(ERR_peek_last_error()) == X509_R_KEY_VALUES_MISMATCH) {
            return fail(key_path + " is not the key for the certificate in " + cert_path);
        }
        return fail(key_path + ": not a usable PEM private key (an unencrypted one is needed)");
    }
    if (SSL_CTX_check_private_key(ctx) != 1) {
        return fail(key_path + " is not the key for the certificate in " + cert_path);
    }
    return std::shared_ptr<TlsContext>(new TlsContext(ctx, std::move(alpn_wire)));
}

TlsContext::TlsContext(ssl_ctx_st* ctx, std::vector<uint8_t> alpn_wire) : ctx_(ctx), alpn_wire_(std::move(alpn_wire)) {
    if (!alpn_wire_.empty()) SSL_CTX_set_alpn_select_cb(ctx_, select_alpn, &alpn_wire_);
}

TlsContext::~TlsContext() { SSL_CTX_free(ctx_); }

// ─── TlsSession ─────────────────────────────────────────────────────────────

TlsSession::TlsSession(const TlsContext& context, int fd) : ssl_(SSL_new(context.native())) {
    if (!ssl_) return;  // out of memory: every call reports Error
    SSL_set_fd(ssl_, fd);
    SSL_set_accept_state(ssl_);
    // Partial writes, like send(): the caller keeps the rest and retries
    // with whatever is left, from wherever its buffer now lives.
    SSL_set_mode(ssl_, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
}

TlsSession::~TlsSession() { SSL_free(ssl_); }

namespace {

TlsSession::Result failure(SSL* ssl, int ret) {
    using Status = TlsSession::Status;
    const int error = SSL_get_error(ssl, ret);
    ERR_clear_error();
    switch (error) {
        case SSL_ERROR_WANT_READ:   return {Status::WantRead, 0};
        case SSL_ERROR_WANT_WRITE:  return {Status::WantWrite, 0};
        case SSL_ERROR_ZERO_RETURN: return {Status::Closed, 0};
        case SSL_ERROR_SYSCALL:     return {Status::Closed, 0};  // the socket failed: reset, broken pipe
        default:                    return {Status::Error, 0};   // a TLS protocol failure
    }
}

}  // namespace

TlsSession::Result TlsSession::read(uint8_t* buffer, size_t size) {
    if (!ssl_) return {Status::Error, 0};
    ERR_clear_error();
    const int n = SSL_read(ssl_, buffer, static_cast<int>(std::min<size_t>(size, INT_MAX)));
    if (n > 0) return {Status::Ok, static_cast<size_t>(n)};
    return failure(ssl_, n);
}

TlsSession::Result TlsSession::write(const uint8_t* data, size_t size) {
    if (!ssl_) return {Status::Error, 0};
    if (size == 0) return {Status::Ok, 0};
    ERR_clear_error();
    const int n = SSL_write(ssl_, data, static_cast<int>(std::min<size_t>(size, INT_MAX)));
    if (n > 0) return {Status::Ok, static_cast<size_t>(n)};
    return failure(ssl_, n);
}

bool TlsSession::has_buffered() const { return ssl_ && SSL_has_pending(ssl_) == 1; }

bool TlsSession::handshake_done() const { return ssl_ && SSL_is_init_finished(ssl_) == 1; }

std::string TlsSession::alpn() const {
    if (!ssl_) return {};
    const unsigned char* data   = nullptr;
    unsigned int         length = 0;
    SSL_get0_alpn_selected(ssl_, &data, &length);
    return data ? std::string(reinterpret_cast<const char*>(data), length) : std::string{};
}

void TlsSession::shutdown() {
    if (!handshake_done()) return;
    ERR_clear_error();
    SSL_shutdown(ssl_);  // one try: we close right after, whatever happens
    ERR_clear_error();
}

}  // namespace dnsentinel::net
