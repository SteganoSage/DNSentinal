#pragma once
/// TLS helpers for tests: a throwaway certificate, made in-process, and a
/// blocking TLS client that runs on its own thread (the listener under test
/// needs the event loop's thread).

#include "dnsentinel/net/event_loop.h"
#include "dnsentinel/wire/parser.h"

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cstdio>
#include <functional>
#include <span>
#include <string>
#include <thread>
#include <vector>

namespace dnsentinel::test {

/// A self-signed certificate for localhost and 127.0.0.1, and its key, as
/// PEM files in the test temp directory. Removed when it goes away.
class TestCert {
public:
    TestCert() {
        static std::atomic<int> next{0};
        const std::string base = ::testing::TempDir() + "dnsentinel-tls-" + std::to_string(::getpid()) + "-" +
                                 std::to_string(next++);
        cert = base + ".crt";
        key  = base + ".key";

        EVP_PKEY* pkey = EVP_EC_gen("P-256");
        X509*     x509 = X509_new();
        X509_set_version(x509, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
        X509_gmtime_adj(X509_getm_notBefore(x509), -60);
        X509_gmtime_adj(X509_getm_notAfter(x509), 24 * 3600);
        X509_set_pubkey(x509, pkey);
        X509_NAME* name = X509_get_subject_name(x509);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("localhost"), -1,
                                   -1, 0);
        X509_set_issuer_name(x509, name);
        X509V3_CTX ctx;
        X509V3_set_ctx_nodb(&ctx);
        X509V3_set_ctx(&ctx, x509, x509, nullptr, nullptr, 0);
        X509_EXTENSION* san = X509V3_EXT_conf_nid(nullptr, &ctx, NID_subject_alt_name, "DNS:localhost,IP:127.0.0.1");
        X509_add_ext(x509, san, -1);
        X509_EXTENSION_free(san);
        X509_sign(x509, pkey, EVP_sha256());

        FILE* f = std::fopen(cert.c_str(), "w");
        PEM_write_X509(f, x509);
        std::fclose(f);
        f = std::fopen(key.c_str(), "w");
        PEM_write_PrivateKey(f, pkey, nullptr, nullptr, 0, nullptr, nullptr);
        std::fclose(f);
        X509_free(x509);
        EVP_PKEY_free(pkey);
    }
    ~TestCert() {
        ::unlink(cert.c_str());
        ::unlink(key.c_str());
    }
    TestCert(const TestCert&)            = delete;
    TestCert& operator=(const TestCert&) = delete;

    std::string cert, key;
};

/// What a TlsClient saw.
struct TlsClientResult {
    bool                 handshake = false;  // completed, with the certificate verified
    std::string          alpn;               // agreed protocol, "" if none
    std::vector<uint8_t> received;           // everything read after the handshake
    bool                 closed = false;     // the server closed the connection
};

/// Connects to 127.0.0.1:`port` over TLS, trusting only `ca_file`, sends
/// `to_send`, then reads until `done(received)` says enough, the server
/// closes, or 3 s pass. Runs on its own thread and stops `loop` when it
/// finishes, so the test can run the loop until then.
class TlsClient {
public:
    TlsClient(net::EventLoop& loop, uint16_t port, std::string ca_file, std::vector<uint8_t> to_send,
              std::function<bool(const std::vector<uint8_t>&)> done, std::string alpn_offer = "")
        : thread_([&loop, port, ca = std::move(ca_file), send = std::move(to_send), done = std::move(done),
                   alpn = std::move(alpn_offer), this] {
              run(port, ca, send, done, alpn);
              loop.stop();
          }) {}
    ~TlsClient() { join(); }

    void join() {
        if (thread_.joinable()) thread_.join();
    }
    TlsClientResult result;

private:
    void run(uint16_t port, const std::string& ca, const std::vector<uint8_t>& send,
             const std::function<bool(const std::vector<uint8_t>&)>& done, const std::string& alpn) {
        const int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(port);
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
        timeval timeout{3, 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout);
        if (connect(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof addr) != 0) {
            ::close(fd);
            return;
        }

        SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
        SSL_CTX_load_verify_locations(ctx, ca.c_str(), nullptr);
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
        SSL* ssl = SSL_new(ctx);
        X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl), "127.0.0.1");
        if (!alpn.empty()) {
            std::vector<uint8_t> wire{static_cast<uint8_t>(alpn.size())};
            wire.insert(wire.end(), alpn.begin(), alpn.end());
            SSL_set_alpn_protos(ssl, wire.data(), static_cast<unsigned>(wire.size()));
        }
        SSL_set_fd(ssl, fd);
        if (SSL_connect(ssl) == 1) {
            result.handshake          = true;
            const unsigned char* data = nullptr;
            unsigned int         len  = 0;
            SSL_get0_alpn_selected(ssl, &data, &len);
            if (data) result.alpn.assign(reinterpret_cast<const char*>(data), len);
            if (!send.empty()) SSL_write(ssl, send.data(), static_cast<int>(send.size()));
            uint8_t buf[4096];
            while (!done(result.received)) {
                const int n = SSL_read(ssl, buf, sizeof buf);
                if (n <= 0) {
                    const int error = SSL_get_error(ssl, n);
                    result.closed   = error == SSL_ERROR_ZERO_RETURN || error == SSL_ERROR_SYSCALL ||
                                    (error == SSL_ERROR_SSL && ERR_GET_REASON(ERR_peek_error()) ==
                                                                   SSL_R_UNEXPECTED_EOF_WHILE_READING);
                    break;
                }
                result.received.insert(result.received.end(), buf, buf + n);
            }
        }
        ERR_clear_error();
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        ::close(fd);
    }

    std::thread thread_;
};

/// Splits 2-byte-length framed DNS messages.
inline std::vector<Message> framed_messages(const std::vector<uint8_t>& bytes) {
    std::vector<Message> out;
    size_t               at = 0;
    while (bytes.size() - at >= 2) {
        const size_t length = (size_t{bytes[at]} << 8) | bytes[at + 1];
        if (bytes.size() - at - 2 < length) break;
        if (auto msg = wire::parse(std::span<const uint8_t>(bytes.data() + at + 2, length))) out.push_back(*msg);
        at += 2 + length;
    }
    return out;
}

}  // namespace dnsentinel::test
