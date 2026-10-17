#include "dnsentinel/net/tls.h"

#include "../policy/list_file.h"
#include "tls_test_util.h"

#include <gtest/gtest.h>

#include <string>
#include <vector>

using namespace dnsentinel;
using namespace dnsentinel::net;
using namespace dnsentinel::test;

TEST(TlsContext, LoadsACertificateAndItsKey) {
    TestCert cert;
    auto     tls = TlsContext::create_server(cert.cert, cert.key, {"dot"});
    ASSERT_TRUE(tls.has_value()) << tls.error();
    EXPECT_NE((*tls)->native(), nullptr);
}

TEST(TlsContext, ErrorsNameTheFileAndTheProblem) {
    TestCert cert, other;
    ListFile garbage("not a certificate or a key\n");
    struct Case {
        std::string cert, key, expected;
    };
    const Case cases[] = {
        {"/nonexistent/server.crt", cert.key, "cannot open /nonexistent/server.crt: No such file"},
        {cert.cert, "/nonexistent/server.key", "cannot open /nonexistent/server.key"},
        {garbage.path(), cert.key, garbage.path() + ": not a usable PEM certificate"},
        {cert.cert, garbage.path(), garbage.path() + ": not a usable PEM private key"},
        {cert.cert, other.key, other.key + " is not the key for the certificate in " + cert.cert},
    };
    for (const auto& c : cases) {
        auto tls = TlsContext::create_server(c.cert, c.key);
        ASSERT_FALSE(tls.has_value()) << c.expected;
        EXPECT_NE(tls.error().find(c.expected), std::string::npos) << tls.error();
    }
}

TEST(TlsContext, RejectsBadAlpnNames) {
    TestCert cert;
    auto     tls = TlsContext::create_server(cert.cert, cert.key, {""});
    ASSERT_FALSE(tls.has_value());
    EXPECT_NE(tls.error().find("bad ALPN"), std::string::npos);
}
