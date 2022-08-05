#include <gtest/gtest.h>
#include <openssl/x509.h>

#include "net/tls.h"

TEST(TlsSerialize, CertWorks) {
    X509 *x = X509_new();
    ag::TlsCert *cert = ag::tls_serialize_cert(x);
    ASSERT_TRUE(cert);
    ASSERT_TRUE(cert->data);
    ASSERT_GT(cert->size, 0);
    ag::tls_free_serialized_cert(cert);
    X509_free(x);
}

TEST(TlsSerialize, ChainWorks) {
    static constexpr size_t NUM_CERTS = 10;

    STACK_OF(X509) *c = sk_X509_new_null();
    for (size_t i = 0; i < NUM_CERTS; ++i) {
        sk_X509_push(c, X509_new());
    }

    ag::TlsChain *chain = ag::tls_serialize_cert_chain(c);
    ASSERT_TRUE(chain);
    ASSERT_TRUE(chain->data);
    ASSERT_EQ(chain->size, sk_X509_num(c));
    for (uint32_t i = 0; i < chain->size; ++i) {
        ASSERT_TRUE(chain->data[i].data);
        ASSERT_GT(chain->data[i].size, 0);
    }
    ag::tls_free_serialized_chain(chain);

    sk_X509_pop_free(c, [](X509 *x) {
        X509_free(x);
    });
}
