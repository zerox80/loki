#include "cvpn/dtls.h"
#include "cvpn/runtime.h"
#include "internal.h"

#include <arpa/inet.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

static unsigned char cookie_key[32];

static int cookie_mac(SSL *ssl, const unsigned char bucket[4], unsigned char output[32])
{
    struct sockaddr_storage storage = {0};
    const struct sockaddr_in *peer = (const struct sockaddr_in *)&storage;
    unsigned char input[10];
    size_t result_size = 0;

    if (BIO_dgram_get_peer(SSL_get_rbio(ssl), &storage) <= 0 || storage.ss_family != AF_INET)
        return 0;
    memcpy(input, &peer->sin_addr, 4);
    memcpy(input + 4, &peer->sin_port, 2);
    memcpy(input + 6, bucket, 4);
    return EVP_Q_mac(NULL, "HMAC", NULL, "SHA256", NULL,
                     cookie_key, sizeof(cookie_key), input, sizeof(input),
                     output, 32, &result_size) != NULL && result_size == 32;
}

static int cookie_generate(SSL *ssl, unsigned char *cookie, unsigned int *length)
{
    uint32_t bucket = htonl((uint32_t)(cvpn_clock_ms() / 60000u));
    memcpy(cookie, &bucket, 4);
    if (!cookie_mac(ssl, cookie, cookie + 4))
        return 0;
    *length = 36;
    return 1;
}

static int cookie_verify(SSL *ssl, const unsigned char *cookie, unsigned int length)
{
    uint32_t bucket;
    uint32_t now = (uint32_t)(cvpn_clock_ms() / 60000u);
    unsigned char expected[32];

    if (length != 36)
        return 0;
    memcpy(&bucket, cookie, 4);
    bucket = ntohl(bucket);
    if (bucket != now && bucket != now - 1u)
        return 0;
    return cookie_mac(ssl, cookie, expected) && !CRYPTO_memcmp(expected, cookie + 4, 32);
}

int cvpn_dtls_cookie_init(void)
{
    return RAND_priv_bytes(cookie_key, (int)sizeof(cookie_key)) == 1;
}

void cvpn_dtls_cookie_cleanup(void)
{
    OPENSSL_cleanse(cookie_key, sizeof(cookie_key));
}

void cvpn_dtls_cookie_bind(SSL_CTX *context)
{
    SSL_CTX_set_cookie_generate_cb(context, cookie_generate);
    SSL_CTX_set_cookie_verify_cb(context, cookie_verify);
}
