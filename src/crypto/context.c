#include "cvpn/dtls.h"
#include "internal.h"

#include <stdio.h>
#include <sys/socket.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#if OPENSSL_VERSION_NUMBER < 0x30000000L
#error "LOKI requires OpenSSL 3.0 or later"
#endif

SSL_CTX *cvpn_dtls_context_new(const struct cvpn_options *options)
{
    SSL_CTX *context = SSL_CTX_new(DTLS_method());
    if (!context)
        return NULL;
    SSL_CTX_set_security_level(context, 2);
    SSL_CTX_set_options(context, SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION | SSL_OP_NO_TICKET);
    SSL_CTX_set_session_cache_mode(context, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_verify(context, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_verify_depth(context, 1);
    if (!SSL_CTX_set_min_proto_version(context, DTLS1_2_VERSION) ||
        !SSL_CTX_set_max_proto_version(context, DTLS1_2_VERSION) ||
        !SSL_CTX_set_cipher_list(context,
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256") ||
        !SSL_CTX_set1_groups_list(context, "X25519:P-256") ||
        !SSL_CTX_load_verify_locations(context, options->ca, NULL) ||
        !SSL_CTX_use_certificate_chain_file(context, options->cert) ||
        !SSL_CTX_use_PrivateKey_file(context, options->key, SSL_FILETYPE_PEM) ||
        !SSL_CTX_check_private_key(context)) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(context);
        return NULL;
    }
    cvpn_dtls_cookie_bind(context);
    return context;
}

SSL *cvpn_dtls_new(SSL_CTX *context, int fd, const struct cvpn_options *options)
{
    SSL *ssl = SSL_new(context);
    BIO *bio = NULL;
    struct sockaddr_in peer;
    socklen_t peer_size = sizeof(peer);

    if (!ssl)
        return NULL;
    bio = BIO_new_dgram(fd, BIO_NOCLOSE);
    if (!bio) {
        SSL_free(ssl);
        return NULL;
    }
    SSL_set_bio(ssl, bio, bio);
    SSL_set_hostflags(ssl, X509_CHECK_FLAG_NO_WILDCARDS | X509_CHECK_FLAG_NEVER_CHECK_SUBJECT);
    if (!SSL_set1_host(ssl, options->peer_name)) {
        SSL_free(ssl);
        return NULL;
    }
    SSL_set_options(ssl, SSL_OP_NO_QUERY_MTU);
    if (DTLS_set_link_mtu(ssl, (long)cvpn_link_mtu(options->mtu)) <= 0) {
        SSL_free(ssl);
        return NULL;
    }
    if (options->server) {
        SSL_set_accept_state(ssl);
    } else {
        SSL_set_connect_state(ssl);
        if (getpeername(fd, (struct sockaddr *)&peer, &peer_size) < 0 ||
            BIO_ctrl_set_connected(bio, &peer) <= 0) {
            SSL_free(ssl);
            return NULL;
        }
    }
    return ssl;
}
