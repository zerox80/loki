#include "cvpn/dtls.h"
#include "cvpn/runtime.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <sys/socket.h>
#include <openssl/err.h>

#define HANDSHAKE_MS UINT64_C(12000)

int cvpn_dtls_listen(SSL *ssl, int fd)
{
    BIO_ADDR *address = BIO_ADDR_new();
    int success = 0;
    if (!address)
        return 0;
    fprintf(stderr, "Listening for an authenticated peer.\n");
    while (!cvpn_stopping()) {
        struct sockaddr_in peer = {.sin_family = AF_INET};
        size_t address_size = sizeof(peer.sin_addr);
        struct pollfd input = {.fd = fd, .events = POLLIN};
        int result = DTLSv1_listen(ssl, address);
        if (result > 0) {
            if (BIO_ADDR_family(address) != AF_INET ||
                !BIO_ADDR_rawaddress(address, &peer.sin_addr, &address_size))
                break;
            peer.sin_port = BIO_ADDR_rawport(address);
            if (connect(fd, (struct sockaddr *)&peer, sizeof(peer)) < 0 ||
                BIO_ctrl_set_connected(SSL_get_rbio(ssl), &peer) <= 0)
                break;
            success = 1;
            break;
        }
        if (result < 0 || (poll(&input, 1, 200) < 0 && errno != EINTR))
            break;
    }
    BIO_ADDR_free(address);
    return success;
}

int cvpn_dtls_handshake(SSL *ssl, int fd, const struct cvpn_options *options)
{
    uint64_t deadline = cvpn_clock_ms() + HANDSHAKE_MS;
    while (!cvpn_stopping() && cvpn_clock_ms() < deadline) {
        int result;
        int error;
        ERR_clear_error();
        result = SSL_do_handshake(ssl);
        if (result == 1) {
            X509 *peer = SSL_get1_peer_certificate(ssl);
            int verified = peer && SSL_get_verify_result(ssl) == X509_V_OK;
            X509_free(peer);
            if (DTLS_get_data_mtu(ssl) < CVPN_HEADER_SIZE + options->mtu) {
                fprintf(stderr, "DTLS payload capacity cannot carry the configured inner MTU.\n");
                return 0;
            }
            return verified;
        }
        error = SSL_get_error(ssl, result);
        if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
            break;
        if (!cvpn_dtls_wait(ssl, fd, error == SSL_ERROR_WANT_WRITE ? POLLOUT : POLLIN, deadline))
            break;
    }
    fprintf(stderr, "Handshake failed or timed out.\n");
    if (SSL_get_verify_result(ssl) != X509_V_OK)
        fprintf(stderr, "Peer certificate rejected: %s.\n",
                X509_verify_cert_error_string(SSL_get_verify_result(ssl)));
    ERR_print_errors_fp(stderr);
    return 0;
}
