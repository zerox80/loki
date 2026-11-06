#ifndef CVPN_DTLS_H
#define CVPN_DTLS_H

#include "cvpn/options.h"
#include "cvpn/protocol.h"
#include <openssl/ssl.h>
#include <stddef.h>
#include <stdint.h>

int cvpn_dtls_cookie_init(void);
void cvpn_dtls_cookie_cleanup(void);
SSL_CTX *cvpn_dtls_context_new(const struct cvpn_options *options);
SSL *cvpn_dtls_new(SSL_CTX *context, int fd, const struct cvpn_options *options);
int cvpn_dtls_listen(SSL *ssl, int fd);
int cvpn_dtls_handshake(SSL *ssl, int fd, const struct cvpn_options *options);
int cvpn_dtls_wait(SSL *ssl, int fd, short events, uint64_t deadline);
int cvpn_dtls_send_frame(SSL *ssl, int fd, enum cvpn_type type,
                         const unsigned char *payload, size_t payload_size);

#endif
