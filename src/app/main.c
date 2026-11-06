#include "cvpn/options.h"
#include "cvpn/dtls.h"
#include "cvpn/runtime.h"
#include "cvpn/session.h"
#include "cvpn/tun.h"
#include "cvpn/udp.h"

#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/err.h>

int main(int argc, char **argv)
{
    struct cvpn_options options;
    SSL_CTX *context;
    int tun;

    if (!cvpn_options_parse(argc, argv, &options)) {
        cvpn_options_usage(argv[0]);
        return EXIT_FAILURE;
    }
    if (cvpn_signals_install() < 0) {
        perror("sigaction");
        return EXIT_FAILURE;
    }
    if (!cvpn_dtls_cookie_init())
        return EXIT_FAILURE;
    context = cvpn_dtls_context_new(&options);
    if (!context)
        return EXIT_FAILURE;
    tun = cvpn_tun_open(&options);
    if (tun < 0) {
        SSL_CTX_free(context);
        return EXIT_FAILURE;
    }
    while (!cvpn_stopping()) {
        int fd = cvpn_udp_open(&options);
        SSL *ssl;
        if (fd < 0)
            break;
        ssl = cvpn_dtls_new(context, fd, &options);
        if (!ssl) {
            ERR_print_errors_fp(stderr);
            close(fd);
            break;
        }
        if ((!options.server || cvpn_dtls_listen(ssl, fd)) && cvpn_dtls_handshake(ssl, fd, &options))
            cvpn_session_run(ssl, fd, tun, &options);
        /* Best-effort close_notify also on SIGTERM releases the peer's slot. */
        (void)SSL_shutdown(ssl);
        SSL_free(ssl);
        close(fd);
        if (!cvpn_stopping())
            (void)poll(NULL, 0, 1000);
    }
    close(tun);
    SSL_CTX_free(context);
    cvpn_dtls_cookie_cleanup();
    return cvpn_stopping() ? EXIT_SUCCESS : EXIT_FAILURE;
}
