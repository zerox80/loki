#include "cvpn/dtls.h"
#include "cvpn/runtime.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <sys/time.h>
#include <openssl/err.h>

int cvpn_dtls_wait(SSL *ssl, int fd, short events, uint64_t deadline)
{
    struct timeval timeout;
    struct pollfd input = {.fd = fd, .events = events};
    uint64_t now = cvpn_clock_ms();
    uint64_t remaining;
    int wait_ms;

    if (cvpn_stopping() || now >= deadline)
        return 0;
    remaining = deadline - now;
    wait_ms = remaining < 200u ? (int)remaining : 200;
    if (DTLSv1_get_timeout(ssl, &timeout)) {
        uint64_t timer_ms = (uint64_t)timeout.tv_sec * 1000u +
                            ((uint64_t)timeout.tv_usec + 999u) / 1000u;
        if (timer_ms < (uint64_t)wait_ms)
            wait_ms = (int)timer_ms;
    }
    if (poll(&input, 1, wait_ms) < 0 && errno != EINTR)
        return 0;
    if (DTLSv1_handle_timeout(ssl) < 0)
        return 0;
    return !cvpn_stopping();
}

int cvpn_dtls_send_frame(SSL *ssl, int fd, enum cvpn_type type,
                       const unsigned char *payload, size_t payload_size)
{
    unsigned char frame[CVPN_FRAME_MAX];
    size_t frame_size = cvpn_encode(frame, sizeof(frame), type, payload, payload_size);
    uint64_t deadline = cvpn_clock_ms() + 1000u;
    if (!frame_size)
        return 0;
    while (!cvpn_stopping() && cvpn_clock_ms() < deadline) {
        size_t written = 0;
        int result;
        int error;
        ERR_clear_error();
        result = SSL_write_ex(ssl, frame, frame_size, &written);
        if (result == 1)
            return written == frame_size;
        error = SSL_get_error(ssl, result);
        if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
            if (errno == EMSGSIZE)
                fprintf(stderr, "Outer path MTU is too small; reduce --mtu (outer budget is MTU + 80).\n");
            return 0;
        }
        if (!cvpn_dtls_wait(ssl, fd, error == SSL_ERROR_WANT_WRITE ? POLLOUT : POLLIN, deadline))
            return 0;
    }
    return 0;
}
