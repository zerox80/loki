#include "cvpn/session.h"
#include "cvpn/runtime.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/err.h>

#define IDLE_MS UINT64_C(15000)
#define MAX_RECORDS UINT64_C(1048576)

void cvpn_session_run(SSL *ssl, int fd, int tun, const struct cvpn_options *options)
{
    unsigned char hello[CVPN_HELLO_SIZE];
    unsigned char incoming[65536];
    unsigned char outgoing[65536];
    uint64_t started = cvpn_clock_ms();
    uint64_t last_rx = started;
    uint64_t next_hello = 0;
    uint64_t records = 0;
    uint64_t tx_packets = 0, rx_packets = 0, dropped = 0;
    int ready = 0;

    cvpn_hello(hello, (const unsigned char *)&options->local_ip,
                (const unsigned char *)&options->peer_ip, options->mtu);
    fprintf(stderr, "Authenticated %s using %s.\n", options->peer_name, SSL_get_cipher(ssl));
    fprintf(stderr, "MTU: inner=%u, outer-budget=%zu (includes %u-byte reserve).\n",
            (unsigned int)options->mtu, cvpn_link_mtu(options->mtu), CVPN_OUTER_RESERVE);
    while (!cvpn_stopping()) {
        uint64_t now = cvpn_clock_ms();
        struct pollfd inputs[2] = {
            {.fd = fd, .events = POLLIN},
            {.fd = tun, .events = ready ? POLLIN : 0}
        };
        int polled;

        if (now - last_rx >= IDLE_MS) {
            fprintf(stderr, "Peer idle timeout.\n");
            break;
        }
        if (now - started >= options->session_ms || records >= MAX_RECORDS) {
            fprintf(stderr, "Session limit reached; establishing fresh keys.\n");
            break;
        }
        if (now >= next_hello) {
            if (!cvpn_dtls_send_frame(ssl, fd, CVPN_HELLO, hello, sizeof(hello)))
                break;
            records++;
            next_hello = now + (ready ? 5000u : 1000u);
        }
        polled = poll(inputs, 2, SSL_pending(ssl) > 0 ? 0 : 100);
        if (polled < 0) {
            if (errno == EINTR) continue;
            perror("poll");
            break;
        }
        if (inputs[0].revents & (POLLERR | POLLHUP | POLLNVAL))
            break;
        if (inputs[1].revents & (POLLERR | POLLHUP | POLLNVAL))
            break;
        if (DTLSv1_handle_timeout(ssl) < 0)
            break;
        if ((inputs[0].revents & POLLIN) || SSL_pending(ssl) > 0) {
            for (unsigned int batch = 0; batch < 64; batch++) {
                struct cvpn_frame frame;
                size_t size = 0;
                int result;
                ERR_clear_error();
                result = SSL_read_ex(ssl, incoming, sizeof(incoming), &size);
                if (result != 1) {
                    int error = SSL_get_error(ssl, result);
                    if (error == SSL_ERROR_WANT_READ) break;
                    if (error == SSL_ERROR_WANT_WRITE &&
                        cvpn_dtls_wait(ssl, fd, POLLOUT, cvpn_clock_ms() + 1000u))
                        break;
                    goto done;
                }
                if (!cvpn_decode(incoming, size, &frame)) {
                    fprintf(stderr, "Invalid authenticated CVPN record.\n");
                    goto done;
                }
                if (frame.type == CVPN_CLOSE)
                    goto done;
                if (frame.type == CVPN_HELLO) {
                    if (!cvpn_check_hello(frame.payload, frame.length,
                                          (const unsigned char *)&options->local_ip,
                                          (const unsigned char *)&options->peer_ip, options->mtu)) {
                        fprintf(stderr, "Peer tunnel configuration mismatch.\n");
                        goto done;
                    }
                    if (!ready) {
                        ready = 1;
                        fprintf(stderr, "Tunnel ready.\n");
                    }
                } else {
                    const unsigned char *address = frame.payload + (options->server ? 12 : 16);
                    const struct in_addr *expected = options->server ? &options->peer_ip : &options->local_ip;
                    if (!ready || !cvpn_ipv4(frame.payload, frame.length, options->mtu) || memcmp(address, expected, 4)) {
                        dropped++;
                        continue;
                    }
                    ssize_t written = write(tun, frame.payload, frame.length);
                    if (written == (ssize_t)frame.length) rx_packets++;
                    else if (written < 0 && (errno == EAGAIN || errno == EINTR)) dropped++;
                    else goto done;
                }
                last_rx = cvpn_clock_ms();
            }
        }
        if (ready && (inputs[1].revents & POLLIN)) {
            ssize_t length = read(tun, outgoing, sizeof(outgoing));
            if (length < 0 && (errno == EAGAIN || errno == EINTR)) continue;
            if (length <= 0) break;
            const unsigned char *address = outgoing + (options->server ? 16 : 12);
            const struct in_addr *expected = options->server ? &options->peer_ip : &options->local_ip;
            if (!cvpn_ipv4(outgoing, (size_t)length, options->mtu) || memcmp(address, expected, 4)) {
                dropped++;
                continue;
            }
            if (!cvpn_dtls_send_frame(ssl, fd, CVPN_DATA, outgoing, (size_t)length))
                break;
            records++;
            tx_packets++;
        }
    }
done:
    if (!cvpn_stopping())
        (void)cvpn_dtls_send_frame(ssl, fd, CVPN_CLOSE, NULL, 0);
    fprintf(stderr, "Session ended: tx=%llu rx=%llu dropped=%llu.\n",
            (unsigned long long)tx_packets, (unsigned long long)rx_packets,
            (unsigned long long)dropped);
}
