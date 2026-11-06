#ifndef CVPN_PROTOCOL_H
#define CVPN_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#define CVPN_HEADER_SIZE 8u
#define CVPN_MTU_DEFAULT 1280u
#define CVPN_MTU_MIN 1280u
#define CVPN_MTU_MAX 9000u
#define CVPN_OUTER_RESERVE 80u
#define CVPN_FRAME_MAX (CVPN_HEADER_SIZE + CVPN_MTU_MAX)
#define CVPN_HELLO_SIZE 10u

enum cvpn_type { CVPN_HELLO = 1, CVPN_DATA = 2, CVPN_CLOSE = 3 };

struct cvpn_frame {
    enum cvpn_type type;
    const unsigned char *payload;
    size_t length;
};

/* Addresses are the four bytes of an IPv4 address in network byte order. */
int cvpn_mtu_valid(size_t mtu);
size_t cvpn_link_mtu(size_t inner_mtu);
size_t cvpn_encode(unsigned char *output, size_t capacity, enum cvpn_type type,
                   const unsigned char *payload, size_t length);
int cvpn_decode(const unsigned char *input, size_t length, struct cvpn_frame *out);
void cvpn_hello(unsigned char output[CVPN_HELLO_SIZE],
                const unsigned char local[4], const unsigned char peer[4], uint16_t mtu);
int cvpn_check_hello(const unsigned char *payload, size_t length,
                     const unsigned char local[4], const unsigned char peer[4], uint16_t mtu);
int cvpn_ipv4(const unsigned char *packet, size_t length, size_t mtu);

#endif
