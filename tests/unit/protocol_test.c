#include "cvpn/protocol.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "Failed: %s, line %d\n", #condition, __LINE__); \
    exit(EXIT_FAILURE); \
} } while (0)

int main(void)
{
    const unsigned char client[4] = {10, 203, 0, 2};
    const unsigned char server[4] = {10, 203, 0, 1};
    const unsigned char expected[] = {
        'C', 'V', 'P', '1', 1, 0, 0, 10, 10, 203, 0, 2, 10, 203, 0, 1, 5, 0
    };
    unsigned char frame[CVPN_FRAME_MAX + 1];
    unsigned char hello[CVPN_HELLO_SIZE];
    unsigned char packet[CVPN_MTU_MAX + 1] = {0};
    struct cvpn_frame decoded;
    size_t size;
    uint32_t random = UINT32_C(0x5a17b39c);

    CHECK(cvpn_link_mtu(1280) == 1360);
    CHECK(cvpn_link_mtu(1400) == 1480);
    CHECK(cvpn_link_mtu(9000) == 9080);
    CHECK(!cvpn_mtu_valid(1279) && !cvpn_mtu_valid(9001));
    CHECK(!cvpn_link_mtu(0) && !cvpn_link_mtu(SIZE_MAX));
    cvpn_hello(hello, client, server, CVPN_MTU_DEFAULT);
    size = cvpn_encode(frame, sizeof(frame), CVPN_HELLO, hello, sizeof(hello));
    CHECK(size == sizeof(expected) && !memcmp(frame, expected, sizeof(expected)));
    CHECK(cvpn_decode(expected, sizeof(expected), &decoded));
    CHECK(cvpn_check_hello(decoded.payload, decoded.length, server, client, CVPN_MTU_DEFAULT));
    CHECK(!cvpn_check_hello(decoded.payload, decoded.length, client, server, CVPN_MTU_DEFAULT));
    CHECK(!cvpn_check_hello(decoded.payload, decoded.length, server, client, 1200));
    CHECK(!cvpn_check_hello(decoded.payload, decoded.length, server, client, 0));
    for (size_t length = 0; length < size; length++)
        CHECK(!cvpn_decode(frame, length, &decoded));
    for (size_t index = 0; index < CVPN_HEADER_SIZE; index++) {
        unsigned char saved = frame[index];
        frame[index] ^= 0x80;
        CHECK(!cvpn_decode(frame, size, &decoded));
        frame[index] = saved;
    }
    CHECK(!cvpn_encode(frame, 3, CVPN_HELLO, hello, sizeof(hello)));
    CHECK(!cvpn_encode(frame, sizeof(frame), CVPN_DATA, packet, sizeof(packet)));
    CHECK(!cvpn_encode(frame, sizeof(frame), CVPN_DATA, NULL, 20));
    CHECK(!cvpn_decode(NULL, 0, &decoded));
    CHECK(!cvpn_decode(expected, sizeof(expected), NULL));

    packet[0] = 0x45;
    packet[2] = 0;
    packet[3] = 20;
    CHECK(cvpn_ipv4(packet, 20, CVPN_MTU_DEFAULT));
    packet[0] = 0x44;
    CHECK(!cvpn_ipv4(packet, 20, CVPN_MTU_DEFAULT));
    packet[0] = 0x4f;
    CHECK(!cvpn_ipv4(packet, 20, CVPN_MTU_DEFAULT));
    packet[0] = 0x45;
    CHECK(!cvpn_ipv4(packet, 21, CVPN_MTU_DEFAULT));
    packet[0] = 0x65;
    CHECK(!cvpn_ipv4(packet, 20, CVPN_MTU_DEFAULT));
    packet[0] = 0x45;
    packet[2] = (unsigned char)(CVPN_MTU_DEFAULT >> 8);
    packet[3] = (unsigned char)CVPN_MTU_DEFAULT;
    CHECK(cvpn_ipv4(packet, CVPN_MTU_DEFAULT, CVPN_MTU_DEFAULT));
    CHECK(!cvpn_ipv4(packet, CVPN_MTU_DEFAULT, 1200));
    packet[3]++;
    CHECK(!cvpn_ipv4(packet, CVPN_MTU_DEFAULT + 1, CVPN_MTU_DEFAULT));
    packet[2] = (unsigned char)(CVPN_MTU_MAX >> 8);
    packet[3] = (unsigned char)CVPN_MTU_MAX;
    CHECK(cvpn_ipv4(packet, CVPN_MTU_MAX, CVPN_MTU_MAX));
    size = cvpn_encode(frame, sizeof(frame), CVPN_DATA, packet, CVPN_MTU_MAX);
    CHECK(size == CVPN_FRAME_MAX && cvpn_decode(frame, size, &decoded));
    CHECK(!cvpn_decode(frame, size + 1, &decoded));
    CHECK(!cvpn_ipv4(packet, CVPN_MTU_MAX + 1, CVPN_MTU_MAX));
    CHECK(cvpn_encode(frame, sizeof(frame), CVPN_CLOSE, NULL, 0) == CVPN_HEADER_SIZE);

    /* Feed arbitrary and near-valid frames through the bounded parser. */
    for (unsigned int iteration = 0; iteration < 50000; iteration++) {
        random ^= random << 13;
        random ^= random >> 17;
        random ^= random << 5;
        size_t length = random % sizeof(frame);
        for (size_t index = 0; index < length; index++)
            frame[index] = (unsigned char)(random + index);
        if ((iteration & 1u) && length >= CVPN_HEADER_SIZE) {
            memcpy(frame, "CVP1", 4);
            frame[4] = (unsigned char)(iteration % 5u);
            frame[5] = 0;
            frame[6] = (unsigned char)((length - CVPN_HEADER_SIZE) >> 8);
            frame[7] = (unsigned char)(length - CVPN_HEADER_SIZE);
        }
        if (cvpn_decode(frame, length, &decoded)) {
            CHECK(decoded.length <= CVPN_MTU_MAX);
            CHECK(decoded.payload == frame + CVPN_HEADER_SIZE);
            CHECK(decoded.length + CVPN_HEADER_SIZE == length);
            if (decoded.type == CVPN_DATA)
                (void)cvpn_ipv4(decoded.payload, decoded.length, CVPN_MTU_DEFAULT);
        }
    }
    puts("PASS: wire vector, malformed lengths/types/versions, IPv4 bounds, 50000 parser inputs.");
    return EXIT_SUCCESS;
}
