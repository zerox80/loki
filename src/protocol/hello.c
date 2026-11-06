#include "cvpn/protocol.h"
#include <string.h>

void cvpn_hello(unsigned char output[CVPN_HELLO_SIZE],
                const unsigned char local[4], const unsigned char peer[4], uint16_t mtu)
{
    memcpy(output, local, 4);
    memcpy(output + 4, peer, 4);
    output[8] = (unsigned char)(mtu >> 8);
    output[9] = (unsigned char)mtu;
}

int cvpn_check_hello(const unsigned char *payload, size_t length,
                     const unsigned char local[4], const unsigned char peer[4], uint16_t mtu)
{
    return payload && cvpn_mtu_valid(mtu) && length == CVPN_HELLO_SIZE &&
           !memcmp(payload, peer, 4) && !memcmp(payload + 4, local, 4) &&
           (((unsigned int)payload[8] << 8) | payload[9]) == mtu;
}
