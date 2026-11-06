#include "cvpn/protocol.h"
#include <string.h>

int cvpn_ipv4(const unsigned char *packet, size_t length, size_t mtu)
{
    size_t header_size;
    size_t declared_size;

    if (!packet || !cvpn_mtu_valid(mtu) || length < 20u || length > mtu || (packet[0] >> 4) != 4)
        return 0;
    header_size = (size_t)(packet[0] & 15u) * 4u;
    declared_size = ((size_t)packet[2] << 8) | packet[3];
    return header_size >= 20u && header_size <= length && declared_size == length;
}
