#include "cvpn/protocol.h"
#include <string.h>

int cvpn_mtu_valid(size_t mtu)
{
    return mtu >= CVPN_MTU_MIN && mtu <= CVPN_MTU_MAX;
}

size_t cvpn_link_mtu(size_t inner_mtu)
{
    return cvpn_mtu_valid(inner_mtu) ? inner_mtu + CVPN_OUTER_RESERVE : 0;
}
