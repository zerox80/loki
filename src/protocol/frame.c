#include "cvpn/protocol.h"
#include <string.h>

static int valid_size(enum cvpn_type type, size_t length)
{
    switch (type) {
    case CVPN_HELLO: return length == CVPN_HELLO_SIZE;
    case CVPN_DATA: return length >= 20u && length <= CVPN_MTU_MAX;
    case CVPN_CLOSE: return length == 0u;
    default: return 0;
    }
}

size_t cvpn_encode(unsigned char *output, size_t capacity, enum cvpn_type type,
                   const unsigned char *payload, size_t length)
{
    if (!output || !valid_size(type, length) ||
        (length && !payload) || capacity < CVPN_HEADER_SIZE + length)
        return 0;
    memcpy(output, "CVP1", 4);
    output[4] = (unsigned char)type;
    output[5] = 0;
    output[6] = (unsigned char)(length >> 8);
    output[7] = (unsigned char)length;
    if (length)
        memcpy(output + CVPN_HEADER_SIZE, payload, length);
    return CVPN_HEADER_SIZE + length;
}

int cvpn_decode(const unsigned char *input, size_t length, struct cvpn_frame *out)
{
    size_t payload_size;
    enum cvpn_type type;

    if (!input || !out || length < CVPN_HEADER_SIZE || length > CVPN_FRAME_MAX)
        return 0;
    if (memcmp(input, "CVP1", 4) || input[5] != 0)
        return 0;
    type = (enum cvpn_type)input[4];
    payload_size = ((size_t)input[6] << 8) | input[7];
    if (payload_size != length - CVPN_HEADER_SIZE || !valid_size(type, payload_size))
        return 0;
    *out = (struct cvpn_frame){type, input + CVPN_HEADER_SIZE, payload_size};
    return 1;
}
