#include "cvpn/runtime.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

uint64_t cvpn_clock_ms(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) {
        perror("clock_gettime");
        exit(EXIT_FAILURE);
    }
    return (uint64_t)now.tv_sec * 1000u + (uint64_t)now.tv_nsec / 1000000u;
}
