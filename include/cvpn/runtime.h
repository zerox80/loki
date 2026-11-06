#ifndef CVPN_RUNTIME_H
#define CVPN_RUNTIME_H

#include <stdint.h>

uint64_t cvpn_clock_ms(void);
int cvpn_signals_install(void);
int cvpn_stopping(void);

#endif
