#ifndef CVPN_SESSION_H
#define CVPN_SESSION_H

#include "cvpn/dtls.h"

void cvpn_session_run(SSL *ssl, int fd, int tun, const struct cvpn_options *options);

#endif
