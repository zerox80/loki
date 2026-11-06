#ifndef CVPN_OPTIONS_H
#define CVPN_OPTIONS_H

#include <netinet/in.h>
#include <stdint.h>

#define CVPN_SESSION_MAX_MS UINT64_C(1800000)

struct cvpn_options {
    int server;
    const char *endpoint;
    const char *tun;
    const char *cert;
    const char *key;
    const char *ca;
    const char *peer_name;
    struct in_addr local_ip;
    struct in_addr peer_ip;
    uint16_t port;
    uint16_t mtu;
    uint64_t session_ms;
};


void cvpn_options_usage(const char *program);
int cvpn_options_parse(int argc, char **argv, struct cvpn_options *out);

#endif
