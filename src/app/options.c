#include "cvpn/options.h"
#include "cvpn/protocol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void cvpn_options_usage(const char *program)
{
    fprintf(stderr,
        "Usage: %s client|server --endpoint IPV4 --tun NAME\n"
        "       --cert FILE --key FILE --ca FILE --peer-name DNS_NAME\n"
        "       [--port 4433] [--local-ip IPV4] [--peer-ip IPV4]\n"
        "       [--mtu 1280] [--session-seconds 1800]\n"
        "MTU is the inner IP MTU (1280..9000); outer budget is MTU + 80.\n"
        "Server endpoint is the local bind address (e.g. 0.0.0.0).\n"
        "Client endpoint is the server's numeric IPv4 address.\n"
        "Prepare the TUN interface with tools/network.py before starting.\n",
        program);
}

static int parse_unsigned(const char *text, unsigned long low, unsigned long high,
                          unsigned long *result)
{
    char *end = NULL;
    unsigned long number;
    if (!text || !*text || strspn(text, "0123456789") != strlen(text))
        return 0;
    errno = 0;
    number = strtoul(text, &end, 10);
    if (errno || !end || *end || number < low || number > high)
        return 0;
    *result = number;
    return 1;
}

int cvpn_options_parse(int argc, char **argv, struct cvpn_options *out)
{
    static const struct option names[] = {
        {"endpoint", required_argument, NULL, 'e'},
        {"tun", required_argument, NULL, 't'},
        {"cert", required_argument, NULL, 'c'},
        {"key", required_argument, NULL, 'k'},
        {"ca", required_argument, NULL, 'a'},
        {"peer-name", required_argument, NULL, 'n'},
        {"port", required_argument, NULL, 'p'},
        {"local-ip", required_argument, NULL, 'l'},
        {"peer-ip", required_argument, NULL, 'r'},
        {"session-seconds", required_argument, NULL, 's'},
        {"mtu", required_argument, NULL, 'm'},
        {NULL, 0, NULL, 0}
    };
    int option;
    unsigned long number;
    struct in_addr endpoint;

    if (argc < 2 || (strcmp(argv[1], "server") && strcmp(argv[1], "client")))
        return 0;
    *out = (struct cvpn_options){.server = !strcmp(argv[1], "server"),
                           .port = 4433, .mtu = CVPN_MTU_DEFAULT, .session_ms = CVPN_SESSION_MAX_MS};
    (void)inet_pton(AF_INET, out->server ? "10.203.0.1" : "10.203.0.2", &out->local_ip);
    (void)inet_pton(AF_INET, out->server ? "10.203.0.2" : "10.203.0.1", &out->peer_ip);
    optind = 2;
    while ((option = getopt_long(argc, argv, "", names, NULL)) != -1) {
        switch (option) {
        case 'e': out->endpoint = optarg; break;
        case 't': out->tun = optarg; break;
        case 'c': out->cert = optarg; break;
        case 'k': out->key = optarg; break;
        case 'a': out->ca = optarg; break;
        case 'n': out->peer_name = optarg; break;
        case 'p':
            if (!parse_unsigned(optarg, 1, 65535, &number)) return 0;
            out->port = (uint16_t)number;
            break;
        case 'l': if (inet_pton(AF_INET, optarg, &out->local_ip) != 1) return 0; break;
        case 'r': if (inet_pton(AF_INET, optarg, &out->peer_ip) != 1) return 0; break;
        case 's':
            if (!parse_unsigned(optarg, 5, 1800, &number)) return 0;
            out->session_ms = (uint64_t)number * 1000u;
            break;
        case 'm':
            if (!parse_unsigned(optarg, CVPN_MTU_MIN, CVPN_MTU_MAX, &number)) return 0;
            out->mtu = (uint16_t)number;
            break;
        default: return 0;
        }
    }
    if (optind != argc || !out->endpoint || !out->tun || !out->cert ||
        !out->key || !out->ca || !out->peer_name || !*out->peer_name ||
        !*out->tun || strlen(out->tun) >= IFNAMSIZ ||
        inet_pton(AF_INET, out->endpoint, &endpoint) != 1 ||
        out->local_ip.s_addr == out->peer_ip.s_addr)
        return 0;
    if (!out->server && (ntohl(endpoint.s_addr) == 0 ||
        ntohl(endpoint.s_addr) >= UINT32_C(0xe0000000)))
        return 0;
    return 1;
}
