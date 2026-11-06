#include "cvpn/udp.h"

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

int cvpn_udp_open(const struct cvpn_options *options)
{
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(options->port)};
    int discovery = IP_PMTUDISC_DO;
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    /* Outer IP packets must remain whole. Inner IPv4 DF semantics are left
     * to the kernel while forwarding to/from the configured TUN MTU. */
    if (setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &discovery, sizeof(discovery)) < 0) {
        perror("set outer Don't Fragment policy");
        close(fd);
        return -1;
    }
    (void)inet_pton(AF_INET, options->endpoint, &address.sin_addr);
    if ((options->server && bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0) ||
        (!options->server && connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0)) {
        perror(options->server ? "bind UDP" : "connect UDP");
        close(fd);
        return -1;
    }
    return fd;
}
