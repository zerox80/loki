#include "cvpn/tun.h"

#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

int cvpn_tun_open(const struct cvpn_options *options)
{
    struct ifreq request = {0};
    int fd = -1;
    int control;

    if (!if_nametoindex(options->tun)) {
        fprintf(stderr, "TUN interface %s does not exist; run the network helper.\n", options->tun);
        return -1;
    }
    memcpy(request.ifr_name, options->tun, strlen(options->tun) + 1);
    control = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (control < 0)
        return -1;
    if (ioctl(control, SIOCGIFMTU, &request) < 0 || request.ifr_mtu != (int)options->mtu) {
        fprintf(stderr, "TUN MTU must match --mtu %u.\n", (unsigned int)options->mtu);
        goto done;
    }
    if (ioctl(control, SIOCGIFADDR, &request) < 0 ||
        ((struct sockaddr_in *)&request.ifr_addr)->sin_addr.s_addr != options->local_ip.s_addr) {
        fprintf(stderr, "TUN IPv4 address does not match --local-ip.\n");
        goto done;
    }
    fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0)
        goto done;
    request.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (ioctl(fd, TUNSETIFF, &request) < 0) {
        perror("TUNSETIFF");
        close(fd);
        fd = -1;
    }
done:
    close(control);
    return fd;
}
