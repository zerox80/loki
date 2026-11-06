#include "cvpn/runtime.h"

#include <signal.h>
#include <stddef.h>

static volatile sig_atomic_t stop_flag;

static void stop_requested(int signo)
{
    (void)signo;
    stop_flag = 1;
}

int cvpn_signals_install(void)
{
    struct sigaction action = {.sa_handler = stop_requested};
    sigemptyset(&action.sa_mask);
    return sigaction(SIGINT, &action, NULL) < 0 || sigaction(SIGTERM, &action, NULL) < 0 ? -1 : 0;
}

int cvpn_stopping(void)
{
    return stop_flag != 0;
}
