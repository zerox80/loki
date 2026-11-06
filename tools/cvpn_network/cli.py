"""Manage the host TUN, routes, DNS and firewall for LOKI VPN."""

import argparse
import os
import subprocess
import sys

from .client import client_up
from .server import server_up
from .cleanup import down
from .common import MTU_DEFAULT, MTU_MIN, MTU_MAX, interface, ipv4

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for kind in ("client", "server"):
        up = commands.add_parser(f"{kind}-up")
        up.add_argument("--tun", type=interface, default="cvpn0")
        up.add_argument("--owner", type=int, required=True, help="UID that will run the C daemon")
        up.add_argument("--port", type=int, default=4433)
        up.add_argument("--mtu", type=int, default=MTU_DEFAULT,
                        help="Inner IP MTU (1280..9000); outer budget is MTU + 80")
        up.add_argument("--state-dir")
        if kind == "client":
            up.add_argument("--endpoint", type=ipv4, required=True)
            up.add_argument("--dns", type=ipv4, default="1.1.1.1")
            up.add_argument("--dns-mode", choices=("resolved", "manual"), default="resolved")
        else:
            up.add_argument("--wan", type=interface, required=True)
        stop = commands.add_parser(f"{kind}-down")
        stop.add_argument("--state-dir")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("The network helper requires root; the C daemon runs as the selected owner")
    if hasattr(args, "port") and (not 1 <= args.port <= 65535 or args.owner < 0):
        parser.error("Invalid port or UID")
    if hasattr(args, "mtu") and not MTU_MIN <= args.mtu <= MTU_MAX:
        parser.error(f"MTU must be in {MTU_MIN}..{MTU_MAX}")
    os.umask(0o077)
    try:
        if args.command == "client-up": client_up(args)
        elif args.command == "server-up": server_up(args)
        else: down(args, args.command.split("-")[0])
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as error:
        detail = error.stderr.strip() if isinstance(error, subprocess.CalledProcessError) else str(error)
        print(f"CVPN setup/cleanup failed: {detail}", file=sys.stderr)
        print("Partial setup is retained. Use the matching *-down command to clean up;\n"
              "an installed client kill switch remains active until cleanup succeeds.", file=sys.stderr)
        return 1
    return 0
