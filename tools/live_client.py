#!/usr/bin/env python3
"""Activate a supervised Linux desktop test, with an independent rollback guard."""

import argparse
import ipaddress
import json
import os
from pathlib import Path
import pwd
import socket
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "tools/network.py"
TUN = "cvpn0"
UNITS = ("cvpn-client-preflight.service", "cvpn-client-test.service")


def run(*args, check=True, timeout=15):
    return subprocess.run(list(map(str, args)), check=check, timeout=timeout,
                          capture_output=True, text=True)


def user_command(uid, *args):
    return ["runuser", "-u", pwd.getpwuid(uid).pw_name, "--", "env",
            f"XDG_RUNTIME_DIR=/run/user/{uid}",
            f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus", *map(str, args)]


def cleanup(uid):
    for unit in UNITS:
        run(*user_command(uid, "systemctl", "--user", "stop", unit), check=False)
    if Path("/run/cvpn-client/state.json").exists():
        result = run(sys.executable, HELPER, "client-down", check=False)
        if result.returncode:
            print(result.stderr, file=sys.stderr)
            # This guard owns this test's dedicated interface/table/priority.
            # Explicitly undo them even if the resolver service is unavailable.
            for command in (("resolvectl", "revert", TUN),
                            ("ip", "-4", "rule", "del", "priority", "11100", "table", "51899"),
                            ("ip", "-4", "route", "flush", "table", "51899"),
                            ("ip", "tuntap", "del", "dev", TUN, "mode", "tun"),
                            ("nft", "delete", "table", "inet", "cvpn_client")):
                run(*command, check=False)
    else:
        run("ip", "tuntap", "del", "dev", TUN, "mode", "tun", check=False)


def start_daemon(args, unit):
    run(*user_command(args.owner, "systemd-run", "--user", f"--unit={unit}", "--collect",
                     "--property=NoNewPrivileges=yes", "--property=Restart=on-failure",
                     "--property=RestartSec=2", "--property=StartLimitIntervalSec=0",
                     f"--property=StandardOutput=append:{args.log}",
                     f"--property=StandardError=append:{args.log}",
                     args.binary, "client", "--endpoint", args.endpoint, "--port", args.port,
                     "--tun", TUN, "--mtu", "1280", "--cert", args.keys / "client.pem",
                     "--key", args.keys / "client.key", "--ca", args.keys / "ca.pem",
                     "--peer-name", "server.cvpn"))


def wait_tunnel():
    deadline = time.monotonic() + 22
    while time.monotonic() < deadline:
        result = run("ping", "-4", "-c", "1", "-W", "1", "10.203.0.1", check=False, timeout=3)
        if result.returncode == 0:
            return
        time.sleep(0.3)
    raise RuntimeError("The authenticated tunnel did not become reachable")


def trace_ip():
    text = run("curl", "--ipv4", "--noproxy", "*", "--fail", "--silent", "--show-error",
               "--max-time", "10", "https://1.1.1.1/cdn-cgi/trace", timeout=12).stdout
    return dict(line.split("=", 1) for line in text.splitlines() if "=" in line)["ip"]


def dns_udp():
    ident = os.urandom(2)
    query = ident + struct.pack("!HHHHH", 0x0100, 1, 0, 0, 0)
    query += b"\x06google\x02de\0" + struct.pack("!HH", 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)
        sock.sendto(query, ("1.1.1.1", 53))
        answer, peer = sock.recvfrom(4096)
    if peer[0] != "1.1.1.1" or answer[:2] != ident or len(answer) < 12 or \
       not answer[2] & 0x80 or answer[3] & 0x0F or int.from_bytes(answer[6:8], "big") == 0:
        raise RuntimeError("DNS over UDP through the tunnel failed")


def activate(args):
    if Path(f"/sys/class/net/{TUN}").exists() or Path("/run/cvpn-client").exists():
        raise RuntimeError("Existing CVPN configuration found; refusing to overwrite it")
    for unit in UNITS:
        if run(*user_command(args.owner, "systemctl", "--user", "is-active", unit), check=False).returncode == 0:
            raise RuntimeError(f"Existing test service is active: {unit}")
    args.log.touch(exist_ok=True)
    os.chown(args.log, args.owner, pwd.getpwuid(args.owner).pw_gid)
    # Independent root process survives loss of this activation process and
    # restores the original network if validation never completes.
    guard_code = ("import subprocess,time; time.sleep(90); "
                  f"subprocess.run({[sys.executable, str(Path(__file__).resolve()), 'stop', '--owner', str(args.owner)]!r})")
    guard = subprocess.Popen([sys.executable, "-c", guard_code], start_new_session=True,
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        print("Phase 1: authenticated UDP tunnel and routed Internet probe, before changing the default route.", flush=True)
        run("ip", "tuntap", "add", "dev", TUN, "mode", "tun", "user", args.owner)
        run("ip", "addr", "add", "10.203.0.2/30", "dev", TUN)
        run("ip", "link", "set", "dev", TUN, "mtu", "1280", "up")
        run("ip", "route", "add", "1.1.1.1/32", "dev", TUN, "src", "10.203.0.2")
        start_daemon(args, "cvpn-client-preflight")
        wait_tunnel()
        if trace_ip() != args.endpoint:
            raise RuntimeError("The preflight Internet probe did not exit through the VPN server")
        run(*user_command(args.owner, "systemctl", "--user", "stop", UNITS[0]))
        run("ip", "tuntap", "del", "dev", TUN, "mode", "tun")
        print("Phase 2: full tunnel, DNS and kill switch.", flush=True)
        run(sys.executable, HELPER, "client-up", "--endpoint", args.endpoint,
            "--port", args.port, "--owner", args.owner, "--mtu", "1280")
        start_daemon(args, "cvpn-client-test")
        wait_tunnel()
        exit_ip = trace_ip()
        if exit_ip != args.endpoint:
            raise RuntimeError("Full-tunnel exit address does not match the server")
        dns_udp()
        resolver = run("resolvectl", "query", "--interface=cvpn0", "google.de", timeout=10).stdout
        http = run("curl", "--ipv4", "--noproxy", "*", "--silent", "--show-error",
                   "--max-time", "10", "--output", "/dev/null", "--write-out", "%{http_code}",
                   "https://www.google.de/generate_204", timeout=12).stdout.strip()
        if http != "204":
            raise RuntimeError(f"Internet HTTP probe returned {http}")
        result = {"connected": True, "server": args.endpoint, "transport": "DTLS over UDP",
                  "port": args.port, "inner_mtu": 1280, "outer_mtu_limit": 1360,
                  "exit_ip": exit_ip, "dns_udp": "passed", "resolved_query": resolver,
                  "http_status": http, "service": UNITS[1]}
        args.results.write_text(json.dumps(result, indent=2) + "\n")
        os.chown(args.results, args.owner, pwd.getpwuid(args.owner).pw_gid)
        guard.terminate()
        guard.wait(timeout=3)
        print(json.dumps(result, indent=2), flush=True)
    except BaseException:
        cleanup(args.owner)
        guard.terminate()
        guard.wait(timeout=3)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    start = commands.add_parser("start")
    start.add_argument("--owner", type=int, required=True)
    start.add_argument("--endpoint", required=True)
    start.add_argument("--port", type=int, default=4433)
    for name in ("binary", "keys", "log", "results"):
        start.add_argument(f"--{name}", type=lambda p: Path(p).resolve(), required=True)
    stop = commands.add_parser("stop")
    stop.add_argument("--owner", type=int, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("Run this helper through the system authentication dialog (pkexec)")
    if args.action == "stop":
        cleanup(args.owner)
        print("VPN test stopped; the original network configuration has been restored.")
    else:
        args.endpoint = str(ipaddress.IPv4Address(args.endpoint))
        activate(args)


if __name__ == "__main__":
    main()
