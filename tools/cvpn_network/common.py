"""Shared host validation, persistent state and command helpers."""

import argparse
import ipaddress
import json
from pathlib import Path
import re
import subprocess

TABLE = 51899
PRIORITY = 11100
CLIENT_TABLE = "cvpn_client"
SERVER_TABLE = "cvpn_server"
NAT_TABLE = "cvpn_nat"
MTU_DEFAULT = 1280
MTU_MIN = 1280
MTU_MAX = 9000
OUTER_RESERVE = 80
CLIENT = "10.203.0.2"
SERVER = "10.203.0.1"

def run(*arguments, check=True, data=None):
    return subprocess.run(list(map(str, arguments)), input=data, text=True,
                          capture_output=True, check=check)


def json_command(*arguments):
    result = run(*arguments, check=False)
    if result.returncode:
        return []
    return json.loads(result.stdout or "[]")


def interface(value):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,15}", value):
        raise argparse.ArgumentTypeError("Use a 1–15 character Linux interface name")
    return value


def ipv4(value):
    address = ipaddress.IPv4Address(value)
    if address.is_unspecified or address.is_multicast or address.is_loopback or int(address) == 0xFFFFFFFF:
        raise argparse.ArgumentTypeError("Use a unicast, non-loopback IPv4 address")
    return str(address)


def nft_exists(family, table):
    return run("nft", "list", "table", family, table, check=False).returncode == 0


def check_uplink_mtu(name, inner_mtu):
    links = json_command("ip", "-j", "link", "show", "dev", name)
    budget = inner_mtu + OUTER_RESERVE
    if len(links) != 1 or links[0].get("mtu", 0) < budget:
        raise RuntimeError(f"Uplink {name} needs an MTU of at least {budget} for inner MTU {inner_mtu}")


def save(directory, state):
    # The directory is created by this process with mode 0700 and must not exist
    # before setup. Do not accept someone else's preexisting state directory.
    target = directory / "state.json"
    target.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    target.chmod(0o600)


def prepare_state(args, kind):
    directory = Path(args.state_dir or f"/run/cvpn-{kind}")
    if directory.exists():
        raise RuntimeError(f"State directory already exists: {directory}; run {kind}-down first")
    if json_command("ip", "-j", "link", "show", "dev", args.tun):
        raise RuntimeError(f"Interface already exists: {args.tun}")
    tunnel_network = ipaddress.IPv4Network("10.203.0.0/30")
    for device in json_command("ip", "-j", "-4", "addr", "show"):
        for address in device.get("addr_info", []):
            existing = ipaddress.IPv4Interface(f"{address['local']}/{address['prefixlen']}").network
            if existing.overlaps(tunnel_network):
                raise RuntimeError(f"Tunnel subnet {tunnel_network} overlaps an existing interface")
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    state = {"version": 1, "kind": kind, "tun": args.tun, "owner": args.owner, "port": args.port,
             "mtu": args.mtu, "outer_mtu": args.mtu + OUTER_RESERVE, "tun_planned": False,
             "firewall_planned": False}
    save(directory, state)
    return directory, state


def make_tun(args, address, directory, state):
    state["tun_planned"] = True
    save(directory, state)
    run("ip", "tuntap", "add", "dev", args.tun, "mode", "tun", "user", args.owner)
    run("ip", "addr", "add", f"{address}/30", "dev", args.tun)
    run("ip", "link", "set", "dev", args.tun, "mtu", args.mtu, "up")
