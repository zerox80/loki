"""Remove only the resources recorded by the matching setup."""

import json
from pathlib import Path

from .common import (CLIENT_TABLE, SERVER_TABLE, NAT_TABLE, PRIORITY, TABLE,
    interface, json_command, nft_exists, run)

def down(args, kind):
    directory = Path(args.state_dir or f"/run/cvpn-{kind}")
    state = json.loads((directory / "state.json").read_text())
    if state.get("version") != 1 or state.get("kind") != kind:
        raise RuntimeError("Unrecognized state file")
    tun = interface(state["tun"])
    if kind == "client":
        if state.get("dns_planned") and json_command("ip", "-j", "link", "show", "dev", tun):
            run("resolvectl", "revert", tun)
        if state.get("routes_planned"):
            for rule in json_command("ip", "-j", "-4", "rule", "show"):
                if rule.get("priority") == PRIORITY and str(rule.get("table")) == str(TABLE):
                    run("ip", "-4", "rule", "del", "priority", PRIORITY, "table", TABLE)
            run("ip", "-4", "route", "flush", "table", TABLE, check=False)
    if state.get("tun_planned") and json_command("ip", "-j", "link", "show", "dev", tun):
        run("ip", "tuntap", "del", "dev", tun, "mode", "tun")
        if json_command("ip", "-j", "link", "show", "dev", tun):
            raise RuntimeError("Stop the CVPN daemon before removing its TUN interface")
    if kind == "server":
        if state.get("forwarding_planned"):
            wan = interface(state["wan"])
            Path(f"/proc/sys/net/ipv4/conf/{wan}/forwarding").write_text(state["wan_forwarding_before"] + "\n")
        if state.get("firewall_planned"):
            for family, table in (("ip", NAT_TABLE), ("inet", SERVER_TABLE)):
                if nft_exists(family, table):
                    run("nft", "delete", "table", family, table)
    elif state.get("firewall_planned") and nft_exists("inet", CLIENT_TABLE):
        # Release the kill switch only after DNS/routes/TUN cleanup succeeded.
        run("nft", "delete", "table", "inet", CLIENT_TABLE)
    (directory / "state.json").unlink()
    directory.rmdir()
    print(f"Removed CVPN {kind} configuration.")
