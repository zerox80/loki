"""Laptop routes, DNS and fail-closed firewall."""

import shutil

from .common import (CLIENT, CLIENT_TABLE, PRIORITY, TABLE, OUTER_RESERVE,
    check_uplink_mtu, interface, json_command, make_tun, nft_exists, prepare_state, run, save)

def client_up(args):
    if nft_exists("inet", CLIENT_TABLE):
        raise RuntimeError("CVPN client firewall already exists")
    rules = json_command("ip", "-j", "-4", "rule", "show")
    if any(rule.get("priority") == PRIORITY for rule in rules):
        raise RuntimeError(f"Policy priority {PRIORITY} is already in use")
    if json_command("ip", "-j", "-4", "route", "show", "table", str(TABLE)):
        raise RuntimeError(f"Routing table {TABLE} is already in use")
    route = json_command("ip", "-j", "-4", "route", "get", args.endpoint)
    if len(route) != 1 or "dev" not in route[0]:
        raise RuntimeError("No usable uplink route to the server")
    uplink = interface(route[0]["dev"])
    if uplink == "lo" or uplink == args.tun:
        raise RuntimeError("The endpoint must be reachable through the physical uplink")
    check_uplink_mtu(uplink, args.mtu)
    if args.dns_mode == "resolved" and not shutil.which("resolvectl"):
        raise RuntimeError("resolvectl is required for DNS mode 'resolved'")
    if args.dns_mode == "resolved":
        run("resolvectl", "status")
    directory, state = prepare_state(args, "client")
    state.update(endpoint=args.endpoint, port=args.port, uplink=uplink,
                 routes_planned=False, dns_planned=False)
    state["firewall_planned"] = True
    save(directory, state)
    ruleset = f'''table inet {CLIENT_TABLE} {{
  chain output {{
    type filter hook output priority -200; policy drop;
    oifname "lo" accept
    meta skuid {args.owner} ip daddr {args.endpoint} udp dport {args.port} oifname "{uplink}" accept
    meta nfproto ipv4 oifname "{args.tun}" accept
  }}
}}\n'''
    run("nft", "-f", "-", data=ruleset)
    make_tun(args, CLIENT, directory, state)
    state["routes_planned"] = True
    save(directory, state)
    endpoint_route = ["ip", "-4", "route", "add", "table", str(TABLE), f"{args.endpoint}/32"]
    if route[0].get("gateway"):
        endpoint_route += ["via", route[0]["gateway"], "dev", uplink, "onlink"]
    else:
        endpoint_route += ["dev", uplink, "scope", "link"]
    run(*endpoint_route)
    run("ip", "-4", "route", "add", "table", TABLE, "default", "dev", args.tun, "src", CLIENT)
    run("ip", "-4", "rule", "add", "priority", PRIORITY, "lookup", TABLE)
    if args.dns_mode == "resolved":
        state["dns_planned"] = True
        save(directory, state)
        run("resolvectl", "dns", args.tun, args.dns)
        run("resolvectl", "domain", args.tun, "~.")
        run("resolvectl", "default-route", args.tun, "yes")
    save(directory, state)
    print(f"Client prepared on {args.tun}; kill switch is active, including IPv6 blocking.")
    print(f"MTU: inner={args.mtu}, outer budget={args.mtu + OUTER_RESERVE} (reserve {OUTER_RESERVE}).")
    if args.dns_mode == "manual":
        print("DNS mode is manual: configure a resolver reachable through the tunnel.")
    print(f"State: {directory}. The firewall remains active when the daemon exits.")
