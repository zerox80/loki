"""Server TUN, restricted forwarding and IPv4 NAT."""

from pathlib import Path

from .common import (CLIENT, SERVER, SERVER_TABLE, NAT_TABLE, OUTER_RESERVE,
    check_uplink_mtu, json_command, make_tun, nft_exists, prepare_state, run, save)

def server_up(args):
    if not json_command("ip", "-j", "link", "show", "dev", args.wan):
        raise RuntimeError(f"WAN interface does not exist: {args.wan}")
    check_uplink_mtu(args.wan, args.mtu)
    if nft_exists("inet", SERVER_TABLE) or nft_exists("ip", NAT_TABLE):
        raise RuntimeError("CVPN server firewall/NAT tables already exist")
    directory, state = prepare_state(args, "server")
    state.update(wan=args.wan,
                 wan_forwarding_before=Path(f"/proc/sys/net/ipv4/conf/{args.wan}/forwarding").read_text().strip(),
                 forwarding_planned=False)
    make_tun(args, SERVER, directory, state)
    state["firewall_planned"] = True
    save(directory, state)
    ruleset = f'''table inet {SERVER_TABLE} {{
  chain input {{
    type filter hook input priority -10; policy accept;
    iifname "{args.wan}" udp dport {args.port} accept
  }}
  chain forward {{
    type filter hook forward priority -10; policy accept;
    iifname "{args.tun}" ip saddr {CLIENT} oifname "{args.wan}" accept
    iifname "{args.wan}" oifname "{args.tun}" ip daddr {CLIENT} ct state established,related accept
    iifname "{args.tun}" drop
    oifname "{args.tun}" drop
  }}
}}
table ip {NAT_TABLE} {{
  chain postrouting {{
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr {CLIENT} oifname "{args.wan}" masquerade
  }}
}}\n'''
    run("nft", "-f", "-", data=ruleset)
    state["forwarding_planned"] = True
    save(directory, state)
    # Global ip_forward toggles can reset unrelated Linux IPv4 settings.
    # Enable forwarding only on the two interfaces used by this tunnel.
    Path(f"/proc/sys/net/ipv4/conf/{args.tun}/forwarding").write_text("1\n")
    Path(f"/proc/sys/net/ipv4/conf/{args.wan}/forwarding").write_text("1\n")
    print(f"Server prepared on {args.tun}, WAN {args.wan}, UDP port {args.port}.")
    print(f"MTU: inner={args.mtu}, outer budget={args.mtu + OUTER_RESERVE} (reserve {OUTER_RESERVE}).")
    print("Existing host/cloud firewall policies must also allow that UDP port and tunnel forwarding.")
