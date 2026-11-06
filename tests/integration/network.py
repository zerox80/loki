#!/usr/bin/env python3
"""Exercise the real C daemons in disposable Linux network namespaces."""

import argparse
from collections import Counter
import errno
import http.server
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
MARKER = b"CVPN-INTEGRATION-PLAINTEXT-SHOULD-STAY-IN-THE-TUNNEL-"
BODY = MARKER * 4096
# Linux UAPI values from linux/in.h. Python does not expose all of these
# socket-option names consistently across versions/builds.
IP_MTU_DISCOVER = 10
IP_RECVERR = 11
IP_MTU = 14
IP_PMTUDISC_DONT = 0
IP_PMTUDISC_DO = 2


def run(*arguments, check=True, timeout=10):
    return subprocess.run(list(map(str, arguments)), check=check, timeout=timeout,
                          capture_output=True, text=True)


class Lab:
    def __init__(self, directory, binary):
        self.directory = directory
        self.binary = binary
        self.keepers = []
        self.daemons = []
        self.logs = {}
        self.http_peers = []
        self.http_mss = []
        self.udp_seen = Counter()
        self.capture = []
        self.lock = threading.Lock()
        self.stopping = threading.Event()
        self.http = None
        self.udp = None
        self.raw = None

    def namespace(self):
        process = subprocess.Popen(
            ["unshare", "--net", sys.executable, "-u", "-c",
             "import signal; print('ready', flush=True); signal.pause()"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.keepers.append(process)
        if process.stdout.readline().strip() != "ready":
            raise RuntimeError("Nested namespace failed: " + process.stderr.read())
        return process.pid

    @staticmethod
    def ns(pid, *arguments, **kwargs):
        return run("nsenter", f"--net=/proc/{pid}/ns/net", "--", *arguments, **kwargs)

    def topology(self):
        self.client = self.namespace()
        self.server = self.namespace()
        run("ip", "link", "set", "lo", "up")
        run("ip", "addr", "add", "203.0.113.10/32", "dev", "lo")
        run("ip", "link", "add", "brlab", "type", "bridge")
        run("ip", "addr", "add", "198.18.0.1/24", "dev", "brlab")
        run("ip", "-6", "addr", "add", "fd42:203::1/64", "dev", "brlab", "nodad")
        run("ip", "link", "set", "brlab", "up")
        for suffix, pid, number in (("c", self.client, 3), ("s", self.server, 2)):
            run("ip", "link", "add", f"v_{suffix}", "type", "veth", "peer", "name", f"eth_{suffix}")
            run("ip", "link", "set", f"eth_{suffix}", "netns", pid)
            run("ip", "link", "set", f"v_{suffix}", "master", "brlab")
            run("ip", "link", "set", f"v_{suffix}", "up")
            self.ns(pid, "ip", "link", "set", "lo", "up")
            self.ns(pid, "ip", "addr", "add", f"198.18.0.{number}/24", "dev", f"eth_{suffix}")
            self.ns(pid, "ip", "-6", "addr", "add", f"fd42:203::{number}/64", "dev", f"eth_{suffix}", "nodad")
            self.ns(pid, "ip", "link", "set", f"eth_{suffix}", "up")
            self.ns(pid, "ip", "route", "add", "default", "via", "198.18.0.1")

    def services(self):
        lab = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                lab.http_peers.append(self.client_address[0])
                lab.http_mss.append(self.connection.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG))
                self.send_response(200)
                self.send_header("Content-Length", str(len(BODY)))
                self.end_headers()
                try:
                    self.wfile.write(BODY)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def log_message(self, *args):
                pass

        self.http = http.server.ThreadingHTTPServer(("203.0.113.10", 8080), Handler)
        threading.Thread(target=self.http.serve_forever, daemon=True).start()
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("203.0.113.10", 9090))
        self.udp.settimeout(0.2)

        def echo():
            while not self.stopping.is_set():
                try:
                    data, peer = self.udp.recvfrom(65535)
                    with self.lock:
                        self.udp_seen[data] += 1
                    self.udp.sendto(data, peer)
                except socket.timeout:
                    pass
                except OSError:
                    break

        threading.Thread(target=echo, daemon=True).start()
        # ETH_P_ALL sees frames consumed by the bridge receive handler before
        # IPv4 protocol dispatch; ETH_P_IP would miss this bridged traffic.
        self.raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        self.raw.bind(("v_c", 0))
        self.raw.settimeout(0.2)

        def capture():
            while not self.stopping.is_set():
                try:
                    packet = self.raw.recv(65535)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if len(packet) < 42 or packet[12:14] != b"\x08\x00" or packet[14] >> 4 != 4 or packet[23] != 17:
                    continue
                offset = 14 + (packet[14] & 15) * 4
                client_ip = socket.inet_aton("198.18.0.3")
                server_ip = socket.inet_aton("198.18.0.2")
                to_server = (packet[26:30] == client_ip and packet[30:34] == server_ip and
                             packet[offset + 2:offset + 4] == struct.pack("!H", 4433))
                to_client = (packet[26:30] == server_ip and packet[30:34] == client_ip and
                             packet[offset:offset + 2] == struct.pack("!H", 4433))
                if not (to_server or to_client):
                    continue
                total = struct.unpack("!H", packet[16:18])[0]
                with self.lock:
                    self.capture.append((packet[:14 + total], offset))

        threading.Thread(target=capture, daemon=True).start()

    def helper(self, pid, command, *arguments, check=True):
        kind = command.split("-")[0]
        return self.ns(pid, sys.executable, ROOT / "tools/network.py", command,
                       "--state-dir", self.directory / f"{kind}-state", *arguments, check=check)

    def start(self, role, *, peer_name=None, ca=None, seconds=1800, mtu=1280):
        pid = self.server if role == "server" else self.client
        log = self.directory / f"{role}-{len(self.daemons)}.log"
        credentials = self.directory / "pki"
        arguments = [self.binary, role, "--endpoint", "0.0.0.0" if role == "server" else "198.18.0.2",
                     "--tun", "cvpn0", "--cert", credentials / f"{role}.pem",
                     "--key", credentials / f"{role}.key", "--ca", ca or credentials / "ca.pem",
                     "--peer-name", peer_name or ("client.cvpn" if role == "server" else "server.cvpn"),
                     "--session-seconds", str(seconds), "--mtu", str(mtu)]
        with log.open("w") as stream:
            # The daemon must work with no capabilities after the helper has
            # created an owned, persistent TUN device.
            process = subprocess.Popen(
                list(map(str, ["nsenter", f"--net=/proc/{pid}/ns/net", "--", "setpriv",
                               "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all",
                               *arguments])), stdout=stream, stderr=stream)
        self.daemons.append(process)
        self.logs[process.pid] = log
        return process

    def text(self, process):
        return self.logs[process.pid].read_text(errors="replace")

    def wait(self, process, message, timeout=20, count=1):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.text(process).count(message) >= count:
                return
            if process.poll() is not None:
                raise RuntimeError(f"Daemon exited ({process.returncode}): {self.text(process)}")
            time.sleep(0.05)
        raise RuntimeError(f"Timed out waiting for {message!r}: {self.text(process)}")

    @staticmethod
    def stop(process):
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)

    def fetch(self, *, succeeds=True):
        result = self.ns(self.client, "curl", "--noproxy", "*", "--silent", "--show-error",
                         "--max-time", "3", "http://203.0.113.10:8080/", check=False, timeout=5)
        if succeeds:
            if result.returncode or result.stdout.encode() != BODY:
                raise RuntimeError("HTTP transfer failed: " + result.stderr)
        elif result.returncode == 0:
            raise RuntimeError("Traffic escaped while the VPN was unavailable")

    def echo(self, marker):
        script = ("import socket,sys; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); "
                  "s.settimeout(3); m=sys.argv[1].encode(); "
                  "s.sendto(m,('203.0.113.10',9090)); assert s.recvfrom(65535)[0]==m")
        self.ns(self.client, sys.executable, "-c", script, marker.decode(), timeout=5)

    def pmtu_to_sender(self):
        """Real remote UDP replies exercise DF=0 and DF=1 across server NAT."""
        client_code = (
            "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); "
            "s.settimeout(5); s.sendto(b'first',('203.0.113.10',9091)); "
            "assert s.recvfrom(65535)[0]==b'N'*1253; "
            "s.sendto(b'df-probe',('203.0.113.10',9091)); "
            "assert s.recvfrom(65535)[0]==b'S'*1252"
        )
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as remote:
            remote.bind(("203.0.113.10", 9091))
            remote.settimeout(5)
            remote.setsockopt(socket.IPPROTO_IP, IP_RECVERR, 1)
            remote.setsockopt(socket.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DONT)
            process = subprocess.Popen(
                ["nsenter", f"--net=/proc/{self.client}/ns/net", "--", sys.executable, "-c", client_code],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                message, peer = remote.recvfrom(65535)
                if message != b"first" or peer[0] != "198.18.0.2":
                    raise RuntimeError("PMTU probe did not pass server NAT")
                remote.connect(peer)
                if remote.getsockopt(socket.IPPROTO_IP, IP_MTU) < 1281:
                    raise RuntimeError("PMTU baseline would fragment on the sender")
                # 1253 + 8 UDP + 20 IPv4 = 1281: one byte above the TUN MTU.
                # Without DF the server may fragment; the laptop reassembles.
                remote.send(b"N" * 1253)
                if remote.recv(65535) != b"df-probe":
                    raise RuntimeError("The client did not receive/reassemble the non-DF reply")
                remote.setsockopt(socket.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO)
                remote.send(b"X" * 1253)
                deadline = time.monotonic() + 4
                error = None
                while time.monotonic() < deadline and error is None:
                    try:
                        _, ancillary, _, _ = remote.recvmsg(4096, 1024, socket.MSG_ERRQUEUE | socket.MSG_DONTWAIT)
                    except (BlockingIOError, socket.timeout):
                        time.sleep(0.02)
                        continue
                    for level, kind, data in ancillary:
                        if level == socket.IPPROTO_IP and kind == IP_RECVERR:
                            error = struct.unpack("=IBBBBII", data[:16])
                # errno, origin=ICMP, type=Destination Unreachable,
                # code=Fragmentation Needed, pad, next-hop MTU, extra data.
                if error is None or error[:4] != (errno.EMSGSIZE, 2, 3, 4) or error[5] != 1280:
                    raise RuntimeError(f"Missing ICMP Fragmentation Needed, MTU 1280: {error}")
                if remote.getsockopt(socket.IPPROTO_IP, IP_MTU) != 1280:
                    raise RuntimeError("The sender did not learn PMTU 1280")
                remote.send(b"S" * 1252)
                _, errors = process.communicate(timeout=5)
                if process.returncode:
                    raise RuntimeError("The smaller DF reply was not delivered: " + errors)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=3)

    def pmtu_from_client(self):
        """A smaller Internet route must return ICMP through the encrypted VPN."""
        client_code = r'''
import errno, socket, struct, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
s.setsockopt(socket.IPPROTO_IP, 11, 1)
s.setsockopt(socket.IPPROTO_IP, 10, 2)
s.connect(('203.0.113.10', 9092))
s.send(b'baseline')
s.send(b'X' * 1252)
deadline = time.monotonic() + 4
error = None
while time.monotonic() < deadline and error is None:
    try:
        _, ancillary, _, _ = s.recvmsg(4096, 1024, socket.MSG_ERRQUEUE | socket.MSG_DONTWAIT)
    except (BlockingIOError, socket.timeout):
        time.sleep(0.02)
        continue
    for level, kind, data in ancillary:
        if level == socket.IPPROTO_IP and kind == 11:
            error = struct.unpack('=IBBBBII', data[:16])
assert error and error[:4] == (errno.EMSGSIZE, 2, 3, 4) and error[5] == 1200, error
assert s.getsockopt(socket.IPPROTO_IP, 14) == 1200
s.send(b'S' * 1172)
assert s.recv(65535) == b'ok'
'''
        route = ("203.0.113.10/32", "via", "198.18.0.1", "dev", "eth_s", "mtu", "1200")
        self.ns(self.server, "ip", "route", "add", *route)
        process = None
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as remote:
                remote.bind(("203.0.113.10", 9092))
                remote.settimeout(6)
                process = subprocess.Popen(
                    ["nsenter", f"--net=/proc/{self.client}/ns/net", "--", sys.executable, "-c", client_code],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                first, peer = remote.recvfrom(65535)
                if first != b"baseline" or peer[0] != "198.18.0.2":
                    raise RuntimeError("Outbound PMTU baseline did not use server NAT")
                smaller, smaller_peer = remote.recvfrom(65535)
                if smaller != b"S" * 1172 or smaller_peer != peer:
                    raise RuntimeError("Oversized packet passed or the smaller client packet was lost")
                remote.sendto(b"ok", peer)
                _, errors = process.communicate(timeout=5)
                if process.returncode:
                    raise RuntimeError("Client did not learn PMTU through the tunnel: " + errors)
        finally:
            if process and process.poll() is None:
                process.kill()
                process.communicate(timeout=3)
            self.ns(self.server, "ip", "route", "del", "203.0.113.10/32")

    def replay_and_tamper(self):
        def complete_udp_checksum(packet, offset):
            # Packet capture on veth can expose CHECKSUM_PARTIAL frames. Raw
            # reinjection must contain a complete checksum for both exact
            # replays and forgeries to reach DTLS rather than die in UDP.
            packet = bytearray(packet)
            packet[offset + 6:offset + 8] = b"\0\0"
            udp = bytes(packet[offset:])
            pseudo = bytes(packet[26:34]) + b"\0\x11" + struct.pack("!H", len(udp))
            data = pseudo + udp
            if len(data) & 1:
                data += b"\0"
            checksum = sum(struct.unpack(f"!{len(data) // 2}H", data))
            while checksum >> 16:
                checksum = (checksum & 0xFFFF) + (checksum >> 16)
            checksum = (~checksum) & 0xFFFF
            packet[offset + 6:offset + 8] = struct.pack("!H", checksum or 0xFFFF)
            return packet

        marker = b"cvpn-unique-replay-sentinel-abcdef0123456789"
        with self.lock:
            initial = len(self.capture)
        self.echo(marker)
        time.sleep(0.2)
        with self.lock:
            packets = list(self.capture[initial:])
        packets = [(p, o) for p, o in packets if p[o + 8] == 23 and
                   p[26:30] == socket.inet_aton("198.18.0.3") and
                   len(p) - o - 8 == 37 + 8 + 28 + len(marker)]
        if not packets:
            raise RuntimeError("No encrypted application datagrams captured")
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as injector:
            injector.bind(("v_s", 0))
            for packet, offset in packets:
                replay = complete_udp_checksum(packet, offset)
                injector.send(replay)
                injector.send(replay)
            packet, offset = packets[-1]
            corrupt = bytearray(packet)
            sequence_offset = offset + 8 + 5
            sequence = int.from_bytes(corrupt[sequence_offset:sequence_offset + 6], "big")
            corrupt[sequence_offset:sequence_offset + 6] = (sequence + 4096).to_bytes(6, "big")
            corrupt[-1] ^= 0x40
            # Keep UDP valid so the packet reaches DTLS authentication. A high,
            # unused record number also tests that invalid tags do not advance
            # the replay window and discard later legitimate records.
            injector.send(complete_udp_checksum(corrupt, offset))
        time.sleep(0.3)
        with self.lock:
            if self.udp_seen[marker] != 1:
                raise RuntimeError("Replayed or forged data reached the plaintext service")
        self.echo(b"cvpn-legitimate-message-after-forged-high-sequence")

    def close(self):
        for process in reversed(self.daemons):
            self.stop(process)
        self.stopping.set()
        if self.http:
            self.http.shutdown()
            self.http.server_close()
        for resource in (self.raw, self.udp):
            if resource:
                resource.close()
        for process in reversed(self.keepers):
            self.stop(process)


def exercise(directory, binary):
    lab = Lab(directory, binary)
    try:
        lab.topology()
        lab.services()
        lab.ns(lab.server, sys.executable, "-c",
               "from pathlib import Path; Path('/proc/sys/net/ipv4/ip_forward').write_text('0\\n')")
        run(sys.executable, ROOT / "tools/keygen.py", directory / "pki")
        run(sys.executable, ROOT / "tools/keygen.py", directory / "wrong-pki")
        lab.fetch()
        if lab.http_peers[-1] != "198.18.0.3":
            raise RuntimeError("Direct baseline route is incorrect")
        lab.ns(lab.client, "ping", "-6", "-c", "1", "-W", "1", "fd42:203::1")
        lab.ns(lab.server, "ip", "link", "set", "dev", "eth_s", "mtu", "1360")
        lab.ns(lab.client, "ip", "link", "set", "dev", "eth_c", "mtu", "1359")
        rejected = lab.helper(lab.client, "client-up", "--endpoint", "198.18.0.2", "--owner", "0",
                              "--dns-mode", "manual", "--mtu", "1280", check=False)
        if rejected.returncode == 0 or "at least 1360" not in rejected.stderr or (directory / "client-state").exists():
            raise RuntimeError("An undersized uplink was not rejected before setup")
        lab.ns(lab.client, "ip", "link", "set", "dev", "eth_c", "mtu", "1360")
        lab.helper(lab.server, "server-up", "--wan", "eth_s", "--owner", "0", "--mtu", "1280")
        if lab.ns(lab.server, "cat", "/proc/sys/net/ipv4/ip_forward").stdout.strip() != "0":
            raise RuntimeError("Server setup changed global IPv4 forwarding")
        lab.helper(lab.client, "client-up", "--endpoint", "198.18.0.2", "--owner", "0",
                   "--dns-mode", "manual", "--mtu", "1280")
        for pid in (lab.client, lab.server):
            link = lab.ns(pid, "ip", "-j", "link", "show", "dev", "cvpn0").stdout
            if '"mtu":1280' not in link.replace(" ", ""):
                raise RuntimeError("TUN interface did not retain inner MTU 1280")
        lab.fetch(succeeds=False)
        ipv6 = lab.ns(lab.client, "ping", "-6", "-c", "1", "-W", "1", "fd42:203::1", check=False)
        if ipv6.returncode == 0:
            raise RuntimeError("IPv6 escaped the kill switch")
        print("PASS: direct connectivity baseline; fail-closed IPv4 and IPv6 before connection.", flush=True)

        server = lab.start("server")
        lab.wait(server, "Listening for an authenticated peer")
        client = lab.start("client", peer_name="wrong-server.cvpn")
        lab.wait(client, "Peer certificate rejected: hostname mismatch", timeout=5)
        if "Tunnel ready" in lab.text(client) or "Tunnel ready" in lab.text(server):
            raise RuntimeError("Wrong server identity was accepted")
        lab.stop(client)
        lab.stop(server)
        server = lab.start("server", peer_name="wrong-client.cvpn")
        lab.wait(server, "Listening for an authenticated peer")
        client = lab.start("client")
        lab.wait(server, "Peer certificate rejected: hostname mismatch", timeout=5)
        if "Tunnel ready" in lab.text(server):
            raise RuntimeError("Wrong client identity was accepted")
        lab.stop(client)
        lab.stop(server)
        server = lab.start("server")
        lab.wait(server, "Listening for an authenticated peer")
        client = lab.start("client", ca=directory / "wrong-pki/ca.pem")
        lab.wait(client, "Peer certificate rejected:", timeout=5)
        if "Tunnel ready" in lab.text(client):
            raise RuntimeError("Untrusted certificate was accepted")
        lab.stop(client)
        lab.stop(server)
        print("PASS: wrong server SAN, wrong client SAN, and an untrusted CA are rejected.", flush=True)

        for pid, interface in ((lab.client, "eth_c"), (lab.server, "eth_s")):
            lab.ns(pid, "ip", "link", "set", "dev", interface, "mtu", "1500")
        client = lab.start("client", mtu=1400)
        client.wait(timeout=3)
        if client.returncode == 0 or "TUN MTU must match --mtu 1400" not in lab.text(client):
            raise RuntimeError("TUN/configuration MTU mismatch was accepted")
        lab.ns(lab.client, "ip", "link", "set", "dev", "cvpn0", "mtu", "1400")
        server = lab.start("server")
        lab.wait(server, "Listening for an authenticated peer")
        client = lab.start("client", mtu=1400)
        lab.wait(server, "Peer tunnel configuration mismatch")
        if "Tunnel ready" in lab.text(server) or "Tunnel ready" in lab.text(client):
            raise RuntimeError("Peer MTU mismatch was accepted")
        lab.stop(client)
        lab.stop(server)
        lab.ns(lab.server, "ip", "link", "set", "dev", "cvpn0", "mtu", "1400")
        server = lab.start("server", mtu=1400)
        lab.wait(server, "Listening for an authenticated peer")
        client = lab.start("client", mtu=1400)
        lab.wait(server, "Tunnel ready")
        lab.wait(client, "Tunnel ready")
        lab.fetch()
        if lab.http_mss[-1] > 1360:
            raise RuntimeError("The remote TCP sender did not respect the client's MTU 1400")
        lab.stop(client)
        lab.stop(server)
        for pid in (lab.client, lab.server):
            lab.ns(pid, "ip", "link", "set", "dev", "cvpn0", "mtu", "1280")
        print("PASS: MTU input 1280 -> outer budget 1360; undersized uplink and mismatches rejected; custom MTU 1400 works.", flush=True)

        for pid, interface in ((lab.client, "eth_c"), (lab.server, "eth_s")):
            lab.ns(pid, "ip", "link", "set", "dev", interface, "mtu", "1360")
        with lab.lock:
            lab.capture.clear()

        server = lab.start("server")
        lab.wait(server, "Listening for an authenticated peer")
        client = lab.start("client")
        lab.wait(server, "Tunnel ready")
        lab.wait(client, "Tunnel ready")
        lab.fetch()
        if lab.http_peers[-1] != "198.18.0.2":
            raise RuntimeError("Traffic did not exit through server NAT")
        if lab.http_mss[-1] > 1240:
            raise RuntimeError("The remote TCP sender did not respect the client's MTU 1280")
        lab.ns(lab.client, "ping", "-4", "-c", "2", "-W", "1", "10.203.0.1")
        lab.ns(lab.client, "ping", "-4", "-M", "do", "-s", "1252", "-c", "1", "-W", "1", "203.0.113.10")
        too_large = lab.ns(lab.client, "ping", "-4", "-M", "do", "-s", "1253", "-c", "1", "-W", "1",
                           "203.0.113.10", check=False)
        if too_large.returncode == 0:
            raise RuntimeError("The local TUN accepted an oversized DF packet")
        lab.replay_and_tamper()
        lab.pmtu_to_sender()
        lab.pmtu_from_client()
        with lab.lock:
            if not any(packet[26:30] == socket.inet_aton("198.18.0.2") for packet, _ in lab.capture):
                raise RuntimeError("No server-to-client outer traffic captured")
            if any(MARKER in packet for packet, _ in lab.capture):
                raise RuntimeError("Plaintext marker visible in outer UDP traffic")
            if any(len(packet) - 14 > 1360 for packet, _ in lab.capture):
                raise RuntimeError("Outer datagram exceeded the 1360-byte budget")
            for packet, _ in lab.capture:
                flags = struct.unpack("!H", packet[20:22])[0]
                if not flags & 0x4000 or flags & 0x3FFF:
                    raise RuntimeError("Outer IP packet has DF clear or is a fragment")
            if not any(len(packet) - 14 == 1353 for packet, _ in lab.capture):
                raise RuntimeError("No 1280-byte inner packet in a 1353-byte outer packet observed")
        print("PASS: daemons without capabilities; encrypted HTTP/UDP/ICMP, MTU boundary, server NAT.", flush=True)
        print("PASS: real datagram replay and valid-UDP-checksum ciphertext forgery are rejected.", flush=True)
        print("PASS: outer DF is set, no outer IP fragments; sender receives ICMP type 3/code 4, learns MTU 1280 and delivers a smaller reply; inner non-DF reassembly works.", flush=True)
        print("PASS: Client -> Internet PMTU: ICMP type 3/code 4 crosses the encrypted tunnel, client learns path MTU 1200 and a smaller packet reaches the Internet peer.", flush=True)

        lab.stop(server)
        lab.fetch(succeeds=False)
        server = lab.start("server")
        lab.wait(client, "Tunnel ready", timeout=30, count=2)
        lab.wait(server, "Tunnel ready", timeout=30)
        lab.fetch()
        print("PASS: server outage stays fail-closed; the client reconnects after restart.", flush=True)

        lab.stop(client)
        lab.stop(server)
        server = lab.start("server", seconds=5)
        lab.wait(server, "Listening for an authenticated peer")
        client = lab.start("client", seconds=5)
        lab.wait(client, "Tunnel ready")
        lab.wait(server, "Tunnel ready")
        lab.wait(client, "Authenticated", timeout=25, count=2)
        lab.wait(client, "Tunnel ready", timeout=10, count=2)
        lab.fetch()
        print("PASS: session limit triggers a fresh handshake and traffic recovers.", flush=True)

        lab.stop(client)
        lab.stop(server)
        lab.helper(lab.client, "client-down")
        lab.helper(lab.server, "server-down")
        if lab.ns(lab.server, "cat", "/proc/sys/net/ipv4/conf/eth_s/forwarding").stdout.strip() != "0":
            raise RuntimeError("Server cleanup did not restore WAN forwarding")
        lab.fetch()
        if lab.http_peers[-1] != "198.18.0.3":
            raise RuntimeError("Cleanup did not restore the original route")
        print("PASS: explicit cleanup restores the original network configuration.", flush=True)
    except Exception:
        for path in sorted(directory.glob("*.log")):
            print(f"\n{path.name}:\n{path.read_text(errors='replace')[-8000:]}", file=sys.stderr)
        raise
    finally:
        lab.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "build/loki")
    parser.add_argument("--work-dir", type=Path, default=ROOT / "work")
    parser.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if not args.inside:
        environment = os.environ.copy()
        environment["CVPN_TEST_PARENT_NET"] = os.readlink("/proc/self/ns/net")
        result = subprocess.run(["unshare", "--user", "--map-root-user", "--net", sys.executable,
                                 str(Path(__file__).resolve()), "--inside", "--binary", str(args.binary.resolve()),
                                 "--work-dir", str(args.work_dir.resolve())], env=environment)
        return result.returncode
    parent_namespace = os.environ.get("CVPN_TEST_PARENT_NET")
    if not parent_namespace or os.readlink("/proc/self/ns/net") == parent_namespace:
        raise RuntimeError("Refusing to run outside a disposable network namespace")
    args.work_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="cvpn-integration-", dir=args.work_dir) as directory:
        exercise(Path(directory), args.binary.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
