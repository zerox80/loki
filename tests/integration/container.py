#!/usr/bin/env python3
"""Smoke-test the Compose image with disposable keys, TUNs and a native client.

This checks authentication, device access and runtime confinement. The separate
namespace integration test covers packet forwarding, NAT, PMTU and outages.
"""

import argparse
import ipaddress
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]


def run(*args, check=True):
    return subprocess.run(list(map(str, args)), check=check, text=True, capture_output=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'build/loki')
    parser.add_argument('--image', default='loki-vpn:local')
    parser.add_argument('--uid', type=int, default=1000)
    parser.add_argument('--gid', type=int, default=1000)
    parser.add_argument('--port', type=int, default=14433)
    args = parser.parse_args()
    if os.geteuid() != 0 or args.uid <= 0 or args.gid < 0 or not 1 <= args.port <= 65535:
        parser.error('Run as root with a non-root daemon UID and valid GID/UDP port')
    test_net = ipaddress.IPv4Network('10.254.253.0/30')
    for link in json.loads(run('ip', '-j', '-4', 'addr', 'show').stdout):
        for addr in link.get('addr_info', []):
            if ipaddress.IPv4Network(f"{addr['local']}/{addr['prefixlen']}", strict=False).overlaps(test_net):
                parser.error('The disposable test subnet 10.254.253.0/30 is already in use')
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(('127.0.0.1', args.port))

    project = f'loki-smoke-{os.getpid()}'
    created = []
    client = None
    with tempfile.TemporaryDirectory(prefix=project + '-') as temporary:
        directory = Path(temporary)
        os.chown(directory, args.uid, args.gid)
        pki, server_keys = directory / 'pki', directory / 'server-keys'
        run(sys.executable, ROOT / 'tools/keygen.py', pki)
        os.chown(pki, args.uid, args.gid)
        for path in pki.iterdir():
            os.chown(path, args.uid, args.gid)
        server_keys.mkdir(mode=0o700)
        os.chown(server_keys, args.uid, args.gid)
        for name in ('server.pem', 'server.key', 'ca.pem'):
            target = server_keys / name
            shutil.copyfile(pki / name, target)
            target.chmod(0o600)
            os.chown(target, args.uid, args.gid)
        server_tun, client_tun = f'lkis{os.getpid()}', f'lkic{os.getpid()}'
        env_file = directory / 'compose.env'
        env_file.write_text('\n'.join((
            'LOKI_WAN_IFACE=lo', f'LOKI_KEYS_DIR={server_keys}',
            f'LOKI_UID={args.uid}', f'LOKI_GID={args.gid}', f'LOKI_PORT={args.port}',
            f'LOKI_TUN={server_tun}', 'LOKI_MTU=1280', 'LOKI_BIND_ADDRESS=127.0.0.1',
            'LOKI_LOCAL_IP=10.254.253.1', 'LOKI_PEER_IP=10.254.253.2',
            f'LOKI_IMAGE={args.image}', 'LOKI_PEER_NAME=client.cvpn')) + '\n')
        env_file.chmod(0o600)
        compose = ['docker', 'compose', '--project-directory', str(ROOT),
                   '--env-file', str(env_file), '--project-name', project,
                   '-f', str(ROOT / 'compose.yaml')]
        try:
            for name, address in ((server_tun, '10.254.253.1'), (client_tun, '10.254.253.2')):
                run('ip', 'tuntap', 'add', 'dev', name, 'mode', 'tun', 'user', args.uid)
                created.append(name)
                run('ip', 'addr', 'add', f'{address}/32', 'dev', name)
                run('ip', 'link', 'set', 'dev', name, 'mtu', 1280, 'up')
            run(*compose, 'up', '-d', '--no-build', 'server')
            with (directory / 'client.log').open('w') as log:
                client = subprocess.Popen(list(map(str, [
                    'setpriv', '--reuid', args.uid, '--regid', args.gid, '--clear-groups',
                    '--bounding-set=-all', '--inh-caps=-all', '--ambient-caps=-all',
                    args.binary.resolve(), 'client', '--endpoint', '127.0.0.1',
                    '--port', args.port, '--tun', client_tun, '--mtu', 1280,
                    '--local-ip', '10.254.253.2', '--peer-ip', '10.254.253.1',
                    '--cert', pki / 'client.pem', '--key', pki / 'client.key',
                    '--ca', pki / 'ca.pem', '--peer-name', 'server.cvpn'])), stdout=log, stderr=log)
                for _ in range(150):
                    server_log = run(*compose, 'logs', '--no-color', 'server').stdout
                    client_log = (directory / 'client.log').read_text()
                    if 'Tunnel ready.' in client_log and 'Tunnel ready.' in server_log:
                        break
                    if client.poll() is not None:
                        raise RuntimeError('Native client exited: ' + client_log + server_log)
                    time.sleep(0.2)
                else:
                    raise RuntimeError('Handshake timed out: ' + client_log + server_log)
                container_id = run(*compose, 'ps', '-q', 'server').stdout.strip()
                info = json.loads(run('docker', 'inspect', container_id).stdout)[0]
                status = (Path('/proc') / str(info['State']['Pid']) / 'status').read_text()
                fields = dict(line.split(':', 1) for line in status.splitlines() if ':' in line)
                assert info['Config']['User'] == f'{args.uid}:{args.gid}'
                assert 'ALL' in info['HostConfig']['CapDrop']
                assert info['HostConfig']['ReadonlyRootfs']
                assert info['HostConfig']['NetworkMode'] == 'host'
                assert info['HostConfig']['UsernsMode'] == 'host'
                assert int(fields['CapEff'].strip(), 16) == 0
                assert fields['NoNewPrivs'].strip() == '1'
                assert info['State']['Running'] and client.poll() is None
                print('PASS: Compose image authenticates both peers, opens an owned TUN without '
                      'capabilities, runs as non-root with read-only rootfs and no-new-privileges.')
        finally:
            if client is not None and client.poll() is None:
                client.terminate()
                try:
                    client.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    client.kill()
                    client.wait()
            run(*compose, 'down', check=False)
            for name in reversed(created):
                run('ip', 'tuntap', 'del', 'dev', name, 'mode', 'tun', check=False)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
