#!/usr/bin/env python3
"""Build/run the Compose server and prepare its host networking."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

from cvpn_network.common import (MTU_MIN, MTU_MAX, SERVER, check_uplink_mtu,
                                  interface, json_command, nft_exists)

ROOT = Path(__file__).resolve().parents[1]
STATE = Path('/run/cvpn-server/state.json')


def compose(env_file, *arguments, capture=False):
    # Compose itself resolves .env and interpolation; never execute .env as code.
    return subprocess.run(['docker', 'compose', '--project-directory', str(ROOT),
                           '--env-file', str(env_file), '-f', str(ROOT / 'compose.yaml'),
                           *arguments], check=True, text=True,
                          stdout=subprocess.PIPE if capture else None)


def configuration(env_file):
    model = json.loads(compose(env_file, 'config', '--format', 'json', capture=True).stdout)
    service = model['services']['server']
    command = service['command']
    if command[0] != 'server' or len(command) % 2 != 1:
        raise RuntimeError('Expected server command with option/value pairs')
    options = dict(zip(command[1::2], command[2::2]))
    if options.get('--local-ip') != SERVER or options.get('--peer-ip') != '10.203.0.2':
        raise RuntimeError('The host helper requires server 10.203.0.1 and client 10.203.0.2')
    owner, group = map(int, service['user'].split(':'))
    mtu, port = int(options['--mtu']), int(options['--port'])
    if owner <= 0 or group < 0 or not MTU_MIN <= mtu <= MTU_MAX or not 1 <= port <= 65535:
        raise RuntimeError('Use a non-root UID, valid GID/port and inner MTU 1280..9000')
    return {'tun': interface(options['--tun']), 'mtu': mtu, 'port': port, 'owner': owner,
            'wan': interface(model['x-loki-host']['wan_iface'])}, service


def check_keys(service, owner):
    volumes = [v for v in service['volumes'] if v['target'] == '/run/cvpn/keys']
    if len(volumes) != 1 or volumes[0]['type'] != 'bind' or not volumes[0]['read_only']:
        raise RuntimeError('The server credential directory must be a read-only bind mount')
    directory = Path(volumes[0]['source'])
    if not directory.is_dir():
        raise RuntimeError(f'Server credential directory does not exist: {directory}')
    # Only these three files belong on the server; CA/client private keys stay offline/on the laptop.
    unexpected = {p.name for p in directory.iterdir()} - {'server.pem', 'server.key', 'ca.pem'}
    if unexpected:
        raise RuntimeError('Server credential directory must contain only server.pem, server.key and ca.pem')
    for name in ('server.pem', 'server.key', 'ca.pem'):
        target = directory / name
        if target.is_symlink() or not target.is_file():
            raise RuntimeError(f'Missing regular credential file: {target}')
        info = target.stat()
        if info.st_uid != owner or info.st_mode & 0o077 or not info.st_mode & 0o400:
            raise RuntimeError(f'{target} must be owned by UID {owner}, readable by it, with mode 0600')


def prepare(settings, service):
    check_keys(service, settings['owner'])
    check_uplink_mtu(settings['wan'], settings['mtu'])
    if STATE.exists():
        state = json.loads(STATE.read_text())
        expected = {'version': 1, 'kind': 'server', 'outer_mtu': settings['mtu'] + 80,
                    **{key: settings[key] for key in ('tun', 'mtu', 'wan')}}
        # Old native deployments did not record port/owner. Check the TUN owner below.
        if any(state.get(key) != value for key, value in expected.items()):
            raise RuntimeError('Existing server network differs; stop it and run server-down first')
        if state.get('port', 4433) != settings['port'] or state.get('owner', settings['owner']) != settings['owner']:
            raise RuntimeError('Existing server port/owner differs from the Compose configuration')
        links = json_command('ip', '-j', '-d', 'link', 'show', 'dev', settings['tun'])
        addresses = json_command('ip', '-j', '-4', 'addr', 'show', 'dev', settings['tun'])
        owner_file = Path('/sys/class/net') / settings['tun'] / 'owner'
        owner = int(owner_file.read_text()) if owner_file.exists() else None
        correct_address = any(a.get('local') == SERVER and a.get('prefixlen') == 30
                              for link in addresses for a in link.get('addr_info', []))
        if (not links or links[0]['mtu'] != settings['mtu'] or owner != settings['owner']
                or not correct_address or not nft_exists('inet', 'cvpn_server')
                or not nft_exists('ip', 'cvpn_nat')):
            raise RuntimeError('Existing server network is incomplete or has a different TUN owner')
        print('Reusing matching host TUN, forwarding and NAT.', flush=True)
        return
    subprocess.run([sys.executable, str(ROOT / 'tools/network.py'), 'server-up',
                    '--wan', settings['wan'], '--tun', settings['tun'],
                    '--mtu', str(settings['mtu']), '--port', str(settings['port']),
                    '--owner', str(settings['owner'])], check=True)


def network_down():
    if STATE.exists():
        subprocess.run([sys.executable, str(ROOT / 'tools/network.py'), 'server-down'], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--env-file', type=Path, default=ROOT / '.env')
    parser.add_argument('command', choices=('build', 'up', 'prepare', 'down', 'network-down', 'status', 'logs'))
    parser.add_argument('--no-build', action='store_true', help='Use an already-built image for up')
    args = parser.parse_args()
    env_file = args.env_file.resolve()
    if args.command in ('up', 'prepare', 'down', 'network-down') and os.geteuid() != 0:
        parser.error('Host networking requires root; run this helper through sudo')
    try:
        if args.command == 'network-down':
            network_down()
        elif args.command == 'down':
            compose(env_file, 'down')
            network_down()
        elif args.command == 'build':
            configuration(env_file)
            compose(env_file, 'build', 'server')
        elif args.command in ('up', 'prepare'):
            settings, service = configuration(env_file)
            check_keys(service, settings['owner'])
            if args.command == 'up' and not args.no_build:
                compose(env_file, 'build', 'server')
            prepare(settings, service)
            if args.command == 'up':
                compose(env_file, 'up', '-d', '--no-build', 'server')
                print('Container started. Check authenticated tunnel readiness with: docker compose logs server')
        elif args.command == 'status':
            compose(env_file, 'ps')
        else:
            compose(env_file, 'logs', '--tail', '100', 'server')
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f'LOKI Compose: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
