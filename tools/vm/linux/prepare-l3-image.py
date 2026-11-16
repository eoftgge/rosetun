#!/usr/bin/env python3
"""Copy an already provisioned lab test image, remove the legacy IPv4 probe route and, with --sshd, install
sshd offline so that it listens only on the peer's side of the test machine; with --ipv6-router, make the lab's
link-local address the IPv6 default router of the test machine."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

NETWORK = '/etc/systemd/network/00-rosetun-lab.network'
# `inbound.reply` of run-l3.sh reads the banner of sshd on PEER_HOST_ADDRESS, the guest's end of the veth to the
# peer namespace. That address exists only while the scenario runs, hence FreeBind; it is never on the lab wire.
SSHD_LISTEN = '198.51.100.1:22'
# The packaged ssh.socket of Debian 13 (Accept=no) hands its socket to the daemon of ssh.service, so the image
# uses units of its own: a socket that accepts each connection and hands it to `sshd -i`, which binds nothing.
# Not named rosetun*: preflight.no-foreign-service of run-l3.sh refuses any unit with that prefix.
SOCKET_UNIT = 'l3-lab-sshd.socket'
SERVICE_UNIT = 'l3-lab-sshd@.service'
SOCKET_TEXT = f"""[Unit]
Description=sshd of the Rosetun L3 lab, for the peer namespace only
Before=sockets.target

[Socket]
ListenStream={SSHD_LISTEN}
FreeBind=yes
Accept=yes

[Install]
WantedBy=sockets.target
"""
# The [Service] lines of the packaged sshd@.service.
SERVICE_TEXT = """[Unit]
Description=sshd of the Rosetun L3 lab, one connection
After=nss-user-lookup.target auditd.service

[Service]
EnvironmentFile=-/etc/default/ssh
ExecStart=-/usr/sbin/sshd -i $SSHD_OPTS
StandardInput=socket
RuntimeDirectory=sshd
RuntimeDirectoryPreserve=yes
RuntimeDirectoryMode=0755
"""
# The packaged units that could start sshd: masked, so neither a dependency nor a socket starts them.
MASKED_UNITS = ('ssh.socket', 'ssh.service', 'sshd.service')
# Not read by `sshd -i`; a second bound should someone start the daemon after unmasking it.
SSHD_CONFIG = '/etc/ssh/sshd_config.d/rosetun-lab.conf'
SSHD_CONFIG_TEXT = f'ListenAddress {SSHD_LISTEN}\n'
DEB_STAGING = '/var/cache/rosetun-lab-debs'
DEB_NAME = re.compile(r'[a-z0-9][a-z0-9.+-]*_[A-Za-z0-9.+~:%-]+_(amd64|all)\.deb')
# Runs inside the image (guestfish `sh`, a chroot with /dev, /proc and /sys bound). policy-rc.d keeps the
# maintainer scripts from starting anything; nothing here reaches a network.
INSTALL_SCRIPT = f'''set -eu
export PATH=/usr/sbin:/usr/bin:/sbin:/bin DEBIAN_FRONTEND=noninteractive
[ ! -e /usr/sbin/policy-rc.d ]
trap 'rm -f /usr/sbin/policy-rc.d' EXIT
printf '#!/bin/sh\\nexit 101\\n' >/usr/sbin/policy-rc.d
chmod 0755 /usr/sbin/policy-rc.d
dpkg -i {DEB_STAGING}/*.deb
ssh-keygen -A
systemctl disable ssh.socket ssh.service
systemctl mask {' '.join(MASKED_UNITS)}
systemctl enable {SOCKET_UNIT}
rm -rf {DEB_STAGING}
'''
UNIT_DIRECTORIES = ('etc', 'lib')
# Contract v6b: `ipv6.neighbor` of run-l3.sh needs an IPv6 default router on the physical interface. It is the lab's
# link-local address, the modified EUI-64 of its MAC 00:00:5e:00:53:62, which answers in an L3 run. The test machine
# accepts no router advertisement and gets no address beyond those it has; its own link-local address is the EUI-64
# of its MAC, the one the observer's allowance for the echo names.
IPV6_ROUTER = 'fe80::200:5eff:fe00:5362'
IPV6_NETWORK = (('LinkLocalAddressing', 'ipv6'), ('IPv6LinkLocalAddressGenerationMode', 'eui64'),
                ('IPv6AcceptRA', 'no'))
IPV6_ROUTE = {'Destination': '::/0', 'Gateway': IPV6_ROUTER}


def sections_of(text):
    """The sections of a .network file as (raw text, header, [(key, value)]), comments left out."""
    rows = []
    for section in re.split(r'(?=^\[)', text, flags=re.MULTILINE):
        lines = [line.strip() for line in section.splitlines()
                 if line.strip() and not line.lstrip().startswith(('#', ';'))]
        header = lines[0] if lines and lines[0].startswith('[') else None
        fields = [tuple(part.strip() for part in line.split('=', 1)) for line in lines[1 if header else 0:]
                  if '=' in line]
        rows.append((section, header, fields))
    return rows


def ipv6_gateway(value):
    """An IPv6 address, or the gateway a router advertisement names."""
    return ':' in value or value == '_ipv6ra'


def ipv6_router_route(values):
    """A [Route] that makes an IPv6 default route or goes through a link-local or advertised gateway.

    The routes of contract v6a to the lab's IPv6 target network through its global address are not one.
    """
    gateway = values.get('Gateway', '')
    return (values.get('Destination') == '::/0' or gateway == '_ipv6ra' or gateway.lower().startswith('fe80:')
            or (ipv6_gateway(gateway) and 'Destination' not in values))


def check_no_ipv6_router(rows):
    for _, header, fields in rows:
        if header == '[Route]' and ipv6_router_route(dict(fields)):
            raise ValueError('the network file has an IPv6 default or link-local route already')
        if header == '[Network]' and any(key == 'Gateway' and ipv6_gateway(value) for key, value in fields):
            raise ValueError('the network file has an IPv6 gateway already')


def with_ipv6_router(text):
    """The network file with the settings of contract v6b in its one [Network] section and the IPv6 default route.

    A setting the file already has with another value, a second [Network] section or an IPv6 route through a
    gateway is refused rather than overridden: the owner looks at the file.
    """
    rows = sections_of(text)
    check_no_ipv6_router(rows)
    network = [index for index, (_, header, _) in enumerate(rows) if header == '[Network]']
    if len(network) != 1:
        raise ValueError('expected one [Network] section')
    raw, _, fields = rows[network[0]]
    added = ''
    for key, wanted in IPV6_NETWORK:
        values = [value for name, value in fields if name == key]
        if any(value != wanted for value in values):
            raise ValueError(f'[Network] {key}={values[-1]} conflicts with {key}={wanted}')
        if not values:
            added += f'{key}={wanted}\n'
    sections = [section for section, _, _ in rows]
    body = raw.rstrip('\n') + '\n'
    tail = raw[len(raw.rstrip('\n')):][1:]
    sections[network[0]] = body + added + tail
    joined = ''.join(sections)
    route = '[Route]\n' + ''.join(f'{key}={value}\n' for key, value in IPV6_ROUTE.items())
    return joined + ('' if joined.endswith('\n\n') or not joined else '\n' if joined.endswith('\n') else '\n\n') + route


def check_ipv6_router(before, after):
    """Refuse a network file read back from the image unless it is `before` with exactly what v6b adds.

    One [Network] section with each setting of IPV6_NETWORK once and with its value, the same addresses as
    `before`, exactly one IPv6 default or link-local route (IPV6_ROUTE) and every section of `before` kept.
    """
    rows, old = sections_of(after), sections_of(before)
    networks = [fields for _, header, fields in rows if header == '[Network]']
    if len(networks) != 1:
        raise ValueError('ipv6-router: expected one [Network] section')
    for key, wanted in IPV6_NETWORK:
        if [value for name, value in networks[0] if name == key] != [wanted]:
            raise ValueError(f'ipv6-router: [Network] does not set {key}={wanted} once')
    addresses = sorted(value for _, header, fields in old if header == '[Network]' for key, value in fields
                       if key == 'Address')
    if sorted(value for key, value in networks[0] if key == 'Address') != addresses:
        raise ValueError('ipv6-router: the addresses changed')
    routes = [dict(fields) for _, header, fields in rows if header == '[Route]' and ipv6_router_route(dict(fields))]
    if routes != [IPV6_ROUTE]:
        raise ValueError(f'ipv6-router: the IPv6 default and link-local routes are {routes}')
    if any(key == 'Gateway' and ipv6_gateway(value) for key, value in networks[0]):
        raise ValueError('ipv6-router: [Network] names an IPv6 gateway')
    kept = [fields for _, header, fields in rows]
    for _, header, fields in old:
        if header != '[Network]' and fields not in kept:
            raise ValueError(f'ipv6-router: a section {header} of the source is gone')
    return dict(gateway=IPV6_ROUTER, network=dict(IPV6_NETWORK))


def network_for_l3(text):
    sections = re.split(r'(?=^\[)', text, flags=re.MULTILINE)
    kept = []
    defaults = 0
    for section in sections:
        lines = [line.strip() for line in section.splitlines()
                 if line.strip() and not line.lstrip().startswith(('#', ';'))]
        if lines and lines[0] == '[Route]':
            fields = dict(line.split('=', 1) for line in lines[1:])
            if fields.get('Destination') == '203.0.113.0/24':
                if fields != {'Destination': '203.0.113.0/24', 'Gateway': '192.0.2.1'}:
                    raise ValueError('unexpected legacy probe route')
                continue
            if fields.get('Destination') == '0.0.0.0/0' and fields.get('Gateway') == '192.0.2.1':
                defaults += 1
        kept.append(section)
    if defaults != 1:
        raise ValueError('expected one IPv4 default route via the lab')
    return ''.join(kept)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def sshd_debs(directory):
    """The packages of the owner's directory: only regular .deb files, openssh-server among them, with their hashes."""
    entries = sorted(directory.iterdir(), key=lambda path: path.name)
    debs = []
    for path in entries:
        if path.is_symlink() or not path.is_file() or not DEB_NAME.fullmatch(path.name):
            raise ValueError(f'sshd-debs: unexpected entry {path.name!r}')
        debs.append(dict(name=path.name, sha256=digest(path), size_bytes=path.stat().st_size))
    if not any(deb['name'].startswith('openssh-server_') for deb in debs):
        raise ValueError('sshd-debs: no openssh-server package')
    return debs


def unit_settings(texts):
    """The [Socket] settings of a unit and its drop-ins, applied in order: an empty ListenStream= resets the list."""
    settings = dict(listen=[], other_listen=[], free_bind=None, accept=None)
    for text in texts:
        section = None
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith(('#', ';')):
                continue
            if line.startswith('['):
                section = line
                continue
            if section != '[Socket]' or '=' not in line:
                continue
            key, value = (part.strip() for part in line.split('=', 1))
            if key == 'ListenStream':
                settings['listen'] = settings['listen'] + [value] if value else []
            elif key.startswith('Listen'):
                settings['other_listen'].append(f'{key}={value}')
            elif key == 'FreeBind':
                settings['free_bind'] = value
            elif key == 'Accept':
                settings['accept'] = value
    return settings


def unit_texts(root, name, kind):
    """A unit as systemd would load it from a copy of /etc/systemd/system (etc) and /usr/lib/systemd/system (lib):
    the first file found, then every drop-in of `<name>.d` and `<kind>.d`, in the order of their names."""
    main = None
    for directory in UNIT_DIRECTORIES:
        path = root / directory / name
        # A link points into the image, not into this copy, so it is never followed.
        if path.is_symlink():
            raise ValueError(f'sshd: {name} is a link')
        if path.is_file():
            main = path
            break
    if main is None:
        raise ValueError(f'sshd: no {name}')
    dropins = {}
    for directory in reversed(UNIT_DIRECTORIES):
        for folder in (kind + '.d', name + '.d'):
            for path in sorted((root / directory / folder).glob('*.conf')):
                if path.is_symlink():
                    raise ValueError(f'sshd: the drop-in {path.name} of {name} is a link')
                dropins[path.name] = path
    return [main.read_text(encoding='utf-8')] + [dropins[key].read_text(encoding='utf-8') for key in sorted(dropins)]


def check_sshd(root, ssh_files, leftovers):
    """Refuse an image whose sshd could listen anywhere but SSHD_LISTEN or start on its own.

    `root` holds copies of /etc/systemd/system (etc) and /usr/lib/systemd/system (lib), `ssh_files` the names
    in /etc/ssh, `leftovers` whether the policy-rc.d or the package directory of the installation is still there.
    """
    etc = root / 'etc'
    for name in MASKED_UNITS:
        path = etc / name
        if not (path.is_symlink() and os.readlink(path) == '/dev/null'):
            raise ValueError(f'sshd: {name} is not masked')
    if not (etc / 'sockets.target.wants' / SOCKET_UNIT).is_symlink():
        raise ValueError(f'sshd: {SOCKET_UNIT} is not enabled')
    for folder in (*etc.glob('*.wants'), *etc.glob('*.requires')):
        for name in MASKED_UNITS:
            if (folder / name).is_symlink() or (folder / name).exists():
                raise ValueError(f'sshd: {name} is still linked in {folder.name}')
    settings = unit_settings(unit_texts(root, SOCKET_UNIT, 'socket'))
    if settings['listen'] != [SSHD_LISTEN] or settings['other_listen']:
        raise ValueError(f"sshd: {SOCKET_UNIT} listens on {settings['listen'] + settings['other_listen']}")
    if settings['free_bind'] != 'yes':
        raise ValueError(f'sshd: {SOCKET_UNIT} has no FreeBind=yes')
    # With Accept=yes systemd hands each connection to `sshd -i`; without it sshd would be a daemon that
    # binds its own sockets, and nothing here could vouch for where.
    if settings['accept'] != 'yes':
        raise ValueError(f'sshd: {SOCKET_UNIT} does not accept connections itself (Accept=yes)')
    if unit_texts(root, SERVICE_UNIT, 'service') != [SERVICE_TEXT]:
        raise ValueError(f'sshd: {SERVICE_UNIT} is not the one this tool writes, or has a drop-in')
    if not any(re.fullmatch(r'ssh_host_[a-z0-9]+_key', name) for name in ssh_files):
        raise ValueError('sshd: no host key')
    if any(leftovers):
        raise ValueError('sshd: the installation left policy-rc.d or its packages in the image')
    return settings


def image_descriptor(destination, debs=None, ipv6_router=None):
    """The descriptor of the new image; the fields of [image] and, with sshd or the IPv6 router, what was changed."""
    descriptor = dict(schema='rosetun.matrix.image.v1', identifier=destination.stem,
                      guest_os='linux', architecture='x86_64', path=str(destination),
                      size_bytes=destination.stat().st_size, sha256=digest(destination),
                      format='qcow2', profile='bios-i440fx-v1')
    if debs is not None:
        descriptor['sshd'] = dict(listen=SSHD_LISTEN, socket=SOCKET_UNIT, debs=debs)
    if ipv6_router is not None:
        descriptor['ipv6_router'] = ipv6_router
    return descriptor


def guestfish(image, *commands, writable=False):
    """One guestfish session for all the commands; a read-only one returns what they printed."""
    arguments = ['guestfish', '--rw' if writable else '--ro', '-a', str(image), '-i']
    for index, command in enumerate(commands):
        arguments += ([':'] if index else []) + list(command)
    # The maintainer scripts' output goes to stderr for the owner to read; stdout stays the JSON of main.
    return subprocess.run(arguments, check=True, stdout=sys.stderr if writable else subprocess.PIPE, text=True).stdout


def install_sshd(image, directory, debs):
    with tempfile.TemporaryDirectory() as temp:
        script, socket, service, config = (Path(temp) / name for name in ('install.sh', 'socket', 'service', 'conf'))
        for path, text in ((script, INSTALL_SCRIPT), (socket, SOCKET_TEXT), (service, SERVICE_TEXT),
                           (config, SSHD_CONFIG_TEXT)):
            path.write_text(text, encoding='utf-8', newline='\n')
        guestfish(image, ['mkdir-p', DEB_STAGING],
                  *(['upload', str(directory / deb['name']), f"{DEB_STAGING}/{deb['name']}"] for deb in debs),
                  ['upload', str(socket), '/etc/systemd/system/' + SOCKET_UNIT],
                  ['upload', str(service), '/etc/systemd/system/' + SERVICE_UNIT],
                  ['mkdir-p', SSHD_CONFIG.rsplit('/', 1)[0]], ['upload', str(config), SSHD_CONFIG],
                  ['upload', str(script), '/root/rosetun-lab-sshd.sh'], ['sh', 'sh /root/rosetun-lab-sshd.sh'],
                  ['rm', '/root/rosetun-lab-sshd.sh'], writable=True)


def read_sshd(image):
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        for directory in UNIT_DIRECTORIES:
            (root / directory).mkdir()
        output = guestfish(image, ['copy-out', '/etc/systemd/system', str(root / 'etc')],
                           ['copy-out', '/usr/lib/systemd/system', str(root / 'lib')], ['ls', '/etc/ssh'],
                           ['exists', '/usr/sbin/policy-rc.d'], ['exists', DEB_STAGING])
        for directory in UNIT_DIRECTORIES:
            # copy-out puts the directory itself, `system`, under the target.
            (root / directory / 'system').rename(root / (directory + '.copy'))
            (root / directory).rmdir()
            (root / (directory + '.copy')).rename(root / directory)
        lines = output.splitlines()
        if len(lines) < 2 or not set(lines[-2:]) <= {'true', 'false'}:
            raise ValueError('sshd: unexpected guestfish output')
        return check_sshd(root, lines[:-2], [line == 'true' for line in lines[-2:]])


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('destination', type=Path)
    parser.add_argument('--source-sha256', required=True)
    parser.add_argument('--descriptor', type=Path, required=True)
    parser.add_argument('--sshd', action='store_true', help='install sshd for inbound.reply (image contract v6)')
    parser.add_argument('--sshd-debs', type=Path, metavar='DIR',
                        help='openssh-server and its Debian 13 dependencies as .deb files; nothing is downloaded')
    parser.add_argument('--ipv6-router', action='store_true',
                        help="make the lab's link-local address the IPv6 default router (image contract v6b)")
    args = parser.parse_args(argv)
    if args.sshd and args.sshd_debs is None:
        parser.error('--sshd needs --sshd-debs DIR')
    if args.sshd_debs is not None and not args.sshd:
        parser.error('--sshd-debs is only for --sshd')
    return args


def main(argv=None):
    args = arguments(argv)
    source = args.source.resolve(strict=True)
    destination = args.destination.resolve()
    if destination.exists() or args.descriptor.exists():
        raise ValueError('destination and descriptor must be new files')
    debs = sshd_debs(args.sshd_debs.resolve(strict=True)) if args.sshd else None
    before = digest(source)
    if before != args.source_sha256:
        raise ValueError('source image hash mismatch')
    info = json.loads(subprocess.check_output(['qemu-img', 'info', '--output=json', str(source)]))
    if info['format'] != 'qcow2' or 'backing-filename' in info:
        raise ValueError('source must be a standalone qcow2 image')
    def read(image):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'network'
            subprocess.run(['guestfish', '--ro', '-a', str(image), '-i', 'download', NETWORK, str(target)],
                           check=True)
            return target.read_text(encoding='utf-8')
    original = read(source)
    prepared = network_for_l3(original)
    updated = with_ipv6_router(prepared) if args.ipv6_router else prepared
    with source.open('rb') as incoming, destination.open('xb') as outgoing:
        shutil.copyfileobj(incoming, outgoing, 1024 * 1024)
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', newline='\n') as temp:
            temp.write(updated)
            temp.flush()
            subprocess.run(['guestfish', '--rw', '-a', str(destination), '-i', 'upload', temp.name, NETWORK],
                           check=True)
        readback = read(destination)
        if readback != updated:
            raise ValueError('network readback mismatch')
        ipv6_router = check_ipv6_router(prepared, readback) if args.ipv6_router else None
        sshd = None
        if debs is not None:
            install_sshd(destination, args.sshd_debs.resolve(strict=True), debs)
            if sshd_debs(args.sshd_debs.resolve(strict=True)) != debs:
                raise ValueError('sshd-debs changed during the installation')
            sshd = read_sshd(destination)
    except BaseException:
        # A half-prepared copy is never left to be taken for a prepared one.
        destination.unlink()
        raise
    if digest(source) != before:
        raise ValueError('source image changed')
    descriptor = image_descriptor(destination, debs, ipv6_router)
    with args.descriptor.open('x', encoding='utf-8') as stream:
        json.dump(descriptor, stream, indent=2)
        stream.write('\n')
    print(json.dumps(dict(source_sha256=before, network_before=original, network_after=updated, sshd=sshd,
                          ipv6_router=ipv6_router, image=descriptor), indent=2))


if __name__ == '__main__':
    main()
