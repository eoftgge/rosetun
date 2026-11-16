#!/usr/bin/env python3
"""Copy an already provisioned lab test image, remove the legacy IPv4 probe route and, with --sshd, install
sshd offline so that it listens only on the peer's side of the test machine; with --ipv6-router, make the lab's
link-local address the IPv6 default router of the test machine; with --deps-debs, install offline what the rosetun
package needs for the L5 image, which stays quiet and has no rosetun in it."""

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
# Stage 8b, the L5 test image: run-l5.sh installs the real package with `dpkg -i`, which fetches nothing, so what the
# package needs is installed here, offline, from the owner's .deb files. The names are those of the `Depends:` that
# installer/linux/build-deb.sh writes (`build-artifacts.sh --deb` builds both packages with it): its fixed ones and
# GUI_LIBRARIES, then desktop-file-utils, one of its `Recommends:`, which `install.desktop` of run-l5.sh needs for the
# desktop database. The shared libraries `dpkg-shlibdeps` adds are known only from a built package:
# `--check-package` reads them from it. The rosetun package itself is never in the image.
L5_DEPENDS = ('nftables', 'systemd', 'init-system-helpers', 'libegl1', 'libgl1', 'libwayland-client0',
              'libwayland-egl1', 'libx11-6', 'libx11-xcb1', 'libxcb1', 'libxcursor1', 'libxi6', 'libxkbcommon-x11-0',
              'libxkbcommon0', 'libxrender1', 'desktop-file-utils')
# The quiet image of contract v5: a unit that a dependency enables (a link in a `.wants`, `.requires` or `.upholds`
# folder) could reach the network by itself, so any is refused unless it is named here. None is, so far.
L5_ALLOWED_UNITS = ()
ENABLING_FOLDERS = ('.wants', '.requires', '.upholds')
# Runs inside the image like INSTALL_SCRIPT; `dpkg --audit` prints any package left half-installed.
DEPS_INSTALL_SCRIPT = f'''set -eu
export PATH=/usr/sbin:/usr/bin:/sbin:/bin DEBIAN_FRONTEND=noninteractive
[ ! -e /usr/sbin/policy-rc.d ]
trap 'rm -f /usr/sbin/policy-rc.d' EXIT
printf '#!/bin/sh\\nexit 101\\n' >/usr/sbin/policy-rc.d
chmod 0755 /usr/sbin/policy-rc.d
dpkg -i {DEB_STAGING}/*.deb
[ -z "$(dpkg --audit)" ]
rm -rf {DEB_STAGING}
'''
DPKG_STATUS = '/var/lib/dpkg/status'
# The bound of the control member a .deb is read for, and of the package database read back from the image.
CONTROL_LIMIT = 1024 * 1024
STATUS_LIMIT = 64 * 1024 * 1024
RELATION = re.compile(r'\s*([a-z0-9][a-z0-9+.-]+)(?::[a-z0-9-]+)?\s*'
                      r'(?:\(\s*(<<|<=|=|>=|>>|<|>)\s*([0-9][^)\s]*)\s*\))?\s*')
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


def image_descriptor(destination, debs=None, ipv6_router=None, l5=None):
    """The descriptor of the new image; the fields of [image] and, with sshd, the IPv6 router or the L5 dependencies,
    what was changed."""
    descriptor = dict(schema='rosetun.matrix.image.v1', identifier=destination.stem,
                      guest_os='linux', architecture='x86_64', path=str(destination),
                      size_bytes=destination.stat().st_size, sha256=digest(destination),
                      format='qcow2', profile='bios-i440fx-v1')
    if debs is not None:
        descriptor['sshd'] = dict(listen=SSHD_LISTEN, socket=SOCKET_UNIT, debs=debs)
    if ipv6_router is not None:
        descriptor['ipv6_router'] = ipv6_router
    if l5 is not None:
        descriptor['l5_dependencies'] = l5
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


def deps_debs(directory):
    """The dependencies of the L5 image: only regular .deb files, none of them the rosetun package, hashed."""
    debs = []
    for path in sorted(directory.iterdir(), key=lambda path: path.name):
        if path.is_symlink() or not path.is_file() or not DEB_NAME.fullmatch(path.name):
            raise ValueError(f'deps-debs: unexpected entry {path.name!r}')
        if path.name.split('_', 1)[0] == 'rosetun':
            raise ValueError('deps-debs: the rosetun package is never installed in the image')
        debs.append(dict(name=path.name, sha256=digest(path), size_bytes=path.stat().st_size))
    if not debs:
        raise ValueError('deps-debs: no package')
    return debs


def _order(character):
    """The weight of one character of a non-digit part of a Debian version, as dpkg orders them."""
    if character is None or character.isdigit():
        return 0
    if character == '~':
        return -1
    return ord(character) if character.isalpha() else ord(character) + 256


def _compare_part(a, b):
    """dpkg's comparison of two upstream versions or two revisions: negative, zero or positive."""
    i = j = 0
    while i < len(a) or j < len(b):
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            left, right = _order(a[i] if i < len(a) else None), _order(b[j] if j < len(b) else None)
            if left != right:
                return left - right
            i, j = i + 1, j + 1
        start_a, start_b = i, j
        while i < len(a) and a[i].isdigit():
            i += 1
        while j < len(b) and b[j].isdigit():
            j += 1
        left, right = int(a[start_a:i] or 0), int(b[start_b:j] or 0)
        if left != right:
            return left - right
    return 0


def compare_versions(a, b):
    """Compare two Debian versions ([epoch:]upstream[-revision]) as `dpkg --compare-versions` does."""
    def split(version):
        epoch, _, rest = version.partition(':') if ':' in version else ('0', '', version)
        upstream, _, revision = rest.rpartition('-') if '-' in rest else (rest, '', '')
        return int(epoch), upstream, revision
    (epoch_a, upstream_a, revision_a), (epoch_b, upstream_b, revision_b) = split(a), split(b)
    if epoch_a != epoch_b:
        return epoch_a - epoch_b
    return _compare_part(upstream_a, upstream_b) or _compare_part(revision_a, revision_b)


def relations(text):
    """A Depends field as a list of groups of alternatives, each (name, operator, version) or (name, None, None)."""
    groups = []
    for group in text.split(','):
        alternatives = []
        for alternative in group.split('|'):
            match = RELATION.fullmatch(alternative)
            if not match:
                raise ValueError(f'check-package: cannot read the relation {alternative.strip()!r}')
            alternatives.append(match.groups())
        groups.append(alternatives)
    return groups


def holds(installed, operator, wanted):
    if operator is None:
        return True
    order = compare_versions(installed, wanted)
    return {'<<': order < 0, '<=': order <= 0, '<': order <= 0, '=': order == 0, '>=': order >= 0,
            '>': order >= 0, '>>': order > 0}[operator]


def stanzas(text):
    """The paragraphs of a Debian control file or the dpkg database: a dict of fields each, continuations joined."""
    rows, fields, last = [], {}, None
    for line in text.splitlines():
        if not line.strip():
            if fields:
                rows.append(fields)
            fields, last = {}, None
        elif line[0] in ' \t':
            if last is None:
                raise ValueError('a continuation line without a field')
            fields[last] += '\n' + line.strip()
        else:
            name, separator, value = line.partition(':')
            if not separator:
                raise ValueError(f'a line without a field: {line!r}')
            last = name.strip()
            fields[last] = value.strip()
    if fields:
        rows.append(fields)
    return rows


def package_control(path):
    """The control paragraph of a .deb, read from its ar archive with the standard library; nothing is unpacked."""
    import io
    import tarfile
    with path.open('rb') as stream:
        if stream.read(8) != b'!<arch>\n':
            raise ValueError(f'check-package: {path.name} is not a Debian package')
        while True:
            header = stream.read(60)
            if len(header) != 60 or header[58:60] != b'`\n':
                raise ValueError(f'check-package: {path.name} has no control member')
            name, size = header[:16].decode('ascii').strip().rstrip('/'), int(header[48:58].decode('ascii'))
            if name.startswith('control.tar'):
                if size > CONTROL_LIMIT:
                    raise ValueError(f'check-package: the control member of {path.name} is too large')
                with tarfile.open(fileobj=io.BytesIO(stream.read(size)), mode='r:*') as archive:
                    for member in archive.getmembers():
                        if member.name in ('control', './control') and member.isfile():
                            paragraphs = stanzas(archive.extractfile(member).read().decode('utf-8'))
                            if len(paragraphs) != 1:
                                raise ValueError(f'check-package: the control file of {path.name} is not one paragraph')
                            return paragraphs[0]
                raise ValueError(f'check-package: the control member of {path.name} has no control file')
            stream.seek(size + size % 2, 1)


def installed_packages(status):
    """From the dpkg database: name -> version of every installed package, and name -> provided versions."""
    installed, provided = {}, {}
    for fields in stanzas(status):
        if fields.get('Status') != 'install ok installed':
            continue
        installed[fields['Package']] = fields['Version']
        for alternatives in relations(fields['Provides']) if fields.get('Provides') else ():
            for name, operator, version in alternatives:
                provided.setdefault(name, []).append(version if operator == '=' else None)
    return installed, provided


def unmet(depends, installed, provided):
    """The groups of a Depends field that nothing installed satisfies, as written in the field."""
    missing = []
    for alternatives in relations(depends):
        def satisfied(name, operator, version):
            if name in installed and holds(installed[name], operator, version):
                return True
            return any(operator is None or (given is not None and holds(given, operator, version))
                       for given in provided.get(name, ()))
        if not any(satisfied(*alternative) for alternative in alternatives):
            missing.append(' | '.join(name + (f' ({operator} {version})' if operator else '')
                                      for name, operator, version in alternatives))
    return missing


def check_dependencies(status, packages=()):
    """Refuse an image without every package of L5_DEPENDS or what a checked package depends on, or with rosetun.

    `packages` are (name of the file, control paragraph) of the packages the owner built for the run.
    """
    installed, provided = installed_packages(status)
    if 'rosetun' in installed:
        raise ValueError('deps: the rosetun package is installed in the image')
    absent = [name for name in L5_DEPENDS if name not in installed]
    if absent:
        raise ValueError(f"deps: not installed: {', '.join(absent)}")
    checked = []
    for file_name, control in packages:
        depends = ', '.join(control[field] for field in ('Pre-Depends', 'Depends') if control.get(field))
        missing = unmet(depends, installed, provided) if depends else []
        if missing:
            raise ValueError(f"deps: {file_name} needs what the image does not have: {', '.join(missing)}")
        checked.append(dict(file=file_name, package=control.get('Package'), version=control.get('Version'),
                            depends=depends))
    return dict(installed={name: installed[name] for name in L5_DEPENDS}, checked_packages=checked)


def unit_links(root):
    """Every link in a copy of /etc/systemd/system (etc) and /usr/lib/systemd/system (lib): (directory, folder, name,
    target), where folder is the path below the unit directory ('.' for the directory itself)."""
    links = set()
    for directory in UNIT_DIRECTORIES:
        base = root / directory
        for path in base.rglob('*'):
            if path.is_symlink():
                relative = path.relative_to(base)
                links.add((directory, relative.parent.as_posix(), relative.name, os.readlink(path)))
    return links


def check_quiet(before, after, allowed=L5_ALLOWED_UNITS):
    """Refuse an image whose dependencies enabled a unit that is not allowed or took a mask away.

    `before` and `after` are unit_links of the image before and after the installation.
    """
    added = sorted(after - before)
    enabled = [link for link in added if link[1].endswith(ENABLING_FOLDERS) and link[3] != '/dev/null']
    refused = [f'{name} in {directory}/{folder}' for directory, folder, name, _ in enabled if name not in allowed]
    if refused:
        raise ValueError(f"quiet: the dependencies enabled {', '.join(refused)}; only {list(allowed)} may be")
    masks = {link for link in before if link[1] == '.' and link[3] == '/dev/null'}
    if masks - after:
        raise ValueError(f"quiet: a mask is gone: {', '.join(sorted(name for _, _, name, _ in masks - after))}")
    return dict(enabled=['/'.join(link[:3]) for link in enabled],
                other_links=['/'.join(link[:3]) for link in added if link not in enabled])


def read_units(image):
    """The unit links of the image, read from copies of its two unit directories."""
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        copy_units(image, root, [])
        return unit_links(root)


def copy_units(image, root, commands):
    """Copy /etc/systemd/system to root/etc and /usr/lib/systemd/system to root/lib in one read-only session with
    `commands` after them; what those print."""
    for directory in UNIT_DIRECTORIES:
        (root / directory).mkdir()
    output = guestfish(image, ['copy-out', '/etc/systemd/system', str(root / 'etc')],
                       ['copy-out', '/usr/lib/systemd/system', str(root / 'lib')], *commands)
    for directory in UNIT_DIRECTORIES:
        # copy-out puts the directory itself, `system`, under the target.
        (root / directory / 'system').rename(root / (directory + '.copy'))
        (root / directory).rmdir()
        (root / (directory + '.copy')).rename(root / directory)
    return output


def install_deps(image, directory, debs):
    with tempfile.TemporaryDirectory() as temp:
        script = Path(temp) / 'install.sh'
        script.write_text(DEPS_INSTALL_SCRIPT, encoding='utf-8', newline='\n')
        guestfish(image, ['mkdir-p', DEB_STAGING],
                  *(['upload', str(directory / deb['name']), f"{DEB_STAGING}/{deb['name']}"] for deb in debs),
                  ['upload', str(script), '/root/rosetun-lab-deps.sh'], ['sh', 'sh /root/rosetun-lab-deps.sh'],
                  ['rm', '/root/rosetun-lab-deps.sh'], writable=True)


def read_l5(image, before, packages):
    """Check the installed image by reading it: the dependencies, the quiet units, no leftover of the installation."""
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        status = root / 'status'
        output = copy_units(image, root, [['download', DPKG_STATUS, str(status)],
                                          ['exists', '/usr/sbin/policy-rc.d'], ['exists', DEB_STAGING],
                                          ['exists', '/root/rosetun-lab-deps.sh']])
        lines = output.splitlines()
        if len(lines) < 3 or not set(lines[-3:]) <= {'true', 'false'}:
            raise ValueError('deps: unexpected guestfish output')
        if 'true' in lines[-3:]:
            raise ValueError('deps: the installation left policy-rc.d, its packages or its script in the image')
        if status.stat().st_size > STATUS_LIMIT:
            raise ValueError('deps: the package database is too large')
        result = check_dependencies(status.read_text(encoding='utf-8'), packages)
        result['units'] = check_quiet(before, unit_links(root))
        return result


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
    parser.add_argument('--deps-debs', type=Path, metavar='DIR',
                        help='the L5 image: what the rosetun package needs, as Debian 13 .deb files; nothing is '
                             'downloaded and the package itself is not installed')
    parser.add_argument('--check-package', type=Path, action='append', default=[], metavar='DEB',
                        help='with --deps-debs: a rosetun package of the run, whose Depends must all be installed; '
                             'only its control file is read')
    args = parser.parse_args(argv)
    if args.sshd and args.sshd_debs is None:
        parser.error('--sshd needs --sshd-debs DIR')
    if args.sshd_debs is not None and not args.sshd:
        parser.error('--sshd-debs is only for --sshd')
    # The L5 image is one of its own: no sshd and no IPv6 router, which L5 does not use.
    if args.deps_debs is not None and (args.sshd or args.ipv6_router):
        parser.error('--deps-debs goes neither with --sshd nor with --ipv6-router')
    if args.check_package and args.deps_debs is None:
        parser.error('--check-package is only for --deps-debs')
    return args


def main(argv=None):
    args = arguments(argv)
    source = args.source.resolve(strict=True)
    destination = args.destination.resolve()
    if destination.exists() or args.descriptor.exists():
        raise ValueError('destination and descriptor must be new files')
    debs = sshd_debs(args.sshd_debs.resolve(strict=True)) if args.sshd else None
    deps = deps_debs(args.deps_debs.resolve(strict=True)) if args.deps_debs is not None else None
    # Read before the image is touched, so that a package that cannot be read stops nothing half-done.
    packages = [(path.name, package_control(path.resolve(strict=True))) for path in args.check_package]
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
        l5 = None
        if deps is not None:
            units = read_units(destination)
            install_deps(destination, args.deps_debs.resolve(strict=True), deps)
            if deps_debs(args.deps_debs.resolve(strict=True)) != deps:
                raise ValueError('deps-debs changed during the installation')
            l5 = dict(debs=deps, **read_l5(destination, units, packages))
    except BaseException:
        # A half-prepared copy is never left to be taken for a prepared one.
        destination.unlink()
        raise
    if digest(source) != before:
        raise ValueError('source image changed')
    descriptor = image_descriptor(destination, debs, ipv6_router, l5)
    with args.descriptor.open('x', encoding='utf-8') as stream:
        json.dump(descriptor, stream, indent=2)
        stream.write('\n')
    print(json.dumps(dict(source_sha256=before, network_before=original, network_after=updated, sshd=sshd,
                          ipv6_router=ipv6_router, l5_dependencies=l5, image=descriptor), indent=2))


if __name__ == '__main__':
    main()
