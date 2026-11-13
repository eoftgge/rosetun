#!/usr/bin/python3
"""Owner-installed root entry point. Never executes delivered code."""

import base64
import subprocess
import ctypes
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys
import uuid

ROOT = Path('/root/rosetun-l2-stage')
INSTALLED = Path('/usr/local/libexec/rosetun-l2/stage-l2')


def require(condition):
    if not condition:
        raise ValueError('unsafe or invalid L2 import')


def trusted(path, *, directory=False, private=False):
    info = path.lstat()
    require((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            and info.st_uid == 0 and not info.st_mode & (0o077 if private else 0o022))
    if not directory:
        require(info.st_nlink == 1)
    return info


def parents(path):
    for parent in reversed((path, *path.parents)):
        trusted(parent, directory=True)


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_new(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        os.fchown(stream.fileno(), 0, 0)
        os.fchmod(stream.fileno(), 0o600)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def publish(source, target):
    # Linux renameat2(RENAME_NOREPLACE) atomically refuses even an empty destination.
    libc = ctypes.CDLL(None, use_errno=True)
    rename = libc.renameat2
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    if rename(-100, os.fsencode(source), -100, os.fsencode(target), 1):
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))


def boot_id():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def vm_uuid():
    return Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower()


BINARIES = ('l2_transport_fixture', 'rosetun_helper_privileged_tests', 'rosetun_ipc_tests')
CONTENT = ('guest/launch.sh', 'guest/start.sh', 'guest/lib.sh', 'guest/run-l2.sh',
           'scenarios.tsv') + tuple('artifacts/' + n for n in BINARIES) + ('artifacts/provenance.json',)
# The stage profiles. L2 names no profile in its request; L3 names itself in the identity.
L3_BINARIES = ('rosetun-helper-privileged', 'rosetun', 'sing-box')
L3_CONTENT = ('guest/launch.sh', 'guest/start.sh', 'guest/lib.sh', 'guest/run-l3.sh',
              'scenarios-l3.tsv') + tuple('artifacts/' + n for n in L3_BINARIES + (
                  'rosetun-helper.service', 'rosetun-engine.rules', 'request-kill-switch.json',
                  'request-lan.json', 'request-lan-private.json', 'request-dns-lock.json',
                  'request-program-direct.json', 'request-program-proxy.json')) + ('artifacts/provenance.json',)
ENV_L2 = ('RUN_ID STAND_ID EXPECTED_BOOT_ID USER_A USER_B BIOS_GUID SCENARIO_TIMEOUT_SECONDS '
          'UNIT_TIMEOUT_SECONDS JOB_TIMEOUT_SECONDS').split()
ENV_L3 = ENV_L2 + ['HOST_ADDRESS', 'NODE_PORT', 'PROBE_ADDRESS', 'DNS_PROBE_ADDRESS']
LAB_MARKER, MARKER_PORT = 'LAB_MARKER_ADDRESS', '9100'
PROFILES = {'l2': dict(content=CONTENT, binaries=BINARIES, env=ENV_L2),
            'l3': dict(content=L3_CONTENT, binaries=L3_BINARIES, env=ENV_L3)}
EXECUTABLE = set(BINARIES) | set(L3_BINARIES)
DOCUMENTATION_V4 = tuple(ipaddress.ip_network(n) for n in ('192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24'))
SERIAL = 'rosetun-l2-media'
ISO_LIMIT = 1700 * 1024 * 1024
TOTAL_LIMIT = 1600 * 1024 * 1024


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def make_manifest(hashes, names):
    return ''.join(hashes[n] + '  ' + n + '\n' for n in names).encode('ascii')


def unique(pairs):
    result = {}
    for k, v in pairs:
        require(k not in result)
        result[k] = v
    return result


def request(raw):
    require(len(raw) <= 16384)
    data = base64.b64decode(raw, validate=True)
    require(base64.b64encode(data).decode() == raw)
    value = json.loads(data, object_pairs_hook=unique)
    require(type(value) is dict and set(value) == {'identity', 'env', 'hashes', 'sizes'})
    i, env, hashes, sizes = (value[k] for k in ('identity', 'env', 'hashes', 'sizes'))
    require(all(type(v) is dict for v in (i, env, hashes, sizes)))
    profile = i.get('profile', 'l2')
    require(type(profile) is str and profile in PROFILES and ('profile' in i) == (profile != 'l2'))
    content, binaries, order = (PROFILES[profile][k] for k in ('content', 'binaries', 'env'))
    require(set(i) == set('host_run_id guest_run_id stand_id vm_uuid boot_id import_id media_sha256 media_size content_sha256 manifest_sha256'.split()) | (
        {'profile'} if profile != 'l2' else set()))
    for k in ('host_run_id', 'stand_id'):
        require(type(i[k]) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_-]{0,95}', i[k]))
    require(type(i['guest_run_id']) is str and re.fullmatch('[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}', i['guest_run_id']))
    require(type(i['import_id']) is str and re.fullmatch('[0-9a-f]{32}', i['import_id']))
    for k in ('vm_uuid', 'boot_id'):
        require(type(i[k]) is str and str(uuid.UUID(i[k])) == i[k] and uuid.UUID(i[k]).int != 0)
    for k in ('media_sha256', 'content_sha256', 'manifest_sha256'):
        require(type(i[k]) is str and re.fullmatch('[0-9a-f]{64}', i[k]))
    require(type(i['media_size']) is int and 0 < i['media_size'] <= ISO_LIMIT)
    require(set(hashes) == set(sizes) == set(content))
    for n in content:
        require(type(hashes[n]) is str and re.fullmatch('[0-9a-f]{64}', hashes[n]))
        limit = 512 * 1024 * 1024 if n in tuple('artifacts/' + b for b in binaries) else 256 * 1024
        require(type(sizes[n]) is int and 0 < sizes[n] <= limit)
    require(sum(sizes.values()) <= TOTAL_LIMIT)
    # Only an L3 run inside the lab names the observer's marker service, last in the file.
    marker = profile == 'l3' and LAB_MARKER in env
    order = order + [LAB_MARKER] if marker else order
    require(set(env) == set(order))
    require(all(type(v) is str for v in env.values()))
    require(env['RUN_ID'] == i['guest_run_id'] and env['STAND_ID'] == i['stand_id'] and
            env['EXPECTED_BOOT_ID'] == i['boot_id'] and env['BIOS_GUID'] == i['vm_uuid'])
    for k in ('USER_A', 'USER_B'):
        require(re.fullmatch('[a-z_][a-z0-9_-]{0,31}', env[k]))
    require(env['USER_A'] != env['USER_B'])
    for k in ('SCENARIO_TIMEOUT_SECONDS', 'UNIT_TIMEOUT_SECONDS', 'JOB_TIMEOUT_SECONDS'):
        require(re.fullmatch('[0-9]+', env[k]) and 10 <= int(env[k]) <= 86400)
    require(60 <= int(env['JOB_TIMEOUT_SECONDS']) <= 7200)
    if profile == 'l3':
        for k in ('HOST_ADDRESS', 'PROBE_ADDRESS', 'DNS_PROBE_ADDRESS'):
            require(re.fullmatch(r'[0-9]{1,3}(\.[0-9]{1,3}){3}', env[k]))
            address = ipaddress.IPv4Address(env[k])
            require(any(address in net for net in DOCUMENTATION_V4))
        require(re.fullmatch('[0-9]{1,5}', env['NODE_PORT']) and 1 <= int(env['NODE_PORT']) <= 65535)
        if marker:
            require(re.fullmatch(r'[0-9]{1,3}(\.[0-9]{1,3}){3}:' + MARKER_PORT, env[LAB_MARKER]))
            require(any(ipaddress.IPv4Address(env[LAB_MARKER].split(':')[0]) in net for net in DOCUMENTATION_V4))
    raw_env = ''.join(k + '=' + env[k] + '\n' for k in order).encode('ascii')
    final = make_manifest(dict(hashes, **{'job.env': sha(raw_env)}), content[:5] + ('job.env',) + content[5:])
    require(sha(final) == i['manifest_sha256'])
    require(sha(make_manifest(hashes, content)) == i['content_sha256'])
    return i, hashes, sizes, raw_env, final


class LinuxDevice:
    def find(self):
        candidates = []
        for item in Path('/sys/class/block').iterdir():
            serial = item / 'serial'
            if serial.exists() and serial.read_text().strip() == SERIAL:
                candidates.append(item)
        require(len(candidates) == 1)
        item = candidates[0]
        require(not (item / 'partition').exists() and (item / 'ro').read_text().strip() == '1')
        require((item / 'device/driver').resolve().name == 'virtio_blk')
        device = Path('/dev') / item.name
        info = device.lstat()
        require(stat.S_ISBLK(info.st_mode))
        require((item / 'dev').read_text().strip() == f'{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}')
        return device, int((item / 'size').read_text()) * 512

    def verify(self, device, size, expected):
        digest = hashlib.sha256()
        remaining = size
        fd = os.open(device, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            while remaining:
                block = stream.read(min(1024 * 1024, remaining))
                require(bool(block))
                digest.update(block)
                remaining -= len(block)
        require(digest.hexdigest() == expected)

    def mount(self, device, target):
        subprocess.run(['/usr/bin/mount', '-t', 'iso9660', '-o', 'ro,nodev,nosuid,noexec',
                        str(device), str(target)], stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, check=True)
        info = device.lstat()
        self.check_mount(target, f'{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}')

    def check_mount(self, target, number):
        lines = [line.split() for line in Path('/proc/self/mountinfo').read_text().splitlines()]
        rows = [r for r in lines if r[4] == str(target)]
        require(len(rows) == 1 and rows[0][2] == number)
        require({'ro', 'nodev', 'nosuid', 'noexec'} <= set(rows[0][5].split(',')))
        require(rows[0][rows[0].index('-') + 1] == 'iso9660')

    def unmount(self, target):
        subprocess.run(['/usr/bin/umount', '--', str(target)], stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, check=True)
        require(not any(r.split()[4] == str(target) for r in Path('/proc/self/mountinfo').read_text().splitlines()))


def composition(root, content=CONTENT):
    found = set()
    for parent, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            path = Path(parent) / name
            mode = path.lstat().st_mode
            require(stat.S_ISDIR(mode) if name in dirs else stat.S_ISREG(mode))
            if name in files:
                require(path.lstat().st_nlink == 1)
            found.add(path.relative_to(root).as_posix())
    require(found == set(content) | {'guest', 'artifacts', 'content.sha256'})


def copy_file(source, target, size, expected):
    before = source.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size == size)
    digest = hashlib.sha256()
    count = 0
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    out = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'rb') as src, os.fdopen(out, 'wb') as dst:
        opened = os.fstat(src.fileno())
        require((opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) ==
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns))
        for block in iter(lambda: src.read(1024 * 1024), b''):
            count += len(block)
            require(count <= size)
            digest.update(block)
            dst.write(block)
        # atime is allowed to change while reading.
        after = os.fstat(src.fileno())
        require((before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns))
        require(count == size and digest.hexdigest() == expected)
        os.fchown(dst.fileno(), 0, 0)
        os.fchmod(dst.fileno(), 0o755 if source.name.endswith('.sh') or source.name in EXECUTABLE else 0o644)
        dst.flush()
        os.fsync(dst.fileno())


def mkdir_private(path):
    path.mkdir(mode=0o700)
    os.chown(path, 0, 0)
    os.chmod(path, 0o700)


def import_media(i, hashes, sizes, env, final, adapter):
    names = PROFILES[i.get('profile', 'l2')]['content']
    attempt = ROOT / ('.import-' + i['import_id'])
    destination = ROOT / i['guest_run_id']
    require(not os.path.lexists(destination))
    mkdir_private(attempt)
    write_new(attempt / 'identity.json', (json.dumps(i, sort_keys=True) + '\n').encode())
    sync_dir(attempt)
    sync_dir(ROOT)
    mountpoint = attempt / 'media'
    mkdir_private(mountpoint)
    package = attempt / 'package'
    mkdir_private(package)
    for name in ('guest', 'artifacts'):
        mkdir_private(package / name)
    device, size = adapter.find()
    require(size == i['media_size'])
    adapter.verify(device, size, i['media_sha256'])
    # A lost mount result is deliberately not retried or cleaned up automatically.
    write_new(attempt / 'mount-intent', b'pending\n')
    sync_dir(attempt)
    adapter.mount(device, mountpoint)
    write_new(attempt / 'mount-confirmed', b'confirmed\n')
    sync_dir(attempt)
    try:
        composition(mountpoint, names)
        expected_content = make_manifest(hashes, names)
        content = mountpoint / 'content.sha256'
        require(content.stat().st_size == len(expected_content))
        require(content.read_bytes() == expected_content)
        for n in names:
            copy_file(mountpoint / n, package / n, sizes[n], hashes[n])
        write_new(package / 'job.env', env)
        write_new(package / 'manifest.sha256', final)
        for n in ('job.env', 'manifest.sha256'):
            os.chmod(package / n, 0o644)
        # Independently verify copied bytes, including the final generated files.
        for n, expected in dict(hashes, **{'job.env': sha(env), 'manifest.sha256': sha(final)}).items():
            trusted(package / n)
            digest = hashlib.sha256()
            with (package / n).open('rb') as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b''):
                    digest.update(block)
                os.fsync(stream.fileno())
            require(digest.hexdigest() == expected)
        for name in ('guest', 'artifacts', '.'):
            sync_dir(package / name)
        publish(package, destination)
        sync_dir(attempt)
        sync_dir(ROOT)
    finally:
        # Any unmount error blocks the ready receipt, even after publication.
        write_new(attempt / 'unmount-intent', b'pending\n')
        sync_dir(attempt)
        adapter.unmount(mountpoint)
        write_new(attempt / 'unmount-confirmed', b'confirmed\n')
        sync_dir(attempt)
    receipt = dict(i, schema='rosetun.l2-import.v1', state='ready')
    write_new(attempt / 'ready.pending', (json.dumps(receipt, sort_keys=True) + '\n').encode('ascii'))
    publish(attempt / 'ready.pending', attempt / 'ready.json')
    sync_dir(attempt)
    sync_dir(ROOT)


def main(argv):
    require(os.geteuid() == 0 and len(argv) == 1)
    i, hashes, sizes, env, final = request(argv[0])
    require(i['boot_id'] == boot_id() and i['vm_uuid'] == vm_uuid())
    parents(INSTALLED.parent)
    trusted(INSTALLED)
    parents(ROOT)
    trusted(ROOT, directory=True, private=True)
    import_media(i, hashes, sizes, env, final, LinuxDevice())


if __name__ == '__main__':
    os.umask(0o077)
    try:
        main(sys.argv[1:])
    except Exception:
        print('stage-l2: rejected or incomplete; retain evidence', file=sys.stderr)
        sys.exit(1)
