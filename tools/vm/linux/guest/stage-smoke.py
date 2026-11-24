#!/usr/bin/python3
"""Owner-installed root entry point. Never executes delivered code."""

import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import uuid

ROOT = Path('/root/rosetun-l2-stage')
INSTALLED = Path('/usr/local/libexec/rosetun-l2/stage-smoke')
PAYLOAD = ('guest/launch.sh', 'guest/start.sh', 'guest/lib.sh', 'guest/run-smoke.sh', 'job.env')
FILES = PAYLOAD + ('manifest.sha256',)
FILE_LIMIT = 24 * 1024
TOTAL_LIMIT = 64 * 1024


def require(condition):
    if not condition:
        raise ValueError('unsafe or invalid smoke stage')


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
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def read_file(path, limit=FILE_LIMIT):
    before = trusted(path)
    require(0 < before.st_size <= limit)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        data = stream.read(limit + 1)
        os.fsync(stream.fileno())
        after = os.fstat(stream.fileno())
    def identity(info):
        return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns
    require(identity(before) == identity(opened) == identity(after) == identity(trusted(path)))
    require(len(data) == before.st_size and b'\r' not in data and data.endswith(b'\n'))
    data.decode('utf-8')
    return data


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


def main(argv):
    require(os.geteuid() == 0 and len(argv) == 7)
    operation, host, guest, machine, boot, attempt, digest = argv
    require(operation in ('create', 'finalize'))
    require(re.fullmatch('[A-Za-z0-9][A-Za-z0-9_-]{0,95}', host))
    require(re.fullmatch('[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}', guest))
    require(re.fullmatch('[0-9a-f]{32}', attempt) and re.fullmatch('[0-9a-f]{64}', digest))
    for value in (machine, boot):
        require(str(uuid.UUID(value)) == value and uuid.UUID(value).int != 0)
    require(machine == vm_uuid() and boot == boot_id())
    parents(INSTALLED.parent)
    trusted(INSTALLED)
    parents(ROOT)
    trusted(ROOT, directory=True, private=True)
    identity = dict(host_run_id=host, guest_run_id=guest, vm_uuid=machine,
                    boot_id=boot, attempt_id=attempt, manifest_sha256=digest)
    raw_identity = (json.dumps(identity, sort_keys=True) + '\n').encode('ascii')
    attempt_dir = ROOT / ('.attempt-' + attempt)
    package = attempt_dir / 'package'
    destination = ROOT / guest
    require(not os.path.lexists(destination))
    if operation == 'create':
        attempt_dir.mkdir(mode=0o700)
        write_new(attempt_dir / 'identity.json', raw_identity)
        package.mkdir(mode=0o700)
        (package / 'guest').mkdir(mode=0o700)
        # qemu-ga may create files as 0666. Reserve private files ourselves;
        # its one write-only open then retains their trusted ownership/mode.
        for name in FILES:
            write_new(package / name, b'')
        sync_dir(package / 'guest')
        sync_dir(package)
        sync_dir(attempt_dir)
        sync_dir(ROOT)
        return
    trusted(attempt_dir, directory=True, private=True)
    require(read_file(attempt_dir / 'identity.json', 1024) == raw_identity)
    trusted(package, directory=True, private=True)
    trusted(package / 'guest', directory=True, private=True)
    require(set(p.name for p in attempt_dir.iterdir()) == {'identity.json', 'package'})
    require(set(p.name for p in package.iterdir()) == {'guest', 'job.env', 'manifest.sha256'})
    require(set(p.name for p in (package / 'guest').iterdir()) == {p.split('/')[1] for p in PAYLOAD[:-1]})
    files = {name: read_file(package / name, 1024 if name == 'job.env' else FILE_LIMIT) for name in FILES}
    require(sum(map(len, files.values())) <= TOTAL_LIMIT)
    manifest = ''.join(hashlib.sha256(files[name]).hexdigest() + '  ' + name + '\n' for name in PAYLOAD).encode('ascii')
    require(files['manifest.sha256'] == manifest and hashlib.sha256(manifest).hexdigest() == digest)
    env = files['job.env'].decode('ascii')
    prefix = (f'PROFILE=infra-smoke-v1\nHOST_RUN_ID={host}\nRUN_ID={guest}\n'
              f'VM_UUID={machine}\nEXPECTED_BOOT_ID={boot}\nJOB_ID=smoke\nDELAY_SECONDS=')
    require(env.startswith(prefix) and re.fullmatch(r'([0-9]|[12][0-9]|30)\n', env[len(prefix):]))
    sync_dir(package / 'guest')
    sync_dir(package)
    publish(package, destination)
    sync_dir(attempt_dir)
    sync_dir(ROOT)
    receipt = dict(identity, schema='rosetun.smoke-stage.v1', state='ready')
    write_new(attempt_dir / 'ready.pending', (json.dumps(receipt, sort_keys=True) + '\n').encode('ascii'))
    publish(attempt_dir / 'ready.pending', attempt_dir / 'ready.json')
    sync_dir(attempt_dir)
    sync_dir(ROOT)


if __name__ == '__main__':
    os.umask(0o077)
    try:
        main(sys.argv[1:])
    except (OSError, ValueError, AttributeError, UnicodeError):
        print('stage-smoke: rejected or incomplete; retain evidence', file=sys.stderr)
        sys.exit(1)
