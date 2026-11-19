"""Strict image descriptor and offline qemu-img observations."""

from dataclasses import dataclass, asdict, fields
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat

from .resources import DEVICES, _identifier, _regular_file, _state_path

SCHEMA = "rosetun.matrix.image.v1"
LINUX_PROFILE = "bios-i440fx-v1"
WINDOWS_PROFILE = "windows-uefi-q35-v1"


def local_file(value):
    if not isinstance(value, (str, Path)):
        raise ValueError("invalid local path")
    path = _state_path(value)
    if os.name == 'nt' and any(
            ':' in part or part.endswith(('.', ' '))
            or part.split('.')[0].upper() in DEVICES for part in path.parts[1:]):
        raise ValueError("Windows path aliases and alternate streams are unsupported")
    # Commas are interpreted by QEMU option grammars, independently of the shell.
    if any(ord(c) < 32 for c in str(path)) or ',' in str(path):
        raise ValueError("unsupported QEMU path characters")
    _regular_file(path)
    return path


@dataclass(frozen=True)
class ImageDescriptor:
    schema: str
    identifier: str
    guest_os: str
    architecture: str
    path: str
    size_bytes: int
    sha256: str
    format: str
    profile: str

    def validate(self, directory):
        if (self.schema != SCHEMA or self.guest_os != "linux"
                or self.architecture != "x86_64" or self.format != "qcow2"
                or self.profile != LINUX_PROFILE):
            raise ValueError("unsupported image contract")
        return self._validate_base(directory)

    def _validate_base(self, directory):
        _identifier(self.identifier)
        if type(self.size_bytes) is not int or self.size_bytes <= 0:
            raise ValueError("invalid image size")
        if type(self.sha256) is not str or not re.fullmatch('[0-9a-f]{64}', self.sha256):
            raise ValueError("invalid image digest")
        path = local_file(self.path)
        if path.is_relative_to(directory):
            raise ValueError("base image must be outside the run")
        self.verify_bytes(directory)
        return path

    def verify_bytes(self, run_directory=None, *, fresh=False):
        """Hash the whole file and compare; returns the file's identity as it was read.

        `run_directory` and `fresh` are for the Windows disk, whose digest is remembered between passes: a Linux
        disk is small and is hashed every time.
        """
        path = local_file(self.path)
        before = path.stat()
        if before.st_size != self.size_bytes:
            raise ValueError("base image size mismatch")
        digest = hashlib.sha256()
        with path.open('rb') as stream:
            remaining = self.size_bytes + 1
            while remaining:
                block = stream.read(min(1024 * 1024, remaining))
                if not block:
                    break
                digest.update(block)
                remaining -= len(block)
            held = os.fstat(stream.fileno())
        after = path.stat()
        if (_identity(before) != _identity(held) or _identity(held) != _identity(after)
                or digest.hexdigest() != self.sha256):
            raise ValueError("base image size or digest mismatch")
        return _identity(held)

    def record(self):
        return asdict(self)


def _identity(info):
    """What a file is for the digest cache: device, inode, size and both change times, in nanoseconds.

    The modification time can be set by the file's owner, the change time (`st_ctime_ns`) cannot: any write,
    rename over or `utime` moves it, so a file replaced with its old modification time restored still differs.
    """
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def sha256_of(path, limit):
    """Digest of a small regular file the controller reads whole; a larger file is refused."""
    path = local_file(path)
    before = path.stat()
    if before.st_size > limit:
        raise ValueError("file too large")
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        remaining = before.st_size + 1
        while remaining:
            block = stream.read(min(1024 * 1024, remaining))
            if not block:
                break
            digest.update(block)
            remaining -= len(block)
        held = os.fstat(stream.fileno())
    after = path.stat()
    if _identity(before) != _identity(held) or _identity(held) != _identity(after):
        raise ValueError("file changed while it was read")
    return digest.hexdigest()


FIRMWARE_LIMIT = 64 * 1024 * 1024
# The identity (device, inode, size, change times) of each Windows disk this process hashed in full, by path and
# digest. The disk is tens of gigabytes: the stand needs minutes for one pass, and a run asks for the check
# several times. A pass already made counts as long as the file's identity is the one it saw, and a change of
# the file's bytes changes its change time.
_HASHED = {}
# The same memory between processes: one small record per disk in the stand's state directory, written after a
# full pass that matched the descriptor and trusted only while the file's identity is the one it records. A record
# that is missing, unreadable or unlike the file is no record: the disk is hashed in full.
DIGEST_CACHE = 'image-digests'
DIGEST_CACHE_SCHEMA = 'rosetun.matrix.image-digest.v1'
DIGEST_CACHE_LIMIT = 4096
DIGEST_CACHE_FIELDS = ('schema', 'path', 'sha256', 'device', 'inode', 'size', 'mtime_ns', 'ctime_ns')
HEX64 = re.compile('[0-9a-f]{64}')
SLOT = re.compile('0x[0-9a-f]{1,2}')
# `host`, then switches and values of one CPU option each: nothing that could carry another QEMU option.
CPU_GRAMMAR = re.compile(r'host(,-?[a-z][a-z0-9_-]*(=[0-9a-zx]+)?)*')
MAC = re.compile('([0-9a-f]{2}:){5}[0-9a-f]{2}')
TPM_FILE = re.compile(r'[A-Za-z0-9._-]{1,64}')
TPM_STATE_FILE = 'tpm2-00.permall'
QGA_PORT = 'org.qemu.guest_agent.0'


def _cache_directory(run_directory):
    """The stand's digest directory for a run directory `STATE/runs/ID`; none for any other place."""
    if run_directory is None:
        return None
    directory = Path(run_directory)
    return directory.parent.parent / DIGEST_CACHE if directory.parent.name == 'runs' else None


def _cache_file(cache, path):
    return cache / (hashlib.sha256(str(path).encode()).hexdigest() + '.json')


def _cache_record(path, digest, identity):
    device, inode, size, mtime, ctime = identity
    return dict(schema=DIGEST_CACHE_SCHEMA, path=str(path), sha256=digest, device=device, inode=inode, size=size,
                mtime_ns=mtime, ctime_ns=ctime)


def _cache_hit(cache, path, digest, identity):
    """Whether a record in `cache` says that this file, as it is now, hashed to `digest`; any doubt is a miss."""
    try:
        file = _cache_file(cache, path)
        if cache.is_symlink() or file.is_symlink():
            return False
        descriptor = os.open(file, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        with os.fdopen(descriptor, 'rb') as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                return False
            raw = stream.read(DIGEST_CACHE_LIMIT + 1)
        if len(raw) > DIGEST_CACHE_LIMIT:
            return False
        value = json.loads(raw.decode('utf-8'))
    except (OSError, ValueError, RecursionError):
        return False
    return value == _cache_record(path, digest, identity) and all(
        type(value[name]) is int for name in DIGEST_CACHE_FIELDS[3:]) and set(value) == set(DIGEST_CACHE_FIELDS)


def _cache_store(cache, path, digest, identity):
    """Replace the record atomically; a cache that cannot be written is only a cache that is not there."""
    try:
        if cache.is_symlink():
            return
        cache.mkdir(mode=0o700, exist_ok=True)
        file = _cache_file(cache, path)
        temporary = file.with_name(file.name + '.' + secrets.token_hex(8) + '.tmp')
        raw = (json.dumps(_cache_record(path, digest, identity), sort_keys=True) + '\n').encode()
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        try:
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, file)
        except BaseException:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise
        if os.name == 'posix':
            directory = os.open(cache, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    except OSError:
        return


def _shape(value, required, optional=()):
    if (type(value) is not dict or not set(required) <= set(value)
            or set(value) - set(required) - set(optional)):
        raise ValueError("invalid Windows image descriptor fields")
    return value


def _hashed(value):
    _shape(value, ('path', 'sha256'))
    if type(value['sha256']) is not str or not HEX64.fullmatch(value['sha256']):
        raise ValueError("invalid Windows image digest")
    return str(local_file(value['path'])), value['sha256']


def local_directory(value):
    if not isinstance(value, (str, Path)):
        raise ValueError("invalid local path")
    path = _state_path(value)
    if any(ord(c) < 32 for c in str(path)) or ',' in str(path):
        raise ValueError("unsupported QEMU path characters")
    if not path.is_dir():
        raise ValueError("expected a directory")
    return path


@dataclass(frozen=True)
class WindowsImageDescriptor(ImageDescriptor):
    """The image of stage 9a: the Linux contract plus a `windows` block, profile `windows-uefi-q35-v1`.

    The block is read strictly and its three kinds of state (disk, firmware variables, TPM files) are
    hashed like the Linux disk. `qualified` is false in every descriptor 9a writes and stays the only
    value accepted: the controller has no qualification of a Windows image, so it never reads the
    field as a permission, and a run of such an image is diagnostic whatever the run reports.
    """

    windows: dict

    def verify_bytes(self, run_directory=None, *, fresh=False):
        """Hash the disk in full unless this process or an earlier one already did and the file is the same.

        The file is the same when its device, inode, size, modification time and change time are all what they were
        after that pass. `run_directory` (`STATE/runs/ID`) says which state directory holds the stand's record of
        earlier passes; `fresh` asks for a pass whatever the records say.
        """
        path = local_file(self.path)
        key = (str(path), self.sha256)
        now = _identity(path.stat())
        cache = _cache_directory(run_directory)
        if not fresh and now[2] == self.size_bytes:
            if _HASHED.get(key) == now:
                return now
            if cache is not None and _cache_hit(cache, path, self.sha256, now):
                _HASHED[key] = now
                return now
        _HASHED.pop(key, None)
        identity = super().verify_bytes()
        _HASHED[key] = identity
        if cache is not None:
            _cache_store(cache, path, self.sha256, identity)
        return identity

    def validate(self, directory, *, fresh=False):
        if (self.schema != SCHEMA or self.guest_os != "windows"
                or self.architecture != "x86_64" or self.format != "qcow2"
                or self.profile != WINDOWS_PROFILE):
            raise ValueError("unsupported image contract")
        if fresh:
            self.verify_bytes(directory, fresh=True)
        path = self._validate_base(directory)
        facts = self.facts()
        for name in ('code', 'vars'):
            location, digest = facts[name]
            if sha256_of(location, FIRMWARE_LIMIT) != digest:
                raise ValueError("Windows image firmware digest mismatch")
        for name, digest in facts['tpm_files'].items():
            if sha256_of(os.path.join(facts['tpm_directory'], name), FIRMWARE_LIMIT) != digest:
                raise ValueError("Windows image TPM state digest mismatch")
        return path

    def facts(self):
        """What a launch plan needs of the block, after checking its shape; no file is read."""
        block = _shape(self.windows, ('activated', 'qualified', 'uefi', 'tpm', 'devices'),
                       ('edition', 'language', 'hostname', 'account', 'built_at', 'installation_media',
                        'virtio_win', 'calm'))
        if block['activated'] is not False:
            raise ValueError("an activated Windows image is unsupported")
        if block['qualified'] is not False:
            raise ValueError("a qualified Windows image is unsupported")
        uefi = _shape(block['uefi'], ('secure_boot', 'smm', 'flavour', 'code', 'vars', 'vars_template'), ('note',))
        if uefi['secure_boot'] is not True or type(uefi['smm']) is not bool:
            raise ValueError("unsupported Windows firmware record")
        code, vars_ = _hashed(uefi['code']), _hashed(uefi['vars'])
        _hashed(uefi['vars_template'])
        tpm = _shape(block['tpm'], ('version', 'device', 'emulator', 'state'))
        if (tpm['version'], tpm['device'], tpm['emulator']) != ('2.0', 'tpm-crb', 'swtpm'):
            raise ValueError("unsupported Windows TPM record")
        state = _shape(tpm['state'], ('directory', 'files'))
        files = state['files']
        if (type(files) is not dict or TPM_STATE_FILE not in files or len(files) > 16
                or any(not TPM_FILE.fullmatch(name) or name in ('.', '..') or type(digest) is not str
                       or not HEX64.fullmatch(digest) for name, digest in files.items())):
            raise ValueError("invalid Windows TPM state record")
        devices = _shape(block['devices'], ('machine', 'cpu', 'memory_mib', 'vcpus', 'disk', 'net', 'mac', 'serial',
                                           'qga', 'pci_slots', 'uuid_at_build'))
        if (devices['machine'] != 'q35' or type(devices['cpu']) is not str
                or not CPU_GRAMMAR.fullmatch(devices['cpu'])
                or (devices['disk'], devices['net'], devices['serial'], devices['qga'])
                != ('virtio-blk-pci', 'virtio-net-pci', 'virtio-serial-pci', QGA_PORT)
                or type(devices['mac']) is not str or not MAC.fullmatch(devices['mac'])
                or type(devices['memory_mib']) is not int or type(devices['vcpus']) is not int):
            raise ValueError("unsupported Windows device record")
        slots = _shape(devices['pci_slots'], ('vga', 'disk', 'net', 'serial'))
        values = list(slots.values())
        if (any(type(v) is not str or not SLOT.fullmatch(v) or int(v, 16) in (0, 0x1f) for v in values)
                or len(set(values)) != len(values)):
            raise ValueError("invalid Windows PCI slots")
        return {'smm': uefi['smm'], 'code': code, 'vars': vars_,
                'tpm_directory': str(local_directory(state['directory'])),
                'tpm_files': dict(sorted(files.items())), 'machine': devices['machine'], 'cpu': devices['cpu'],
                'memory_mib': devices['memory_mib'], 'vcpus': devices['vcpus'], 'mac': devices['mac'],
                'slots': dict(slots)}


def image_of(record):
    """The descriptor a launch plan carries: the Windows one when it has the block, else the Linux one."""
    if type(record) is dict and 'windows' in record:
        return WindowsImageDescriptor(**record)
    return ImageDescriptor(**record)


def load_windows_descriptor(path):
    """Read the `image.json` of stage 9a: strict JSON, no duplicate keys, the nine contract fields and the block."""
    raw = local_file(path).read_bytes()
    if len(raw) > 64 * 1024:
        raise ValueError("descriptor too large")
    def invalid_constant(value):
        raise ValueError("non-finite JSON number")
    record = json.loads(raw.decode('utf-8'), object_pairs_hook=_object, parse_constant=invalid_constant)
    names = [f.name for f in fields(WindowsImageDescriptor)]
    if type(record) is not dict or set(record) != set(names):
        raise ValueError("unknown or missing Windows image fields")
    return WindowsImageDescriptor(**record)


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate image JSON key")
        result[key] = value
    return result


def image_chain(output, expected_paths, virtual_size=None):
    """Accept only a complete qcow2 chain with no auxiliary storage."""
    def invalid_constant(value):
        raise ValueError("non-finite image JSON number")
    chain = json.loads(output.decode('utf-8'), object_pairs_hook=_object,
                       parse_constant=invalid_constant)
    if type(chain) is not list or len(chain) != len(expected_paths):
        raise ValueError("unexpected backing chain")
    for index, (info, path) in enumerate(zip(chain, expected_paths)):
        if type(info) is not dict or info.get('format') != 'qcow2':
            raise ValueError("unexpected image format")
        if info.get('filename') != str(path):
            raise ValueError("unexpected image filename")
        size = info.get('virtual-size')
        if type(size) is not int or size <= 0 or (virtual_size is not None and size != virtual_size):
            raise ValueError("invalid virtual size")
        virtual_size = size
        specific = info.get('format-specific')
        if (type(specific) is not dict or specific.get('type') != 'qcow2'
                or type(specific.get('data')) is not dict
                or specific['data'].get('compat') not in ('0.10', '1.1')
                or type(specific['data'].get('refcount-bits')) is not int
                or specific['data']['refcount-bits'] not in (1, 2, 4, 8, 16, 32, 64)):
            raise ValueError("incomplete qcow2 information")
        def check_aux(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    if key in ('data-file', 'data-file-raw', 'encrypt', 'snapshots', 'children'):
                        raise ValueError("auxiliary image storage is unsupported")
                    if key in ('corrupt', 'dirty-flag', 'encrypted') and item is not False:
                        raise ValueError("unsafe image state")
                    check_aux(item)
            elif isinstance(value, list):
                for item in value:
                    check_aux(item)
        # QEMU 8+ describes the qcow2 container's own file node as a child.
        # Accept only that exact leaf, never an additional storage graph.
        if 'children' in info:
            children = info['children']
            if (type(children) is not list or len(children) != 1
                    or type(children[0]) is not dict or set(children[0]) != {'name', 'info'}
                    or children[0]['name'] != 'file'):
                raise ValueError("unexpected image children")
            leaf = children[0]['info']
            required = {'children', 'virtual-size', 'filename', 'format',
                        'format-specific', 'dirty-flag'}
            if (type(leaf) is not dict or not required <= set(leaf)
                    or set(leaf) - required - {'actual-size'}
                    or leaf['children'] != [] or leaf['format'] != 'file'
                    or leaf['filename'] != str(path) or leaf['dirty-flag'] is not False
                    or type(leaf['virtual-size']) is not int
                    or leaf['virtual-size'] <= 0
                    # QEMU reports file length rounded up to a 512-byte sector.
                    or leaf['virtual-size'] != ((local_file(path).stat().st_size + 511) // 512) * 512
                    or leaf['format-specific'] != {'type': 'file', 'data': {}}):
                raise ValueError("unexpected image file child")
            if 'actual-size' in leaf and (type(leaf['actual-size']) is not int or leaf['actual-size'] < 0):
                raise ValueError("invalid child allocation size")
            info = {key: value for key, value in info.items() if key != 'children'}
        check_aux(info)
        backing_keys = {key for key in info if 'backing' in key}
        if index + 1 < len(chain):
            if backing_keys != {'backing-filename', 'full-backing-filename', 'backing-filename-format'}:
                raise ValueError("incomplete backing information")
            if (info['backing-filename'] != str(expected_paths[index + 1])
                    or info['full-backing-filename'] != str(expected_paths[index + 1])
                    or info['backing-filename-format'] != 'qcow2'):
                raise ValueError("backing image mismatch")
        elif backing_keys:
            raise ValueError("unexpected base backing image")
    return virtual_size
