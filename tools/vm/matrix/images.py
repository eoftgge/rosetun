"""Strict image descriptor and offline qemu-img observations."""

from dataclasses import dataclass, asdict
import hashlib
import json
import os
from pathlib import Path
import re

from .resources import DEVICES, _identifier, _regular_file, _state_path


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
        if (self.schema != "rosetun.matrix.image.v1" or self.guest_os != "linux"
                or self.architecture != "x86_64" or self.format != "qcow2"
                or self.profile != "bios-i440fx-v1"):
            raise ValueError("unsupported image contract")
        _identifier(self.identifier)
        if type(self.size_bytes) is not int or self.size_bytes <= 0:
            raise ValueError("invalid image size")
        if type(self.sha256) is not str or not re.fullmatch('[0-9a-f]{64}', self.sha256):
            raise ValueError("invalid image digest")
        path = local_file(self.path)
        if path.is_relative_to(directory):
            raise ValueError("base image must be outside the run")
        self.verify_bytes()
        return path

    def verify_bytes(self):
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
        def identity(info):
            return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if (identity(before) != identity(held) or identity(held) != identity(after)
                or digest.hexdigest() != self.sha256):
            raise ValueError("base image size or digest mismatch")

    def record(self):
        return asdict(self)


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
