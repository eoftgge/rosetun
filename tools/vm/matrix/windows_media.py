"""The read-only medium of a Windows guest (stage 10a): what a run needs from the host, on a disc the guest reads.

A Windows guest of the lab has no network but the lab's wire, which is the observer's: nothing may come to it that way.
The agent's file calls are no way for tens of megabytes either (a session has 128 calls and a megabyte of room in each
direction). So the Rosetun binaries, the pinned sing-box, the runner and its plan go on an ISO that QEMU gives the guest
as a DVD drive (`lab.LabPair`), and the guest checks the hash of each file against the plan before it uses it. The
controller hashes every file it puts on the disc against a pin where there is one, and the disc itself before the guest
starts, so that the bytes the guest was given are the bytes the run's record names.

Nothing here starts a machine. The ISO is made by `xorriso`, which the host has for the Linux media too.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from .evidence import write_file
from .images import local_file
from .resources import resource_path

SCHEMA = 'rosetun.matrix.windows-media.v1'
# The volume label the guest looks for: the one disc of the run.
LABEL = 'ROSETUNLIST'
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,47}')
FILE_LIMIT = 160 * 1024 * 1024
TOTAL_LIMIT = 400 * 1024 * 1024
XORRISO_SECONDS = 300
ISO_NAME = 'windows-media.iso'
RECORD_NAME = 'windows-media.json'


class MediaError(ValueError):
    """A refusal with a code of the controller's own: what is wrong with the files of the disc."""


def _digest(path, limit=None):
    """(SHA-256, size) of a regular file read whole, within `limit` bytes (`FILE_LIMIT` when left out)."""
    limit = FILE_LIMIT if limit is None else limit
    path = local_file(path)
    if path.stat().st_size > limit:
        raise MediaError('windows-media-file-too-large')
    digest, size = hashlib.sha256(), 0
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            size += len(block)
            if size > limit:
                raise MediaError('windows-media-file-too-large')
            digest.update(block)
    return digest.hexdigest(), size


def stage(directory, sources, texts):
    """Copy the files of the disc into `directory`, hashing each while it moves; return a row for each.

    `sources` is a list of (name, path, pin): the pin is the SHA-256 the file must have (None for a file of the
    checkout, whose hash is recorded and travels in the plan). `texts` is a dict of name to bytes for the files the
    controller makes (the plan). A name is plain, so nothing can leave the directory.
    """
    directory = Path(directory)
    rows, total = [], 0
    names = [name for name, _, _ in sources] + list(texts)
    if len(set(names)) != len(names) or any(not NAME.fullmatch(name) for name in names):
        raise MediaError('windows-media-names-invalid')
    for name, path, pin in sources:
        before, size = _digest(path)
        if pin is not None and before != pin:
            raise MediaError('windows-media-source-mismatch')
        target = directory / name
        digest, copied = hashlib.sha256(), 0
        with local_file(path).open('rb') as source, target.open('xb') as stream:
            for block in iter(lambda: source.read(1024 * 1024), b''):
                copied += len(block)
                if copied > size:
                    raise MediaError('windows-media-source-changed')
                digest.update(block)
                stream.write(block)
        if copied != size or digest.hexdigest() != before:
            raise MediaError('windows-media-source-changed')
        rows.append(dict(name=name, sha256=before, size=size, pinned=pin is not None))
        total += size
    for name, data in texts.items():
        if type(data) is not bytes:
            raise MediaError('windows-media-names-invalid')
        (directory / name).write_bytes(data)
        rows.append(dict(name=name, sha256=hashlib.sha256(data).hexdigest(), size=len(data), pinned=False))
        total += len(data)
    if total > TOTAL_LIMIT:
        raise MediaError('windows-media-too-large')
    return rows


def command(xorriso, directory, image):
    """The command line that makes the disc: ISO 9660 level 3 with long Joliet names, which Windows reads."""
    return [xorriso, '-as', 'mkisofs', '-quiet', '-iso-level', '3', '-J', '-joliet-long', '-V', LABEL,
            '-o', str(image), str(directory)]


def build(run, xorriso, sources, texts, *, runner=subprocess.run, scratch=None):
    """Make the disc into the run's own file and write its record; return the record.

    The files are staged in a directory of their own that is removed afterwards. The record names each file with
    its hash, the disc with its own, and the tool; the disc is read back and hashed once it is written.
    """
    image = resource_path(run.directory, ISO_NAME)
    local_file(xorriso)
    work = Path(tempfile.mkdtemp(prefix='rosetun-media-', dir=scratch))
    try:
        rows = stage(work, sources, texts)
        try:
            result = runner(command(xorriso, work, image), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=XORRISO_SECONDS, check=False)
        except (OSError, subprocess.SubprocessError):
            raise MediaError('windows-media-tool-failed') from None
        if result.returncode != 0:
            raise MediaError('windows-media-tool-failed')
    finally:
        shutil.rmtree(work, ignore_errors=True)
    digest, size = _digest(image, TOTAL_LIMIT + 64 * 1024 * 1024)
    record = dict(schema=SCHEMA, label=LABEL, files=rows, iso=dict(name=ISO_NAME, sha256=digest, size=size),
                  tool=Path(xorriso).name)
    write_file(run, RECORD_NAME, (json.dumps(record, sort_keys=True, indent=2) + '\n').encode('ascii'),
               mode='overwrite', readback=True, forbid=run._identity[2])
    return record


def verify(run, record):
    """Before the guest starts the disc is the one the record names: the same bytes, the same size."""
    digest, size = _digest(resource_path(run.directory, ISO_NAME), TOTAL_LIMIT + 64 * 1024 * 1024)
    if (digest, size) != (record['iso']['sha256'], record['iso']['size']):
        raise MediaError('windows-media-changed')
    return True


def files_of(record):
    """name -> row of the files the record lists."""
    return {row['name']: row for row in record['files']}
