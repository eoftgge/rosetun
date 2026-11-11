"""One writer for matrix evidence: rows appended to journals and whole files.

Every failure is a ValueError or an OSError. Turning it into a domain error and
setting flags such as `evidence_failed` stays with the caller.
"""

import json
import os

# Module imports, not names: resources uses fsync_directory from here, so a
# name import in either direction would depend on which module loads first.
from . import resources


class ReadbackError(ValueError):
    """A file read back after the write differs from the bytes written."""


def fsync_directory(path):
    if os.name == 'posix':
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def encode_row(value):
    return (json.dumps(value, sort_keys=True) + '\n').encode('utf-8')


def _registered(relative, manifest):
    if not any(r.get('kind') == 'file' and r.get('path') == relative for r in manifest['resources']):
        raise ValueError('evidence-not-registered')


def _check_forbidden(forbid, raw):
    if forbid is not None and forbid.encode() in raw:
        raise ValueError('owner-token-in-evidence')


def _write_synced(path, raw, mode):
    with path.open(mode) as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def append_row(run, relative, value, *, forbid=None, max_bytes=None, limit_check='after',
               require_registered=False, require_regular=False, create=False,
               sync_parent=False):
    """Append one JSON row to a journal and make it durable.

    `limit_check` 'after' refuses a row that would take the file past
    `max_bytes`; 'before' refuses only when the file is already past it.
    """
    if limit_check not in ('before', 'after'):
        raise ValueError('invalid-limit-check')
    manifest = run._read()
    if require_registered:
        _registered(relative, manifest)
    path = resources.resource_path(run.directory, relative)
    if require_regular:
        resources._regular_file(path)
    raw = encode_row(value)
    _check_forbidden(forbid, raw)
    if max_bytes is not None:
        if limit_check == 'before':
            size = path.stat().st_size if path.exists() else 0
            if size > max_bytes:
                raise ValueError('evidence-size-limit')
        elif path.stat().st_size + len(raw) > max_bytes:
            raise ValueError('evidence-size-limit')
    _write_synced(path, raw, 'xb' if create else 'ab')
    if sync_parent:
        fsync_directory(path.parent)


def write_file(run, relative, raw, *, mode, forbid=None, require_registered=False,
               readback=False, sync_parent=False, temporary=None):
    """Write a whole file. `mode` is 'create' (xb), 'overwrite' (wb) or 'replace'.

    'replace' writes `temporary` exclusively in the same directory, syncs it and
    renames it over the target, so a failure leaves the old content. A failed
    attempt keeps the temporary file as evidence. The directory is synced after
    a replace, and after any other mode when `sync_parent` is set.
    """
    if mode not in ('create', 'overwrite', 'replace'):
        raise ValueError('invalid-write-mode')
    if (mode == 'replace') != (temporary is not None):
        raise ValueError('temporary-name-requires-replace')
    manifest = run._read()
    if require_registered:
        _registered(relative, manifest)
    path = resources.resource_path(run.directory, relative)
    _check_forbidden(forbid, raw)
    if mode == 'replace':
        scratch = resources.resource_path(run.directory, temporary)
        if scratch.parent != path.parent:
            raise ValueError('temporary-must-share-directory')
        _write_synced(scratch, raw, 'xb')
        os.replace(scratch, path)
        fsync_directory(path.parent)
    else:
        _write_synced(path, raw, 'xb' if mode == 'create' else 'wb')
        if sync_parent:
            fsync_directory(path.parent)
    if readback and path.read_bytes() != raw:
        raise ReadbackError('evidence-readback-failed')
