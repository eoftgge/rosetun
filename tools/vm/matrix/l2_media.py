"""Immutable L2 ISO preparation. No build, discovery, download or cleanup."""

import hashlib
import json
import os
from pathlib import Path
import re

from . import linux_l2 as l2
from .evidence import append_row, write_file
from .images import local_file
from .qemu import execute, CommandResult
from .resources import resource_path, execution_resources

CONTENT = tuple(n for n in l2.PAYLOAD if n != 'job.env')
SERIAL = 'rosetun-l2-media'
TOTAL_LIMIT = 1600 * 1024 * 1024
ISO_LIMIT = 1700 * 1024 * 1024


def content(profile='l2'):
    return tuple(n for n in l2.profile_of(profile).payload if n != 'job.env')


def request_resources(profile='l2'):
    """Generated requests live in the run, not in the owner's content directory."""
    return tuple('l3-requests/' + n for n in l2.profile_of(profile).requests)


def resources(profile='l2'):
    """The run resources of one media attachment, in registration order.

    The requests come first: the controller registers them before the media is attached.
    """
    return request_resources(profile) + ('l2-media.iso', 'l2-media.jsonl', 'l2-media.json',
            'l2-import.jsonl', 'l2-receipt.json') + tuple(
        'l2-snapshot/' + n for n in content(profile) + ('content.sha256',)) + tuple(
        'l2-package/' + n for n in l2.profile_of(profile).files)


RESOURCES = resources('l2')


def manifest(hashes, names):
    return ''.join(hashes[n] + '  ' + n + '\n' for n in names).encode('ascii')


def copy_verified(source, target, sha, size):
    l2._regular_file(source)
    before = source.stat()
    digest = hashlib.sha256()
    count = 0
    with source.open('rb') as src, target.open('xb') as dst:
        opened = os.fstat(src.fileno())
        for block in iter(lambda: src.read(1024 * 1024), b''):
            count += len(block)
            if count > size:
                raise ValueError('l2-source-changed')
            digest.update(block)
            dst.write(block)
        after = os.fstat(src.fileno())
        dst.flush()
        os.fsync(dst.fileno())
    def key(s):
        return s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns
    l2._regular_file(source)
    if (not key(before) == key(opened) == key(after) == key(source.stat()) or
            count != size or digest.hexdigest() != sha):
        raise ValueError('l2-source-changed')


def write_requests(run, server, port, diagnostic=False):
    """After qemu.prepare, before attach_media: create the L3 requests as run resources."""
    from . import l3_requests
    manifest = run._read()
    if manifest['state'] != 'prepared' or len(manifest['resources']) != 3 + len(execution_resources(manifest)):
        raise ValueError('l3-requests-require-new-prepared-run')
    files = l3_requests.render_all(server, port, diagnostic=diagnostic)
    names = request_resources('l3')
    registered = False
    try:
        for i, name in enumerate(names):
            path = resource_path(run.directory, name)
            if path.exists():
                raise ValueError('l3-request-destination-exists')
            run.register(dict(id='l2-media-' + str(i), kind='file', path=name))
            registered = True
            path.parent.mkdir(parents=True, exist_ok=True)
            write_file(run, name, files[name.rpartition('/')[2]], mode='create',
                       forbid=run._identity[2], require_registered=True)
    except BaseException:
        if registered:
            try:
                run.mark('quarantined', 'l3-requests-failed')
            except (OSError, ValueError):
                pass
        raise


def verify_media(record):
    if (set(record) != {'path', 'sha256', 'size', 'content_sha256', 'package'} or
            type(record['size']) is not int or not 0 < record['size'] <= ISO_LIMIT or
            not re.fullmatch('[0-9a-f]{64}', record['sha256']) or
            not re.fullmatch('[0-9a-f]{64}', record['content_sha256'])):
        raise ValueError('invalid-l2-media-record')
    sha, size, _ = l2._hash(Path(record['path']), ISO_LIMIT)
    if (sha, size) != (record['sha256'], record['size']):
        raise ValueError('l2-media-changed')


def attach_media(run, *, directory, checkout, xorriso, executor=execute, profile='l2',
                 sing_box_sha256=None):
    """After qemu.prepare, before start. Input is the exact immutable content tree of the profile."""
    profile = l2.profile_of(profile).name
    names = content(profile)
    plan_path = resource_path(run.directory, 'launch-plan.json')
    requests = request_resources(profile)
    if run._read()['state'] != 'prepared' or len(run._read()['resources']) != (
            3 + len(execution_resources(run._read())) + len(requests)):
        raise ValueError('l2-media-requires-new-prepared-run')
    registered_paths = {r['id']: r.get('path') for r in run._read()['resources']}
    for i, name in enumerate(requests):
        if registered_paths.get('l2-media-' + str(i)) != name or not resource_path(run.directory, name).is_file():
            raise ValueError('l3-requests-missing')
    plan = l2._json(plan_path.read_bytes())
    if not plan['config'].get('qga') or plan['config']['machine'] != 'pc-i440fx-10.0':
        raise ValueError('l2-media-requires-pinned-qga-machine')
    # Once a resource is registered the run holds partial files that no retry
    # may reuse, so any later failure quarantines it, as qemu.prepare does.
    registered = False
    try:
        for i, name in enumerate(resources(profile)[len(requests):], len(requests)):
            path = resource_path(run.directory, name)
            if path.exists():
                raise ValueError('l2-media-destination-exists')
            run.register(dict(id='l2-media-' + str(i), kind='file', path=name))
            registered = True
            path.parent.mkdir(parents=True, exist_ok=True)
        def event(**row):
            append_row(run, 'l2-media.jsonl', row, require_registered=True, forbid=run._identity[2])
        def command(args, timeout):
            argv = [str(xorriso), '-no_rc', *args]
            event(argv=argv, timeout=timeout, output_limit=65536, state='intent')
            try:
                result = executor(argv, timeout=timeout, output_limit=65536)
                if (not isinstance(result, CommandResult) or
                        type(result.stdout) is not bytes or type(result.stderr) is not bytes or
                        max(len(result.stdout), len(result.stderr)) > 65536):
                    raise ValueError('invalid-xorriso-output')
                event(state='returned', returncode=result.returncode,
                      stdout=result.stdout.decode('utf-8', 'replace'),
                      stderr=result.stderr.decode('utf-8', 'replace'))
                if result.returncode != 0:
                    raise ValueError('xorriso-failed')
                return result.stdout + result.stderr
            except BaseException as error:
                event(state='failed-retain-partials',
                      stdout=(getattr(error, 'stdout', None) or b'')[:65536].decode('utf-8', 'replace'),
                      stderr=(getattr(error, 'stderr', None) or b'')[:65536].decode('utf-8', 'replace'))
                raise
        event(state='preflight', source=str(directory), checkout=str(checkout),
              snapshot='l2-snapshot', output='l2-media.iso')
        try:
            local_file(xorriso)  # Explicit installed executable; no PATH fallback.
        except (OSError, ValueError):
            event(state='preflight-executable-unavailable')
            raise ValueError('xorriso-1.5.6-preflight-executable-unavailable') from None
        version = command(['-version'], 10).decode('utf-8', 'replace')
        if not re.search(r'xorriso(?: version)?\s*:?\s*1\.5\.6(?:\s|$)', version):
            raise ValueError('xorriso-1.5.6-required')
        # The requests are checked where the controller wrote them, not in the owner's tree.
        source_options = dict(requests_directory=resource_path(run.directory, 'l3-requests')) if requests else {}
        package = l2.validate_package(directory, checkout=checkout, immutable=True, profile=profile,
                                      sing_box_sha256=sing_box_sha256, **source_options)
        if sum(package['sizes'].values()) > TOTAL_LIMIT:
            raise ValueError('l2-media-total-size')
        snapshot = resource_path(run.directory, 'l2-snapshot')
        generated = {'artifacts/' + n for n in l2.profile_of(profile).requests}
        for n in names:
            for target in (snapshot / n, resource_path(run.directory, 'l2-package/' + n)):
                source = (resource_path(run.directory, 'l3-requests/' + n.rpartition('/')[2])
                          if n in generated else Path(directory) / n)
                copy_verified(source, target, package['hashes'][n], package['sizes'][n])
        if l2.validate_package(directory, checkout=checkout, immutable=True, profile=profile,
                               sing_box_sha256=sing_box_sha256, **source_options) != package:
            raise ValueError('l2-source-changed')
        if l2.validate_package(snapshot, checkout=checkout, immutable=True, profile=profile,
                               sing_box_sha256=sing_box_sha256) != package:
            raise ValueError('l2-snapshot-mismatch')
        listing = manifest(package['hashes'], names)
        write_file(run, 'l2-snapshot/content.sha256', listing, mode='create',
                   forbid=run._identity[2])
        event(state='snapshot-verified', package=package, content_sha256=hashlib.sha256(listing).hexdigest())
        iso = resource_path(run.directory, 'l2-media.iso')
        command(['-as', 'mkisofs', '-iso-level', '3', '-R', '-V', 'ROSETUN_' + profile.upper(),
                 '-o', str(iso), str(snapshot)], 300)
        sha, size, _ = l2._hash(iso, ISO_LIMIT)
        record = dict(path=str(iso), sha256=sha, size=size,
                      content_sha256=hashlib.sha256(listing).hexdigest(), package=package)
        write_file(run, 'l2-media.json',
                   json.dumps(dict(record, tool_version=version), sort_keys=True).encode(),
                   mode='create', forbid=run._identity[2])
        # Preserve old plans byte-for-byte when this API is not invoked.
        from .qemu import QemuConfig, _launch_plan
        from .images import ImageDescriptor
        plan = _launch_plan(QemuConfig(**plan['config']), ImageDescriptor(**plan['image']),
                            resource_path(run.directory, 'root.qcow2'), plan['uuid'], media=record)
        write_file(run, 'launch-plan.json', json.dumps(plan, sort_keys=True).encode(),
                   mode='replace', temporary='launch-plan.tmp', forbid=run._identity[2])
        event(state='ready', sha256=sha, size=size, content_sha256=record['content_sha256'])
        for name in ('l2-import.jsonl', 'l2-receipt.json', 'l2-package/job.env', 'l2-package/manifest.sha256'):
            write_file(run, name, b'', mode='create', forbid=run._identity[2])
        return record
    except BaseException as error:
        if registered:
            try:
                run.mark('quarantined', 'l2-media-attach-failed')
            except (OSError, ValueError):
                pass
        raise
