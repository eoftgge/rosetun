"""Strict legacy L2 package validation and one live QGA execution."""

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

from .catalog import digest, parse_catalog
from .config import make_plan, validate_plan
from .jobs import JobError, LAUNCHER, SmokeJob, _uuid
from .lifecycle import _guest_serialized
from .report import assess, _unique_object, _invalid_constant
from .resources import _identifier, _no_links, _regular_file, resource_path

BINARIES = ('l2_transport_fixture', 'rosetun_helper_privileged_tests', 'rosetun_ipc_tests')
SOURCES = ('guest/launch.sh', 'guest/start.sh', 'guest/lib.sh', 'guest/run-l2.sh', 'scenarios.tsv')
PAYLOAD = SOURCES + ('job.env',) + tuple('artifacts/' + n for n in BINARIES) + ('artifacts/provenance.json',)
FILES = PAYLOAD + ('manifest.sha256',)
BLOCK = 32768
REPORT_LIMIT = 256 * 1024
POLLS = 4
EVIDENCE_FILES = ('plan.json', 'package.json', 'assessment.json') + tuple(
    f'{i}/{name}.json' for i in range(1, POLLS + 1)
    for name in ('status', 'report', 'status-after'))


def _json(raw):
    value = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique_object,
                       parse_constant=_invalid_constant)
    if type(value) is not dict:
        raise JobError('l2-json-object-required')
    return value


def _hash(path, limit):
    _regular_file(path)
    before = path.stat()
    if not 0 < before.st_size <= limit:
        raise JobError('l2-package-file-size')
    result = hashlib.sha256()
    count = 0
    header = b''
    with path.open('rb') as stream:
        opened = os.fstat(stream.fileno())
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            if not header:
                header = block[:20]
            count += len(block)
            if count > limit:
                raise JobError('l2-package-file-size')
            result.update(block)
        after = os.fstat(stream.fileno())
    _regular_file(path)
    def key(s):
        return s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns
    if not key(before) == key(opened) == key(after) == key(path.stat()):
        raise JobError('l2-package-file-changed')
    return result.hexdigest(), before.st_size, header


def source_identity(checkout):
    """Match the legacy build's recorded status/diff digest, not an attestation."""
    checkout = Path(checkout)
    def git(*args):
        value = subprocess.run(['git', '-c', 'safe.directory=' + checkout.as_posix(), '-C',
                                str(checkout), *args], capture_output=True, timeout=60,
                               check=True).stdout
        return value.replace(b'\r\n', b'\n')
    sha = git('rev-parse', 'HEAD').decode('ascii').strip()
    status = git('status', '--porcelain=v1', '-uall', '--no-renames')
    diff = git('diff', 'HEAD', '--binary', '--no-ext-diff')
    return dict(source_sha=sha, source_dirty=bool(status.strip()),
                source_dirty_digest=hashlib.sha256(status + b'\n--\n' + diff).hexdigest())


def validate_package(directory, *, checkout, immutable=False, check_source=True):
    """Stream hash existing binaries; reject any extra file, directory or link."""
    root, checkout = Path(directory), Path(checkout)
    for path in (root, checkout):
        if not path.is_absolute() or '..' in path.parts:
            raise JobError('l2-absolute-path-required')
        _no_links(path)
    files = tuple(n for n in PAYLOAD if n != "job.env") if immutable else FILES
    found = set()
    for parent, dirs, names in os.walk(root, followlinks=False):
        for name in dirs + names:
            path = Path(parent) / name
            _no_links(path)
            found.add(path.relative_to(root).as_posix())
    if found != set(files) | {'guest', 'artifacts'}:
        raise JobError('l2-package-composition')
    hashes, sizes, headers = {}, {}, {}
    for name in files:
        limit = 512 * 1024 * 1024 if name.startswith('artifacts/') and name != 'artifacts/provenance.json' else 256 * 1024
        hashes[name], sizes[name], headers[name] = _hash(root / name, limit)
    small = {}
    for name in files:
        if name in tuple('artifacts/' + n for n in BINARIES):
            continue
        _regular_file(root / name)
        with (root / name).open('rb') as stream:
            raw = stream.read(256 * 1024 + 1)
        if len(raw) != sizes[name] or hashlib.sha256(raw).hexdigest() != hashes[name]:
            raise JobError('l2-package-file-changed')
        small[name] = raw
    for name in (() if immutable else ('manifest.sha256', 'job.env')):
        if b'\r' in small[name] or not small[name].endswith(b'\n'):
            raise JobError('l2-package-requires-lf')
    for name in SOURCES:
        path = checkout / 'tools/vm/linux' / name
        _regular_file(path)
        with path.open('rb') as stream:
            raw = stream.read(256 * 1024 + 1)
        if len(raw) > 256 * 1024:
            raise JobError('l2-checkout-file-size')
        raw = raw.replace(b'\r\n', b'\n').rstrip(b'\n') + b'\n'
        if hashlib.sha256(raw).hexdigest() != hashes[name]:
            raise JobError('l2-checkout-script-or-catalog-mismatch')
    if not immutable:
        manifest = {}
        for line in small['manifest.sha256'].decode('ascii').splitlines():
            match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
            if not match or match[2] not in PAYLOAD or match[2] in manifest:
                raise JobError('l2-invalid-manifest')
            manifest[match[2]] = match[1]
        if manifest != {name: hashes[name] for name in PAYLOAD}:
            raise JobError('l2-manifest-mismatch')
    provenance = _json(small['artifacts/provenance.json'])
    if (type(provenance.get('schema')) is not int or provenance['schema'] != 1 or
            provenance.get('target') != 'x86_64-unknown-linux-gnu' or
            provenance.get('stage', 'l2') != 'l2'):
        raise JobError('l2-provenance-target')
    source = source_identity(checkout) if check_source else {
        k: provenance.get(k) for k in ('source_sha', 'source_dirty', 'source_dirty_digest')}
    if (not re.fullmatch('[0-9a-f]{40}', source['source_sha']) or
            type(provenance.get('source_dirty')) is not bool or
            any(provenance.get(k) != v for k, v in source.items())):
        raise JobError('l2-provenance-checkout-mismatch')
    for name in BINARIES:
        head = headers['artifacts/' + name]
        if (len(head) != 20 or head[:6] != b'\x7fELF\x02\x01' or
                head[16:18] not in (b'\x02\x00', b'\x03\x00') or head[18:20] != b'\x3e\x00'):
            raise JobError('l2-artifact-not-x86-64-elf')
        artifacts = provenance.get('artifacts')
        entry = artifacts.get(name) if type(artifacts) is dict else None
        if type(entry) is not dict or entry.get('sha256') != hashes['artifacts/' + name]:
            raise JobError('l2-provenance-artifact-hash')
    env = {} if immutable else validate_env(small["job.env"])
    rows = parse_catalog(small['scenarios.tsv'].decode('utf-8-sig'))
    return dict(env=env, hashes=hashes, sizes=sizes, source=source, catalog=rows,
                catalog_digest=digest(rows), provenance=provenance,
                origin='recorded-checkout-match; not cryptographic proof of build origin')


def validate_env(raw):
    env = {}
    for line in raw.decode('ascii').splitlines():
        match = re.fullmatch(r'([A-Z_]+)=([A-Za-z0-9._:@/+=-]+)', line)
        if not match or match[1] in env:
            raise JobError('l2-invalid-job-env')
        env[match[1]] = match[2]
    if set(env) != set('RUN_ID STAND_ID EXPECTED_BOOT_ID USER_A USER_B BIOS_GUID SCENARIO_TIMEOUT_SECONDS UNIT_TIMEOUT_SECONDS JOB_TIMEOUT_SECONDS'.split()):
        raise JobError('l2-job-env-fields')
    if not re.fullmatch(r'[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}', env['RUN_ID']):
        raise JobError('l2-guest-run-id')
    _uuid(env['EXPECTED_BOOT_ID'])
    _uuid(env['BIOS_GUID'])
    _identifier(env['STAND_ID'])
    if (any(not re.fullmatch('[a-z_][a-z0-9_-]{0,31}', env[k]) for k in ('USER_A', 'USER_B'))
            or env['USER_A'] == env['USER_B']):
        raise JobError('l2-accounts')
    for key in ('SCENARIO_TIMEOUT_SECONDS', 'UNIT_TIMEOUT_SECONDS', 'JOB_TIMEOUT_SECONDS'):
        if not env[key].isdigit() or not 10 <= int(env[key]) <= 86400:
            raise JobError('l2-timeout-range')
    # Limit this first execution API to the legacy CLI's maximum job duration.
    if not 60 <= int(env['JOB_TIMEOUT_SECONDS']) <= 7200:
        raise JobError('l2-job-timeout-range')
    return env


class LinuxL2Job:
    """One installed launcher attempt; explicit channel recovery permits collection only."""

    _evidence = SmokeJob._evidence

    def __init__(self, vm, *, package_directory, checkout, enabled=False):
        self.vm = vm
        self._create(package_directory, checkout, enabled)

    @property
    def _guest_lock(self):
        return self.vm._guest_lock

    @property
    def identity(self):
        return dict(self._identity)

    @property
    def plan(self):
        return _json(self._plan)

    @_guest_serialized
    def _create(self, directory, checkout, enabled):
        vm = self.vm
        vm._check()
        if (enabled is not True or vm.qga is None or
                any(getattr(vm, k, None) is not None for k in ('_linux_l2_job', '_smoke_job', '_smoke_package'))):
            raise JobError('l2-opt-in-and-unused-vm-required')
        delivery = getattr(vm, '_l2_import', None)
        if delivery is not None:
            delivery.require_ready()
        elif getattr(vm, '_l2_media', None) is not None:
            raise JobError('l2-media-requires-import-receipt')
        package = validate_package(directory, checkout=checkout)
        if delivery is not None and package['hashes']['manifest.sha256'] != delivery.identity['manifest_sha256']:
            raise JobError('l2-import-package-mismatch')
        env = package['env']
        observation = vm.guest_observation
        if (not observation or observation['result'] != 'observed' or vm.reset_pending or
                observation['qga_session_id'] != vm.qga.session_id or not vm.qga.valid or
                observation['boot_id'] != env['EXPECTED_BOOT_ID'] or vm.vm_uuid != env['BIOS_GUID'] or
                vm.run._identity[1] != env['STAND_ID']):
            raise JobError('l2-package-vm-or-boot-mismatch')
        identity = dict(host_run_id=_identifier(vm.run._identity[0]), guest_run_id=env['RUN_ID'],
                        stand_id=env['STAND_ID'], vm_uuid=_uuid(vm.vm_uuid),
                        boot_id=_uuid(observation['boot_id']), job_id='linux-l2',
                        manifest_sha256=package['hashes']['manifest.sha256'])
        self._identity = tuple(identity.items())
        plan = make_plan('linux-l2', 'prepared-l2', dict(mode='exploratory',
                         run_id=env['RUN_ID'], boot_id=identity['boot_id']))
        plan.update(catalog=package['catalog'], catalog_digest=package['catalog_digest'])
        validate_plan(plan)
        self._plan = json.dumps(plan, sort_keys=True).encode()
        self.submission = 'not-submitted'
        self.launcher = self.job = 'unknown'
        self.verification = 'UNVERIFIED'
        self.pid = self.session = None
        self.calls = self.polls = 0
        self.handles = {}
        self.assessment = None
        self.deadline = time.monotonic() + int(env['JOB_TIMEOUT_SECONDS']) + 180
        vm._linux_l2_job = self
        self._save('plan.json', self._plan)
        self._save('package.json', json.dumps(dict(package, identity=identity), sort_keys=True).encode())
        self._evidence('l2-created')

    def _save(self, name, data):
        relative = 'linux-l2/' + name
        try:
            if not any(r.get('kind') == 'file' and r.get('path') == relative
                       for r in self.vm.run._read()['resources']):
                raise JobError('l2-evidence-not-registered')
            path = resource_path(self.vm.run.directory, relative)
            with path.open('wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        except (OSError, ValueError):
            self.vm.evidence_failed = True
            raise JobError('l2-evidence-write-failed') from None

    def _begin(self):
        vm = self.vm
        vm._check()
        if (vm.process.poll() is not None or not vm.qga.valid or vm.qga.closed or
                vm.reset_pending or vm.last_boot_id != self.identity['boot_id']):
            raise JobError('l2-channel-or-boot-unverified')
        if time.monotonic() >= self.deadline:
            raise JobError('l2-job-deadline')
        vm.qga.deadline = min(self.deadline, time.monotonic() + 60)

    def _rpc(self, name, args):
        self._begin()
        if self.calls >= 112 or (self.calls >= 111 and name != 'guest-file-close'):
            raise JobError('l2-rpc-budget')
        self.calls += 1
        return self.vm.qga._rpc(name, 5, args)

    def _fresh_boot(self):
        self._begin()
        qga = self.vm.qga
        before = qga.calls
        if self.calls >= 111:
            raise JobError('l2-rpc-budget')
        previous_limit = qga._operation_limit
        qga._operation_limit = min(previous_limit, before + 112 - self.calls)
        try:
            qga.jobs_enabled = True
            qga.probe(5)
            if qga.read_boot_id(5) != self.identity['boot_id']:
                raise JobError('l2-boot-changed')
        finally:
            self.calls += qga.calls - before
            qga._operation_limit = previous_limit

    @_guest_serialized
    def submit(self):
        if self.submission != 'not-submitted':
            raise JobError('l2-already-attempted-inspect-only')
        delivery = getattr(self.vm, '_l2_import', None)
        if delivery is not None:
            delivery.require_ready()
        self._fresh_boot()
        self.submission = 'unknown'
        self.session = self.vm.qga.session_id
        self._evidence('l2-submit-intent')
        try:
            guest = self.identity['guest_run_id']
            value = self._rpc('guest-exec', dict(path=LAUNCHER,
                arg=[guest, '/root/rosetun-l2-stage/' + guest, self.identity['manifest_sha256']],
                **{'capture-output': False}))
            if type(value) is not dict or set(value) != {'pid'} or type(value['pid']) is not int or not 0 < value['pid'] < 2**31:
                self.vm.qga.invalidate()
                raise JobError('l2-invalid-launcher-pid')
            self.pid = value['pid']
            self.submission, self.launcher = 'launcher-spawned', 'running'
        finally:
            self._evidence('l2-submit-return', pid=self.pid, session_id=self.session)
        return self.snapshot()

    def _read(self, name):
        if name not in ('status', 'report', 'status-after'):
            raise JobError('l2-unknown-result-file')
        suffix = 'report.json' if name == 'report' else 'status.json'
        path = '/var/lib/rosetun-l2/' + self.identity['guest_run_id'] + '/report/' + suffix
        pending = self.vm.qga.session_id + ':open:' + str(self.calls)
        self.handles[pending] = 'unconfirmed'
        self._evidence('l2-open-intent', file=name)
        handle = self._rpc('guest-file-open', dict(path=path, mode='r'))
        if type(handle) is not int or not 0 <= handle < 2**63:
            self.vm.qga.invalidate()
            raise JobError('l2-invalid-handle')
        self.handles[pending] = 'answered'
        key = self.vm.qga.session_id + ':' + str(handle)
        self.handles[key] = 'open'
        data, complete = bytearray(), False
        limit = REPORT_LIMIT if name == 'report' else 8192
        try:
            for _ in range(limit // BLOCK + 2):
                requested = min(BLOCK, limit - len(data) + 1)
                value = self._rpc('guest-file-read', dict(handle=handle, count=requested))
                if (type(value) is not dict or set(value) != {'count', 'eof', 'buf-b64'} or
                        type(value['count']) is not int or not 0 <= value['count'] <= requested or
                        type(value['eof']) is not bool or type(value['buf-b64']) is not str or
                        len(value['buf-b64']) > 4 * ((BLOCK + 2) // 3)):
                    raise JobError('l2-invalid-read')
                block = base64.b64decode(value['buf-b64'], validate=True)
                if base64.b64encode(block).decode() != value['buf-b64'] or len(block) != value['count']:
                    raise JobError('l2-invalid-read-count')
                # One extra byte distinguishes an exact-size file from overflow.
                data.extend(block)
                if len(data) > limit:
                    raise JobError('l2-result-size-limit')
                if value['eof']:
                    complete = True
                    return bytes(data)
                if not block:
                    raise JobError('l2-read-no-progress')
            raise JobError('l2-read-block-limit')
        finally:
            try:
                self._save(f'{self.polls}/{name}.json', data)
                self._evidence('l2-file', file=name, complete=complete, size=len(data),
                               sha256=hashlib.sha256(data).hexdigest())
            finally:
                self.handles[key] = 'close-unconfirmed'
                if self.vm.qga.valid:
                    if self._rpc('guest-file-close', dict(handle=handle)) != {}:
                        self.vm.qga.invalidate()
                        raise JobError('l2-invalid-close')
                    self.handles[key] = 'closed'

    @_guest_serialized
    def collect(self):
        self.verification = 'UNVERIFIED'
        self.assessment = None
        try:
            if self.submission == 'not-submitted' or self.polls >= POLLS:
                raise JobError('l2-not-submitted-or-poll-limit')
            self.polls += 1
            self._fresh_boot()
            if self.session != self.vm.qga.session_id:
                if self.launcher in ('running', 'unknown'):
                    self.launcher = 'unknown-after-recovery'
            elif self.pid is not None and self.launcher == 'running':
                value = self._rpc('guest-exec-status', dict(pid=self.pid))
                if type(value) is not dict or type(value.get('exited')) is not bool:
                    raise JobError('l2-invalid-exec-status')
                if value['exited']:
                    if set(value) != {'exited', 'exitcode'} or type(value['exitcode']) is not int:
                        raise JobError('l2-invalid-exec-exit')
                    self.launcher = 'exited-zero' if value['exitcode'] == 0 else 'exited-error'
            raw_status = self._read('status')
            status = _json(raw_status)
            self.job = status.get('state', 'unknown')
            if (self.job != 'finished' or status.get('run_id') != self.identity['guest_run_id'] or
                    status.get('boot_id') != self.identity['boot_id']):
                raise JobError('l2-not-finished-or-foreign-status')
            raw_report = self._read('report')
            if self._read('status-after') != raw_status:
                raise JobError('l2-results-changed')
            self._fresh_boot()
            result = assess(_json(raw_report), status, self.plan)
            self._save('assessment.json', json.dumps(result, sort_keys=True).encode())
            self.assessment = result
            self.verification = result['validation']['status']
        except (OSError, ValueError, UnicodeError, RecursionError):
            self._evidence('l2-collect-unverified')
            raise JobError('l2-result-UNVERIFIED') from None
        self._evidence('l2-collected')
        return self.snapshot()

    def snapshot(self):
        return dict(identity=self.identity, submission=self.submission, launcher=self.launcher,
                    job=self.job, verification=self.verification, assessment=self.assessment,
                    accepted=bool(self.assessment and self.verification == 'PASS' and
                                  self.launcher != 'exited-error' and
                                  self.assessment['acceptance']['accepted']),
                    security_invariants='UNVERIFIED', release_gate=False)
