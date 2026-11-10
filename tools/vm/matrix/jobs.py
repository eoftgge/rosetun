"""One pre-staged infrastructure smoke job, owned by the original live Vm.

There is no package delivery, remote shell, controller restart or retry API.
"""

import base64
import hashlib
import json
import os
import re
import time
import uuid

from .lifecycle import _guest_serialized
from .report import _unique_object, _invalid_constant
from .resources import _identifier, resource_path

LAUNCHER = '/usr/local/libexec/rosetun-l2/launch'
SCHEMA = 'rosetun.infra-smoke.v1'


class JobError(ValueError):
    pass


def _uuid(value):
    if type(value) is not str or str(uuid.UUID(value)) != value or uuid.UUID(value).int == 0:
        raise JobError('invalid-job-uuid')
    return value


class SmokeJob:
    """Explicit opt-in; guest_run_id is an owner-supplied legacy ID, never truncated."""

    def __init__(self, vm, *, enabled=False, guest_run_id, manifest_sha256):
        vm._check()
        if enabled is not True or vm.qga is None:
            raise JobError('job-rpc-explicit-opt-in-required')
        if getattr(vm, '_smoke_job', None) is not None:
            raise JobError('one-job-per-live-vm')
        if (type(guest_run_id) is not str or
                not re.fullmatch(r'[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}', guest_run_id)):
            raise JobError('invalid-guest-run-id')
        if type(manifest_sha256) is not str or not re.fullmatch('[0-9a-f]{64}', manifest_sha256):
            raise JobError('invalid-job-manifest-digest')
        observation = vm.guest_observation
        if (not observation or observation['result'] != 'observed' or vm.reset_pending
                or observation['qga_session_id'] != vm.qga.session_id):
            raise JobError('fresh-guest-observation-required')
        identity = dict(host_run_id=_identifier(vm.run._identity[0]), guest_run_id=guest_run_id,
                             vm_uuid=_uuid(vm.vm_uuid), boot_id=_uuid(observation['boot_id']),
                             job_id='smoke', manifest_sha256=manifest_sha256)
        self._identity = tuple(identity.items())
        self.vm = vm
        self.submission = 'not-submitted'
        self.launcher = 'unknown'
        self.job = 'unknown'
        self.verification = 'UNVERIFIED'
        self.pid = self.session = None
        self.polls = self.calls = 0
        self.handles = {}
        self.deadline = time.monotonic() + 180
        if not vm._guest_lock.acquire(blocking=False):
            raise JobError('job-operation-in-progress')
        try:
            if getattr(vm, '_smoke_job', None) is not None:
                raise JobError('one-job-per-live-vm')
            vm._smoke_job = self
        finally:
            vm._guest_lock.release()
        self._evidence('created')

    @property
    def identity(self):
        return dict(self._identity)

    def _evidence(self, operation, **extra):
        vm = self.vm
        try:
            manifest = vm.run._read()
            if not any(r.get('kind') == 'file' and r.get('path') == 'job-evidence.jsonl'
                       for r in manifest['resources']):
                raise JobError('job-evidence-not-registered')
            row = dict(schema='rosetun.job-evidence.v1', identity=self.identity,
                       operation=operation, submission=self.submission, launcher=self.launcher,
                       job=self.job, verification=self.verification, calls=self.calls,
                       polls=self.polls, handles=self.handles, **extra)
            encoded = json.dumps(row, sort_keys=True)
            if vm.run._identity[2] in encoded:
                raise JobError('invalid-job-evidence')
            path = resource_path(vm.run.directory, 'job-evidence.jsonl')
            if path.stat().st_size + len(encoded.encode()) + 1 > 256 * 1024:
                raise JobError('job-evidence-size-limit')
            with path.open('a', encoding='utf-8') as stream:
                stream.write(encoded + '\n')
                stream.flush()
                os.fsync(stream.fileno())
            if os.name == 'posix':
                fd = os.open(vm.run.directory, os.O_RDONLY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
        except (OSError, ValueError):
            vm.evidence_failed = True
            raise JobError('job-evidence-write-failed') from None

    def _begin(self):
        vm = self.vm
        vm._check()
        if (vm.process.poll() is not None or not vm.qga.valid or vm.qga.closed
                or vm.reset_pending or vm.last_boot_id != self.identity['boot_id']):
            raise JobError('job-channel-or-boot-unverified')
        if time.monotonic() >= self.deadline:
            raise JobError('job-deadline')
        vm.qga.deadline = min(self.deadline, time.monotonic() + 10)

    def _rpc(self, name, arguments=None):
        # Leave one slot for a known handle's close; never raise session limits.
        if self.calls >= 64 or (self.calls >= 63 and name != 'guest-file-close'):
            raise JobError('job-rpc-budget')
        self.calls += 1
        return self.vm.qga._rpc(name, 5, arguments)

    @_guest_serialized
    def submit(self):
        # _guest_serialized expects the Vm lock, exposed below on this facade.
        if self.submission != 'not-submitted':
            raise JobError('job-already-attempted-inspect-only')
        self._begin()
        qga = self.vm.qga
        qga.jobs_enabled = True
        before = qga.calls
        qga.probe(5)
        self.calls += qga.calls - before
        self.submission = 'unknown'
        self.session = qga.session_id
        self._evidence('submit-intent')
        try:
            guest = self.identity['guest_run_id']
            value = self._rpc('guest-exec', {
                'path': LAUNCHER, 'arg': [guest, '/root/rosetun-l2-stage/' + guest,
                                        self.identity['manifest_sha256']], 'capture-output': False})
            if (type(value) is not dict or set(value) != {'pid'} or
                    type(value['pid']) is not int or not 0 < value['pid'] < 2**31):
                qga.invalidate()
                raise JobError('invalid-launcher-pid')
            self.pid = value['pid']
            self.submission = 'launcher-spawned'
            self.launcher = 'running'
        finally:
            self._evidence('submit-return', pid=self.pid, session_id=self.session)
        return self.snapshot()

    @property
    def _guest_lock(self):
        return self.vm._guest_lock

    def snapshot(self):
        return dict(identity=dict(self.identity), submission=self.submission, launcher=self.launcher,
                    job=self.job, verification=self.verification,
                    security_invariants='UNVERIFIED', release_gate=False)

    def _read(self, name):
        if name not in ('started', 'terminal', 'artifact'):
            raise JobError('unknown-job-file')
        suffix = 'artifact.txt' if name == 'artifact' else name + '.json'
        path = '/var/lib/rosetun-l2/' + self.identity['guest_run_id'] + '/report/smoke-' + suffix
        pending = self.vm.qga.session_id + ':open:' + str(self.calls)
        self.handles[pending] = 'unconfirmed'
        handle = self._rpc('guest-file-open', {'path': path, 'mode': 'r'})
        if type(handle) is not int or not 0 <= handle < 2**63:
            self.vm.qga.invalidate()
            raise JobError('invalid-job-handle')
        key = self.vm.qga.session_id + ':' + str(handle)
        self.handles[pending] = 'answered'
        self.handles[key] = 'open'
        try:
            data = bytearray()
            for _ in range(3):
                value = self._rpc('guest-file-read', {'handle': handle, 'count': 4096})
                if (type(value) is not dict or set(value) != {'count', 'eof', 'buf-b64'}
                        or type(value['count']) is not int or not 0 <= value['count'] <= 4096
                        or type(value['eof']) is not bool or type(value['buf-b64']) is not str
                        or len(value['buf-b64']) > 5464):
                    raise JobError('invalid-job-read')
                block = base64.b64decode(value['buf-b64'], validate=True)
                if (base64.b64encode(block).decode() != value['buf-b64'] or
                        len(block) != value['count'] or len(data) + len(block) > 4096):
                    raise JobError('invalid-job-read-size')
                data.extend(block)
                if value['eof']:
                    self._evidence('file', file=name, data_b64=base64.b64encode(data).decode())
                    return bytes(data)
                if not block:
                    raise JobError('job-read-no-progress')
            raise JobError('job-read-limit')
        finally:
            self.handles[key] = 'close-unconfirmed'
            if self.vm.qga.valid:
                if self._rpc('guest-file-close', {'handle': handle}) != {}:
                    self.vm.qga.invalidate()
                    raise JobError('invalid-job-close')
                self.handles[key] = 'closed'

    def _record(self, name):
        value = json.loads(self._read(name).decode('utf-8'), object_pairs_hook=_unique_object,
                           parse_constant=_invalid_constant)
        if (type(value) is not dict or set(value) != set(self.identity) | {'schema', 'state', 'artifact_sha256'}
                or value['schema'] != SCHEMA or any(value[k] != v for k, v in self.identity.items())):
            raise JobError('job-result-identity-or-schema')
        states = ('started',) if name == 'started' else ('succeeded', 'error', 'timeout')
        if value['state'] not in states:
            raise JobError('invalid-job-state')
        digest = value['artifact_sha256']
        if (type(digest) is not str or (not re.fullmatch('[0-9a-f]{64}', digest)
                                      if value['state'] == 'succeeded' else digest != '')):
            raise JobError('invalid-job-artifact-digest')
        return value

    def _poll(self, terminal):
        self.verification = 'UNVERIFIED'
        try:
            self._begin()
            if self.submission == 'not-submitted':
                raise JobError('job-not-submitted')
            if self.polls >= 12:
                raise JobError('job-poll-limit')
            self.polls += 1
            if self.session != self.vm.qga.session_id and self.launcher == 'running':
                self.launcher = 'unknown-after-recovery'
            if (self.pid is not None and self.session == self.vm.qga.session_id
                    and self.launcher == 'running'):
                value = self._rpc('guest-exec-status', {'pid': self.pid})
                if type(value) is not dict or type(value.get('exited')) is not bool:
                    raise JobError('invalid-launcher-status')
                if value['exited']:
                    if (set(value) != {'exited', 'exitcode'} or type(value['exitcode']) is not int):
                        raise JobError('invalid-launcher-exit')
                    self.launcher = 'exited-zero' if value['exitcode'] == 0 else 'exited-error'
            record = self._record('terminal' if terminal else 'started')
            self.job = record['state']
            if terminal:
                if self.job == 'succeeded':
                    artifact = self._read('artifact')
                    if hashlib.sha256(artifact).hexdigest() != record['artifact_sha256']:
                        raise JobError('job-artifact-hash-mismatch')
                self.verification = 'VERIFIED'
        except (OSError, ValueError, UnicodeError, RecursionError):
            self._evidence('collect-unverified')
            raise JobError('job-result-UNVERIFIED') from None
        self._evidence('collect' if terminal else 'inspect')
        return self.snapshot()

    @_guest_serialized
    def inspect(self):
        """Read the saved started marker; no absence inference and no waiting loop."""
        return self._poll(False)

    @_guest_serialized
    def collect(self):
        """Read terminal result and artifact, retaining every guest file."""
        return self._poll(True)
