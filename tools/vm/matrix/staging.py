"""One bounded smoke delivery, retained by the original live controller only."""

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import time

from .jobs import SmokeJob, JobError, _uuid
from .lifecycle import _guest_serialized
from .resources import _identifier, _regular_file, resource_path
from .report import _unique_object, _invalid_constant

HELPER = '/usr/local/libexec/rosetun-l2/stage-smoke'
ROOT = '/root/rosetun-l2-stage'
PAYLOAD = ('guest/launch.sh', 'guest/start.sh', 'guest/lib.sh', 'guest/run-smoke.sh', 'job.env')
FILES = PAYLOAD + ('manifest.sha256',)
FILE_LIMIT = 24 * 1024
TOTAL_LIMIT = 64 * 1024
BLOCK = 8192
RPC_LIMIT = 48
WIRE_LIMIT = 96 * 1024


def _read_source(path):
    _regular_file(path)
    before = path.stat()
    if not 0 < before.st_size <= FILE_LIMIT:
        raise JobError('staging-source-size')
    with path.open('rb') as stream:
        opened = os.fstat(stream.fileno())
        data = stream.read(FILE_LIMIT + 1)
        after = os.fstat(stream.fileno())
    _regular_file(path)
    def identity(s):
        return s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns
    if not identity(before) == identity(opened) == identity(after) == identity(path.stat()):
        raise JobError('staging-source-changed')
    if len(data) != before.st_size or b'\r' in data or not data.endswith(b'\n'):
        raise JobError('staging-source-requires-lf')
    data.decode('utf-8', errors='strict')
    return data


class SmokePackage:
    """Build once; stage once; after uncertainty only receipt inspection is allowed."""

    def __init__(self):
        raise TypeError('use SmokePackage.build')

    @classmethod
    def build(cls, vm, *, checkout, guest_run_id, attempt_id, delay_seconds=0, enabled=False):
        if enabled is not True:
            raise JobError('staging-explicit-opt-in-required')
        obj = object.__new__(cls)
        obj.vm = vm
        return obj._build(checkout, guest_run_id, attempt_id, delay_seconds)

    @property
    def _guest_lock(self):
        return self.vm._guest_lock

    @property
    def identity(self):
        return dict(self._identity)

    @_guest_serialized
    def _build(self, checkout, guest, attempt, delay):
        vm = self.vm
        vm._check()
        if (vm.run._read()['state'] != 'running' or vm.qga is None or
                getattr(vm, '_smoke_package', None) is not None or
                getattr(vm, '_smoke_job', None) is not None or
                getattr(vm, '_linux_l2_job', None) is not None):
            raise JobError('one-staging-attempt-per-live-vm')
        if type(guest) is not str or not re.fullmatch(r'[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}', guest):
            raise JobError('invalid-guest-run-id')
        if type(attempt) is not str or not re.fullmatch('[0-9a-f]{32}', attempt):
            raise JobError('invalid-staging-attempt')
        if type(delay) is not int or not 0 <= delay <= 30:
            raise JobError('invalid-smoke-delay')
        observation = vm.guest_observation
        if (not observation or observation['result'] != 'observed' or vm.reset_pending or
                observation['qga_session_id'] != vm.qga.session_id or not vm.qga.valid):
            raise JobError('fresh-guest-observation-required')
        identity = dict(host_run_id=_identifier(vm.run._identity[0]), guest_run_id=guest,
                        vm_uuid=_uuid(vm.vm_uuid), boot_id=_uuid(observation['boot_id']),
                        attempt_id=attempt)
        checkout = Path(checkout)
        if not checkout.is_absolute() or '..' in checkout.parts:
            raise JobError('explicit-absolute-checkout-required')
        files = [(name, _read_source(checkout / 'tools/vm/linux' / name)) for name in PAYLOAD[:-1]]
        env = (f'PROFILE=infra-smoke-v1\nHOST_RUN_ID={identity["host_run_id"]}\nRUN_ID={guest}\n'
               f'VM_UUID={identity["vm_uuid"]}\nEXPECTED_BOOT_ID={identity["boot_id"]}\n'
               f'JOB_ID=smoke\nDELAY_SECONDS={delay}\n').encode('ascii')
        files.append(('job.env', env))
        manifest = ''.join(hashlib.sha256(data).hexdigest() + '  ' + name + '\n'
                           for name, data in files).encode('ascii')
        files.append(('manifest.sha256', manifest))
        if sum(len(data) for _, data in files) > TOTAL_LIMIT:
            raise JobError('staging-package-size')
        identity['manifest_sha256'] = hashlib.sha256(manifest).hexdigest()
        self._identity = tuple(identity.items())
        self._files = tuple(files)
        self.calls = self.wire_bytes = 0
        self.recoveries = vm.qga_recoveries
        self.handles = {}
        self.state = 'built'
        self.deadline = time.monotonic() + 180
        self.receipt_verified = False
        registered = {r.get('path') for r in vm.run._read()['resources'] if r['kind'] == 'file'}
        names = FILES + ('digest.sha256', 'staging.jsonl')
        if any('smoke-package/' + name not in registered for name in names):
            raise JobError('staging-resources-not-reserved')
        vm._smoke_package = self
        try:
            for name, data in (*files, ('digest.sha256', (identity['manifest_sha256'] + '\n').encode())):
                path = resource_path(vm.run.directory, 'smoke-package/' + name)
                _regular_file(path)
                if path.stat().st_size:
                    raise JobError('staging-local-destination-exists')
                with path.open('r+b') as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
            self._evidence('built')
            if os.name == 'posix':
                for directory in ('smoke-package/guest', 'smoke-package'):
                    fd = os.open(resource_path(vm.run.directory, directory), os.O_RDONLY)
                    try:
                        os.fsync(fd)
                    finally:
                        os.close(fd)
        except BaseException:
            vm.evidence_failed = True
            raise
        return self

    def _evidence(self, operation, **extra):
        try:
            self.vm.run._read()
            path = resource_path(self.vm.run.directory, 'smoke-package/staging.jsonl')
            _regular_file(path)
            row = dict(identity=self.identity, operation=operation, state=self.state,
                       calls=self.calls, wire_bytes=self.wire_bytes, handles=self.handles, **extra)
            raw = (json.dumps(row, sort_keys=True) + '\n').encode('ascii')
            if self.vm.run._identity[2].encode() in raw or path.stat().st_size + len(raw) > 65536:
                raise JobError('staging-evidence-limit')
            with path.open('ab') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            if os.name == 'posix':
                fd = os.open(path.parent, os.O_RDONLY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
        except (OSError, ValueError):
            self.vm.evidence_failed = True
            raise JobError('staging-evidence-failed') from None

    def _begin(self):
        vm = self.vm
        vm._check()
        # Charge each replacement: delimited sync, probe (2), boot read (3).
        self.calls += 6 * (vm.qga_recoveries - self.recoveries)
        self.recoveries = vm.qga_recoveries
        if self.calls >= RPC_LIMIT:
            raise JobError('staging-rpc-budget')
        observation = vm.guest_observation
        if (vm.evidence_failed or vm.process.poll() is not None or not vm.qga.valid or vm.qga.closed or vm.reset_pending or
                vm.vm_uuid != self.identity['vm_uuid'] or vm.last_boot_id != self.identity['boot_id'] or
                not observation or observation['qga_session_id'] != vm.qga.session_id or
                observation['boot_id'] != self.identity['boot_id']):
            raise JobError('staging-vm-or-boot-unverified')
        if time.monotonic() >= self.deadline:
            raise JobError('staging-deadline')
        vm.qga.deadline = self.deadline

    def _rpc(self, name, arguments):
        if self.calls >= RPC_LIMIT or (self.calls >= RPC_LIMIT - 1 and name != 'guest-file-close'):
            raise JobError('staging-rpc-budget')
        self.calls += 1
        return self.vm.qga._rpc(name, 5, arguments)

    def _helper(self, operation):
        args = [operation] + [self.identity[k] for k in
                              ('host_run_id', 'guest_run_id', 'vm_uuid', 'boot_id',
                               'attempt_id', 'manifest_sha256')]
        self._evidence(operation + '-intent')
        value = self._rpc('guest-exec', {'path': HELPER, 'arg': args, 'capture-output': False})
        if type(value) is not dict or set(value) != {'pid'} or type(value['pid']) is not int or not 0 < value['pid'] < 2**31:
            raise JobError('invalid-staging-helper-pid')
        for poll in range(4):
            if poll:
                time.sleep(min(1, max(0, self.deadline - time.monotonic())))
            status = self._rpc('guest-exec-status', {'pid': value['pid']})
            if type(status) is not dict or type(status.get('exited')) is not bool:
                raise JobError('invalid-staging-helper-status')
            if status['exited']:
                if set(status) != {'exited', 'exitcode'} or type(status['exitcode']) is not int or status['exitcode'] != 0:
                    raise JobError('staging-helper-failed')
                return
        raise JobError('staging-helper-unconfirmed')

    def _file(self, path, data=None):
        pending = self.vm.qga.session_id + ':open:' + str(self.calls)
        self.handles[pending] = 'unconfirmed'
        self._evidence('open-intent')
        handle = self._rpc('guest-file-open', {'path': path, 'mode': 'r' if data is None else 'w'})
        if type(handle) is not int or not 0 <= handle < 2**63:
            raise JobError('invalid-staging-handle')
        self.handles[pending] = 'answered'
        key = self.vm.qga.session_id + ':' + str(handle)
        self.handles[key] = 'open'
        try:
            if data is None:
                value = self._rpc('guest-file-read', {'handle': handle, 'count': 4096})
                if (type(value) is not dict or set(value) != {'count', 'eof', 'buf-b64'} or
                        type(value['count']) is not int or not 0 < value['count'] <= 4096 or
                        value['eof'] is not True or type(value['buf-b64']) is not str or
                        len(value['buf-b64']) > 5464):
                    raise JobError('invalid-staging-receipt-read')
                raw = base64.b64decode(value['buf-b64'], validate=True)
                if len(raw) != value['count'] or base64.b64encode(raw).decode() != value['buf-b64']:
                    raise JobError('invalid-staging-receipt-count')
                return raw
            for offset in range(0, len(data), BLOCK):
                block = data[offset:offset + BLOCK]
                encoded = base64.b64encode(block).decode('ascii')
                self.wire_bytes += len(encoded)
                if self.wire_bytes > WIRE_LIMIT:
                    raise JobError('staging-byte-budget')
                value = self._rpc('guest-file-write', {'handle': handle, 'buf-b64': encoded, 'count': len(block)})
                # A confirmed short write is retained and rejected, never retried.
                if (type(value) is not dict or set(value) != {'count', 'eof'} or
                        type(value['count']) is not int or value['count'] != len(block) or
                        type(value['eof']) is not bool or value['eof']):
                    raise JobError('staging-write-count-or-eof')
        finally:
            self.handles[key] = 'close-unconfirmed'
            if self.vm.qga.valid and not self.vm.qga.closed:
                if self._rpc('guest-file-close', {'handle': handle}) != {}:
                    self.vm.qga.invalidate()
                    raise JobError('invalid-staging-close')
                self.handles[key] = 'closed'

    def _receipt(self):
        path = ROOT + '/.attempt-' + self.identity['attempt_id'] + '/ready.json'
        raw = self._file(path)
        value = json.loads(raw.decode('ascii'), object_pairs_hook=_unique_object,
                           parse_constant=_invalid_constant)
        expected = dict(self.identity, schema='rosetun.smoke-stage.v1', state='ready')
        if value != expected:
            raise JobError('staging-receipt-mismatch')
        self._evidence('receipt', receipt_b64=base64.b64encode(raw).decode())
        self.receipt_verified = True
        self.state = 'ready'
        try:
            self._evidence('ready')
        except BaseException:
            self.receipt_verified = False
            self.state = 'unknown'
            raise
        return dict(value)

    @_guest_serialized
    def stage(self):
        if self.state != 'built':
            raise JobError('staging-already-attempted-inspect-only')
        self._begin()
        # 48 delivery + 64 job + up to 16 prior observation RPCs fit 128.
        if self.vm.qga.calls > 16:
            raise JobError('insufficient-qga-session-budget')
        self.state = 'unknown'
        self._evidence('stage-intent')
        try:
            qga = self.vm.qga
            qga.staging_enabled = True
            before = qga.calls
            try:
                qga.probe(5)
            finally:
                self.calls += qga.calls - before
            self._helper('create')
            prefix = ROOT + '/.attempt-' + self.identity['attempt_id'] + '/package/'
            for name, data in self._files:
                self._file(prefix + name, data)
            self._helper('finalize')
            return self._receipt()
        finally:
            self._evidence('stage-return')

    @_guest_serialized
    def check_receipt(self):
        """After explicit recovery, inspect only; never repeat create/write/finalize."""
        if self.state == 'built':
            raise JobError('staging-not-attempted')
        self._begin()
        self.receipt_verified = False
        self.state = 'unknown'
        try:
            return self._receipt()
        finally:
            self._evidence('receipt-return')

    def smoke_job(self, *, enabled=False):
        """Construct the existing job only after a verified finalized receipt."""
        self._begin()
        if not self.receipt_verified or self.state != 'ready':
            raise JobError('staging-not-ready')
        return SmokeJob(self.vm, enabled=enabled, guest_run_id=self.identity['guest_run_id'],
                        manifest_sha256=self.identity['manifest_sha256'])
