"""One irreversible media import attempt, retained by the original live Vm."""

import base64
import hashlib
import json
import re
import time

from . import linux_l2 as l2
from .evidence import append_row
from .jobs import JobError, _uuid
from .lifecycle import _guest_serialized
from .resources import _identifier, resource_path
from .staging import SmokePackage
from .l2_media import manifest

HELPER = '/usr/local/libexec/rosetun-l2/stage-l2'


class L2Import:
    _file = SmokePackage._file

    @property
    def _guest_lock(self):
        return self.vm._guest_lock

    @property
    def identity(self):
        return dict(self._identity)

    def __init__(self, vm, *, guest_run_id, import_id, user_a, user_b,
                 scenario_timeout=30, unit_timeout=180, job_timeout=900, enabled=False, l3=None):
        self.vm = vm
        self._create(guest_run_id, import_id, user_a, user_b, scenario_timeout,
                     unit_timeout, job_timeout, enabled, l3)

    @_guest_serialized
    def _create(self, guest, attempt, user_a, user_b, scenario, unit, job, enabled, l3):
        vm = self.vm
        vm._check()
        if (enabled is not True or vm.qga is None or not getattr(vm, '_l2_media', None) or
                any(getattr(vm, n, None) is not None for n in
                    ('_l2_import', '_linux_l2_job', '_smoke_job', '_smoke_package'))):
            raise JobError('l2-import-requires-unused-media-vm')
        observation = vm.guest_observation
        if (not observation or observation['result'] != 'observed' or vm.reset_pending or
                observation['qga_session_id'] != vm.qga.session_id or not vm.qga.valid):
            raise JobError('l2-import-requires-observed-boot')
        if not re.fullmatch('[0-9a-f]{32}', attempt):
            raise JobError('invalid-l2-import-id')
        media = vm._l2_media
        # The media record names its stage; the L3 block must accompany an L3 media and only that.
        profile = l2.profile_of(media['package'].get('profile', 'l2'))
        if (profile.name == 'l3') != (l3 is not None):
            raise JobError('l2-import-profile-mismatch')
        env = dict(RUN_ID=guest, STAND_ID=_identifier(vm.run._identity[1]),
                   EXPECTED_BOOT_ID=_uuid(observation['boot_id']), USER_A=user_a, USER_B=user_b,
                   BIOS_GUID=_uuid(vm.vm_uuid), SCENARIO_TIMEOUT_SECONDS=str(scenario),
                   UNIT_TIMEOUT_SECONDS=str(unit), JOB_TIMEOUT_SECONDS=str(job))
        if l3 is not None:
            env.update(HOST_ADDRESS=l3['host_address'], NODE_PORT=str(l3['node_port']),
                       PROBE_ADDRESS=l3['probe_address'], DNS_PROBE_ADDRESS=l3['dns_probe_address'])
            # Only inside the lab, and last: the importer in the image takes it in that place.
            if l3.get('lab_marker_address') is not None:
                env['LAB_MARKER_ADDRESS'] = l3['lab_marker_address']
            self.l3 = dict(l3)
        raw_env = ''.join(k + '=' + v + '\n' for k, v in env.items()).encode('ascii')
        l2.validate_env(raw_env, profile.name)
        hashes = dict(media['package']['hashes'], **{'job.env': hashlib.sha256(raw_env).hexdigest()})
        raw_manifest = manifest(hashes, profile.payload)
        identity = dict(host_run_id=_identifier(vm.run._identity[0]), guest_run_id=guest,
                        stand_id=env['STAND_ID'], vm_uuid=env['BIOS_GUID'], boot_id=env['EXPECTED_BOOT_ID'],
                        import_id=attempt, media_sha256=media['sha256'], media_size=media['size'],
                        content_sha256=media['content_sha256'],
                        manifest_sha256=hashlib.sha256(raw_manifest).hexdigest())
        if profile.name != 'l2':
            identity['profile'] = profile.name  # L2 requests and receipts keep their old bytes
        self._identity = tuple(identity.items())
        self.request = dict(identity=identity, env=env, hashes=media['package']['hashes'],
                            sizes=media['package']['sizes'])
        self.calls = self.wire_bytes = 0
        self.handles = {}
        self.state = 'built'
        self.receipt_verified = False
        self.deadline = time.monotonic() + 900
        self.pid = None
        vm._l2_import = self  # Never replace uncertainty with a new facade.
        self._evidence('created')
        for name, data in (('job.env', raw_env), ('manifest.sha256', raw_manifest)):
            path = resource_path(vm.run.directory, 'l2-package/' + name)
            if path.stat().st_size:
                raise JobError('l2-local-destination-exists')
            with path.open('wb') as stream:
                import os
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())

    def _evidence(self, operation, **extra):
        try:
            row = dict(operation=operation, identity=self.identity, state=self.state,
                       calls=self.calls, handles=self.handles, **extra)
            append_row(self.vm.run, 'l2-import.jsonl', row, forbid=self.vm.run._identity[2],
                       max_bytes=128 * 1024, limit_check='before')
        except BaseException:
            self.receipt_verified = False
            self.state = 'unknown'
            self.vm.evidence_failed = True
            raise

    def _begin(self):
        vm = self.vm
        vm._check()
        if (vm.process.poll() is not None or not vm.qga.valid or vm.qga.closed or vm.reset_pending or
                vm.last_boot_id != self.identity['boot_id'] or time.monotonic() >= self.deadline):
            raise JobError('l2-import-channel-boot-or-deadline')
        vm.qga.deadline = self.deadline

    def _rpc(self, name, arguments):
        self._begin()
        if self.calls >= 48:
            raise JobError('l2-import-rpc-budget')
        self.calls += 1
        return self.vm.qga._rpc(name, 5, arguments)

    def _fresh_boot(self):
        self._begin()
        if self.calls > 40:
            raise JobError('l2-import-rpc-budget')
        qga = self.vm.qga
        qga.jobs_enabled = True
        before = qga.calls
        try:
            qga.probe(5)
            if qga.read_boot_id(5) != self.identity['boot_id']:
                raise JobError('l2-import-boot-changed')
        finally:
            self.calls += qga.calls - before

    @_guest_serialized
    def stage(self):
        if self.state != 'built':
            raise JobError('l2-import-already-attempted-inspect-only')
        self._fresh_boot()
        self.state = 'unknown'
        self._evidence('import-intent', request=self.request)
        try:
            request = base64.b64encode(json.dumps(self.request, sort_keys=True).encode()).decode()
            value = self._rpc('guest-exec', dict(path=HELPER, arg=[request], **{'capture-output': False}))
            if (type(value) is not dict or set(value) != {'pid'} or
                    type(value['pid']) is not int or not 0 < value['pid'] < 2**31):
                self.vm.qga.invalidate()
                raise JobError('l2-import-invalid-pid')
            self.pid = value['pid']
            for poll in range(24):
                value = self._rpc('guest-exec-status', dict(pid=self.pid))
                if type(value) is not dict or type(value.get('exited')) is not bool:
                    self.vm.qga.invalidate()
                    raise JobError('l2-import-invalid-status')
                if value['exited']:
                    if value != {'exited': True, 'exitcode': 0}:
                        raise JobError('l2-import-failed-retain-evidence')
                    return self._receipt()
                if poll < 23:
                    time.sleep(30)
            raise JobError('l2-import-poll-budget')
        finally:
            self._evidence('import-return')

    def _receipt(self):
        self.receipt_verified = False
        self.state = 'unknown'
        self._fresh_boot()
        raw = self._file('/root/rosetun-l2-stage/.import-' + self.identity['import_id'] + '/ready.json')
        if l2._json(raw) != dict(self.identity, schema='rosetun.l2-import.v1', state='ready'):
            raise JobError('l2-import-foreign-receipt')
        path = resource_path(self.vm.run.directory, 'l2-receipt.json')
        if path.exists() and path.stat().st_size:
            if path.read_bytes() != raw:
                raise JobError('l2-import-receipt-changed')
        else:
            with path.open('wb') as stream:
                import os
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        self._evidence('receipt', receipt_b64=base64.b64encode(raw).decode())
        self.state = 'ready'
        self.receipt_verified = True
        self._evidence('ready')
        return l2._json(raw)

    @_guest_serialized
    def check_receipt(self):
        if self.state == 'built':
            raise JobError('l2-import-not-attempted')
        return self._receipt()

    def require_ready(self):
        self._begin()
        if not self.receipt_verified or self.state != 'ready':
            raise JobError('l2-import-not-ready')

    def linux_l2_job(self, *, checkout, enabled=False):
        self.require_ready()
        profile = self.vm._l2_media['package'].get('profile', 'l2')
        extra = dict(profile=profile, sing_box_sha256=self.l3['sing_box_sha256']) if profile != 'l2' else {}
        return l2.LinuxL2Job(self.vm, package_directory=resource_path(self.vm.run.directory, 'l2-package'),
                             checkout=checkout, enabled=enabled, **extra)
