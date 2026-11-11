"""One two-VM isolated lab. No assessment profile or L3 execution."""
import base64
import hashlib
from dataclasses import fields
import json
import os
import re
from pathlib import Path
import secrets
import socket
import time
import tomllib
import uuid

from .execution import exact
from .images import ImageDescriptor
from .qemu import QemuConfig, prepare, execute
from .lifecycle import start, _host
from .resources import (StandLease, create_run, completion_verified, resource_path,
                        EXECUTION_FILES, _identifier, _state_path)
from .orchestrator import save, failure, _RETAINED_LEASES
from .lab_protocol import MACS, CAPTURE_LIMIT, LOG_LIMIT, probes, qualify

ENTRY = '/usr/local/libexec/rosetun-lab/entry'
ARTIFACTS = {'lab-capture': 'capture.pcap', 'lab-targets': 'targets.json', 'lab-health': 'health.json'}


def controls(run):
    return {name: dict(kind='inherited-unix-stream', run_id=run._identity[0], purpose='management')
            for name in ('qmp', 'qga')}


def load_lab(path):
    with Path(path).open('rb') as stream:
        config = tomllib.load(stream)
    return validate(config)


def validate(config):
    exact(config, ('schema', 'state_directory', 'stand_id', 'qemu', 'test_image', 'lab_image'))
    if config['schema'] != 'rosetun.matrix.lab.v1':
        raise ValueError('unsupported-lab-schema')
    _state_path(config['state_directory'])
    _identifier(config['stand_id'])
    exact(config['qemu'], [f.name for f in fields(QemuConfig)])
    if config['qemu']['machine'] != 'pc-i440fx-10.0' or config['qemu']['qga'] is not True:
        raise ValueError('lab-requires-pinned-machine-and-qga')
    for role in MACS:
        exact(config[role + '_image'], [f.name for f in fields(ImageDescriptor)])
    return config


def plan_lab(config):
    """Read only: no lease, directories, subprocesses or sockets."""
    validate(config)
    state = _state_path(config['state_directory'])
    QemuConfig(**config['qemu']).validate()
    for role in MACS:
        ImageDescriptor(**config[role + '_image']).validate(state)
    return dict(schema='rosetun.matrix.lab-plan.v1', dry_run=True, configuration=config,
                topology='test -> inherited AF_UNIX stream pair -> lab -> guest namespace',
                roles=MACS, capture_limit=CAPTURE_LIMIT, duration_seconds=60,
                qualification='UNRUN', security_invariants='UNVERIFIED', release_gate=False)


class LabPair:
    """Capability for two particular runs under their original lease."""
    def __init__(self, lease, runs, lab_id, *, pair_factory=socket.socketpair):
        lease._check_live()
        if set(runs) != set(MACS) or lease._active or runs['test'] is runs['lab']:
            raise ValueError('invalid-lab-members')
        for run in runs.values():
            if run._lease is not lease or run._read()['state'] != 'prepared':
                raise ValueError('foreign-lab-member')
        self.lease, self.runs, self.lab_id = lease, dict(runs), _identifier(lab_id)
        self.sockets = {}
        self.used = set()
        self.closed = False
        for role, run in runs.items():
            linkage = json.loads(resource_path(run.directory, 'execution-identity.json').read_bytes())
            if (linkage.get('lab_id') != lab_id or linkage.get('role') != role
                    or linkage.get('members') != {r: runs[r]._identity[0] for r in MACS}
                    or linkage.get('controls') != controls(run)
                    or linkage.get('endpoint') != dict(kind='inherited-unix-stream', role=role, mac=MACS[role])):
                raise ValueError('lab-linkage-mismatch')
            for identifier, name in self.resources(run).items():
                run.register(dict(id=identifier, kind='file', path=name))
                resource_path(run.directory, name).touch(exist_ok=False)
        # Both endpoint records already exist in the execution identity ledgers.
        a, b = pair_factory(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sockets = dict(test=a, lab=b)

    def role(self, run):
        roles = [role for role, member in self.runs.items() if member is run]
        if len(roles) != 1:
            raise ValueError('foreign-lab-run')
        return roles[0]

    def resources(self, run):
        return ARTIFACTS if self.role(run) == 'lab' else {}

    def check_start(self, run):
        self.lease._check_live()
        role = self.role(run)
        if self.closed or role in self.used or run._lease is not self.lease:
            raise ValueError('lab-launch-ownership-mismatch')
        if any(not any(vm.run is member for member in self.runs.values()) or vm.run is run
               for vm in self.lease._active):
            raise ValueError('foreign-active-vm')
        if len(self.lease._active) >= 2:
            raise ValueError('lab-capacity')

    def network(self, run):
        self.lease._check_live()
        role = self.role(run)
        if self.closed or role in self.used:
            raise ValueError('lab-endpoint-already-consumed')
        self.used.add(role)
        fd = self.sockets[role].fileno()
        return ['-netdev', f'stream,id=labwire,addr.type=fd,addr.str={fd},server=off',
                '-device', f'virtio-net-pci,netdev=labwire,id={role}-wire,mac={MACS[role]}'], fd

    def close(self):
        self.closed = False
        errors = []
        for endpoint in self.sockets.values():
            try:
                endpoint.close()
                if endpoint.fileno() != -1:
                    raise ValueError('endpoint-close-unconfirmed')
            except (OSError, ValueError) as error:
                errors.append(error)
        if errors:
            raise ValueError('lab-channel-close-unconfirmed')
        self.closed = True


class Guest:
    """Fixed installed entry point, serialized QGA, no shell or arbitrary paths."""
    def __init__(self, vm, role, lab_id, *, clock=time.monotonic, sleep=time.sleep):
        self.vm, self.role, self.lab_id = vm, role, lab_id
        self.clock, self.sleep = clock, sleep
        self.deadline = clock() + 90

    def rpc(self, name, args):
        self.vm._check()
        if self.clock() >= self.deadline or self.vm.reset_pending:
            raise ValueError('lab-guest-deadline-or-reset')
        self.vm.qga.deadline = time.monotonic() + min(5, self.deadline - self.clock())
        return self.vm.qga._rpc(name, 5, args)

    def call(self, operation, expected):
        if operation not in ({'setup', 'finish'} if self.role == 'lab' else {'probe'}):
            raise ValueError('invalid-lab-operation')
        with self.vm._guest_lock:
            self.vm.qga.deadline = time.monotonic() + 10
            if self.vm.qga.read_boot_id(5) != self.vm.last_boot_id:
                raise ValueError('lab-boot-changed')
            request = dict(operation=operation, role=self.role, lab_id=self.lab_id,
                           vm_uuid=self.vm.vm_uuid, boot_id=self.vm.last_boot_id, probes=expected)
            self.vm.qga.jobs_enabled = True
            self.vm.qga.probe(5)
            response = self.rpc('guest-exec', {'path': ENTRY, 'arg': [json.dumps(request)], 'capture-output': True})
            if type(response) is not dict or set(response) != {'pid'} or type(response['pid']) is not int:
                raise ValueError('invalid-lab-exec')
            for _ in range(40):
                status = self.rpc('guest-exec-status', response)
                if status.get('exited') is True:
                    if status.get('exitcode') != 0 or status.get('out-truncated') or status.get('err-truncated'):
                        raise ValueError('lab-helper-failed')
                    raw = base64.b64decode(status.get('out-data', ''), validate=True)
                    if len(raw) > LOG_LIMIT:
                        raise ValueError('lab-helper-output-limit')
                    result = json.loads(raw)
                    if result.get('lab_id') != self.lab_id or result.get('boot_id') != self.vm.last_boot_id:
                        raise ValueError('lab-helper-identity-mismatch')
                    return result
                self.sleep(0.5)
            raise ValueError('lab-helper-timeout')

    def read(self, name, limit):
        if name not in ARTIFACTS.values():
            raise ValueError('invalid-lab-artifact')
        with self.vm._guest_lock:
            handle = self.rpc('guest-file-open', {'path': '/run/rosetun-lab/' + self.lab_id + '/' + name, 'mode': 'r'})
            if type(handle) is not int:
                raise ValueError('invalid-lab-file-handle')
            data = bytearray()
            try:
                for _ in range(limit // 16384 + 2):
                    row = self.rpc('guest-file-read', {'handle': handle, 'count': 16384})
                    block = base64.b64decode(row['buf-b64'], validate=True)
                    if len(block) != row['count'] or len(data) + len(block) > limit:
                        raise ValueError('lab-artifact-size-limit')
                    data.extend(block)
                    if row.get('eof') is True:
                        return bytes(data)
                    if not block:
                        break
                raise ValueError('incomplete-lab-artifact')
            finally:
                if self.vm.qga.valid:
                    if self.rpc('guest-file-close', {'handle': handle}) != {}:
                        raise ValueError('lab-artifact-close-unconfirmed')


class Adapters:
    host = staticmethod(_host)
    prepare = staticmethod(prepare)
    start = staticmethod(start)
    execute = staticmethod(execute)
    pair = LabPair
    guest = Guest


def lab_smoke(config, *, adapters=None, clock=time.monotonic, sleep=time.sleep):
    plan_lab(config)
    adapters = adapters or Adapters()
    lab_id = uuid.uuid4().hex
    expected = probes(lab_id, lambda: secrets.token_hex(12))
    result = dict(schema='rosetun.matrix.lab-summary.v1', lab_id=lab_id, readiness={},
                  artifact_directories={}, configuration=config,
                  qualification=dict(qualified=False, ipv4='UNVERIFIED', ipv6='UNVERIFIED',
                                     services='UNVERIFIED', observer='UNVERIFIED', evidence='UNVERIFIED'),
                  probes=expected, completion={}, channel_closed=False, completed=False,
                  errors=[], security_invariants='UNVERIFIED', release_gate=False, exit_code=2)
    lease, pair, runs, vms = None, None, {}, {}
    try:
        adapters.host()
        for binary in ('executable', 'image_executable'):
            version = adapters.execute([config['qemu'][binary], '--version'], timeout=5, output_limit=4096)
            if version.returncode != 0 or not re.search(rb'\bversion 10\.0\.13(?:\s|$)', version.stdout.split(b'\n')[0]):
                raise ValueError('lab-requires-qemu-10-0-13')
        lease = StandLease(config['state_directory'], config['stand_id']).acquire()
        for role in MACS:
            run = create_run(lease, lab_id + '-' + role)
            runs[role] = run
            result['artifact_directories'][role] = str(run.directory)
            for identifier, name in EXECUTION_FILES.items():
                run.register(dict(id=identifier, kind='file', path=name))
            save(run, 'execution-identity.json', dict(lab_id=lab_id, role=role,
                 members={r: lab_id + '-' + r for r in MACS}, controls=controls(run),
                 endpoint=dict(kind='inherited-unix-stream', role=role, mac=MACS[role])), initial=True)
            save(run, 'execution-summary.json', result, initial=True)
            adapters.prepare(run, ImageDescriptor(**config[role + '_image']), QemuConfig(**config['qemu']))
        pair = adapters.pair(lease, runs, lab_id)
        for role in MACS:
            vm = adapters.start(runs[role], lab=pair)
            vms[role] = vm
            vm.resume()
            observed = vm.wait_initial_guest(timeout=120, clock=clock, sleep=sleep)
            result['readiness'][role] = dict(vm_uuid=vm.vm_uuid, boot_id=vm.last_boot_id,
                                             vm=True, qga=observed['result'] == 'observed')
        # Drop controller duplicates before probes; QEMU owns both remaining ends.
        pair.close()
        lab = adapters.guest(vms['lab'], 'lab', lab_id, clock=clock, sleep=sleep)
        test = adapters.guest(vms['test'], 'test', lab_id, clock=clock, sleep=sleep)
        ready = lab.call('setup', expected)
        if ready.get('capture_ready') is not True:
            raise ValueError('capture-not-ready')
        try:
            replies = test.call('probe', expected)['replies']
        except Exception as error:
            result['errors'].append(failure('probe', error))
            replies = []
        result['replies'] = replies
        lab.call('finish', expected)
        evidence = {}
        for name, limit in (('capture.pcap', CAPTURE_LIMIT), ('targets.json', LOG_LIMIT), ('health.json', LOG_LIMIT)):
            raw = lab.read(name, limit)
            path = resource_path(runs['lab'].directory, name)
            with path.open('wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            evidence[name] = path.read_bytes()
            if evidence[name] != raw:
                raise ValueError('lab-evidence-readback-failed')
        result['evidence_sha256'] = {name: hashlib.sha256(raw).hexdigest() for name, raw in evidence.items()}
        result['qualification'] = qualify(expected, replies, json.loads(evidence['targets.json']),
                    evidence['capture.pcap'], ready['capture_ready'], json.loads(evidence['health.json']))
    except BaseException as error:
        result['errors'].append(failure('lab-smoke', error))
        if isinstance(error, KeyboardInterrupt):
            result['exit_code'] = 130
    finally:
        if lease is not None:
            # Includes a failed start's handle, never unrelated processes.
            for vm in list(lease._active):
                if any(vm.run is member for member in runs.values()):
                    try:
                        vm.close(hard=True)
                    except BaseException as error:
                        result['errors'].append(failure('vm-close', error))
            if pair is not None:
                try:
                    pair.close()
                    result['channel_closed'] = pair.closed
                except BaseException as error:
                    result['errors'].append(failure('channel-close', error))
                    for run in runs.values():
                        try:
                            run.mark('quarantined', 'lab-channel-close-unconfirmed')
                        except (OSError, ValueError):
                            result['errors'].append(dict(stage='quarantine', reason='ledger-write-failed'))
            for role, run in runs.items():
                try:
                    result['completion'][role] = completion_verified(run.directory, run._read())
                except (OSError, ValueError):
                    result['completion'][role] = False
                    result['errors'].append(dict(stage='completion', reason='ledger-read-failed'))
            result['completed'] = (set(result['completion']) == set(MACS)
                                   and all(result['completion'].values()) and result['channel_closed'])
            if result['exit_code'] != 130:
                result['exit_code'] = 0 if result['completed'] and not result['errors'] and result['qualification']['qualified'] else 2
            for run in runs.values():
                try:
                    save(run, 'execution-summary.json', result)
                except (OSError, ValueError):
                    result['errors'].append(dict(stage='summary', reason='summary-write-failed'))
                    result['exit_code'] = 2
            if lease._active or (pair is not None and not pair.closed):
                _RETAINED_LEASES.append(lease)
            else:
                try:
                    lease.release()
                except (OSError, ValueError):
                    result['errors'].append(dict(stage='lease', reason='lease-release-failed'))
                    result['exit_code'] = 2
    return result
