"""One owned Linux/KVM child, private QMP, and bounded confirmed termination.

There is no PID-based recovery, file cleanup, guest readiness or qualification.
Calls must be serialized by the caller. Startup failures carry the VM handle so
an unconfirmed child can still be stopped without surrendering its lease.
"""

import json
import math
import os
from pathlib import Path
import platform
import socket
import subprocess
import sys
import secrets
import threading
import time
from functools import wraps
from datetime import datetime, timezone

from .qmp_adapter import Qmp
from .qga import Qga, QgaError
from .diagnostics import StderrSink

from .images import ImageDescriptor, image_chain, local_file
from .qemu import QemuConfig, CommandResult, _launch_plan, execute, OUTPUT_LIMIT
from .report import _unique_object, _invalid_constant
from .evidence import append_row
from .resources import resource_path, execution_resources


JOURNAL_LIMIT = 128
# Rows the teardown path may still need once ordinary operations have stopped.
# Every attempt consumes a sequence number, even when its write fails, so the
# count is of attempts. One `_close` writes intent, exit, qga, stderr,
# confirmed and completion (6) and one failure row on top (7). A
# KeyboardInterrupt adds the `close interrupted` row and a second `_close(True)`
# after a first one that got as far as 7: 7 + 1 + 7 = 15. A failed start adds
# `start intent` and `start error` around that, plus a failed `qmp-ready-paused`
# attempt: 3 more, 18 in all. Start runs on an empty journal, so those 3 rows
# only add margin. Further close retries by a caller are not covered; a
# refused retry ends quarantined, as before.
TEARDOWN_ROWS = 18
ORDINARY_ROWS = JOURNAL_LIMIT - TEARDOWN_ROWS


class LifecycleError(ValueError):
    def __init__(self, reason, vm=None):
        super().__init__(reason)
        self.vm = vm


def _limit(value):
    if type(value) not in (int, float) or not math.isfinite(value) or not 0 < value <= 60:
        raise LifecycleError('invalid-lifecycle-timeout')
    return value


def _json(data):
    try:
        return json.loads(data.decode('utf-8'), object_pairs_hook=_unique_object,
                          parse_constant=_invalid_constant)
    except (UnicodeError, ValueError, RecursionError):
        raise LifecycleError('invalid-qmp-json') from None


def _host():
    if sys.platform != 'linux' or platform.machine() != 'x86_64':
        raise LifecycleError('execution-requires-linux-x86-64-kvm')
    # Opening KVM is an availability gate, not hardware or image qualification.
    fd = os.open('/dev/kvm', os.O_RDWR | os.O_CLOEXEC)
    os.close(fd)


def _identity(process, executable):
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    text = Path(f'/proc/{process.pid}/stat').read_text()
    start = text[text.rfind(')') + 2:].split()[19]
    actual = os.readlink(f'/proc/{process.pid}/exe')
    if actual != os.path.realpath(executable) or process.poll() is not None:
        raise LifecycleError('child-identity-unavailable')
    return {'id': 'qemu', 'kind': 'process', 'pid': process.pid, 'platform': 'posix',
            'boot_id': boot, 'start_id': start, 'executable': executable}


def _guest_serialized(method):
    @wraps(method)
    def call(self, *args, **kwargs):
        if not self._guest_lock.acquire(blocking=False):
            raise LifecycleError('qga-operation-in-progress', self)
        try:
            return method(self, *args, **kwargs)
        finally:
            self._guest_lock.release()
    return call


class Vm:
    def __init__(self, run, timeout):
        self.run = run
        self._owner_run = run
        self.timeout = timeout
        self.process = None
        self.qmp = None
        self.qga = None
        self.qga_endpoint = None
        self._guest_lock = threading.Lock()
        self.qga_recoveries = 0
        self._sync_seed = secrets.randbits(63)
        self.last_boot_id = None
        self.reset_boot_id = None
        self.reset_pending = False
        self.qga_reason = 'initial'
        self.launch_sockets = []
        self.guest_observation = None
        self.qga_observations = 0
        self.exited = False
        self.events = 0
        self.vm_uuid = None
        self.stderr = None
        self.evidence_failed = False
        self.completed = False
        self.controls_closed = False
        self.operation_errors = []

    def _check(self):
        if self.run is not self._owner_run:
            raise LifecycleError('vm-owner-mismatch', self)
        self.run._read()
        if self.completed or self not in self.run._lease._active:
            raise LifecycleError('vm-is-not-active')

    def _reserve(self, rows):
        """Refuse an ordinary operation whose rows would eat into the teardown reserve.

        Called before the operation's first row and before any command, so the
        refusal leaves no trace: it is neither evidence loss nor an operation error.
        """
        if self.events + rows > ORDINARY_ROWS:
            raise LifecycleError('lifecycle-journal-limit')

    def _event(self, action, result, *, teardown=False):
        try:
            self.run._read()
            if self.events >= (JOURNAL_LIMIT if teardown else ORDINARY_ROWS):
                raise ValueError('lifecycle-journal-limit')
            self.events += 1
            row = {'schema': 'rosetun.matrix.lifecycle.v2',
                   'sequence': self.events, 'action': action, 'result': result,
                   'utc': datetime.now(timezone.utc).isoformat(),
                   'run_id': self.run._identity[0], 'stand_id': self.run._identity[1],
                   'vm_uuid': self.vm_uuid}
            append_row(self.run, 'lifecycle.jsonl', row, forbid=self.run._identity[2])
        except (OSError, ValueError):
            self.evidence_failed = True
            raise LifecycleError('lifecycle-evidence-write-failed', self) from None

    def _new_qga(self):
        if self.qga is not None and not self.qga.closed:
            raise LifecycleError('qga-old-session-not-closed', self)
        stream = self.qga_endpoint.dup()
        self.launch_sockets.append(stream)
        self.qga = Qga(stream, sync_id=(self._sync_seed + self.qga_recoveries) % 2**63)
        self.launch_sockets.remove(stream)

    @_guest_serialized
    def observe_guest(self):
        return self._observe_guest()

    def wait_initial_guest(self, *, timeout, clock=time.monotonic, sleep=time.sleep):
        """Bound first-agent startup separately from post-operation recovery."""
        if self.last_boot_id is not None or not 0 < timeout <= 300:
            raise LifecycleError('initial-guest-wait-requires-unobserved-boot', self)
        deadline, previous = clock() + timeout, self.timeout
        try:
            for attempt in range(20):
                remaining = deadline - clock()
                if remaining <= 0:
                    break
                self.timeout = min(10, remaining)
                try:
                    return self.observe_guest()
                except LifecycleError:
                    if self.process.poll() is not None or self.evidence_failed:
                        raise
                    self.qga.close()
                    if not self.qga.closed:
                        raise LifecycleError('initial-qga-close-unconfirmed', self)
                    self._sync_seed = (self._sync_seed + 1) % 2**63
                    self._new_qga()
                    sleep(min(15, max(0, deadline - clock())))
            raise LifecycleError('initial-guest-deadline', self)
        finally:
            self.timeout = previous

    @_guest_serialized
    def recover_guest(self):
        """Replace a confirmed closed client under the original live lease."""
        self._check()
        if self.qga_endpoint is None:
            raise LifecycleError('qga-not-configured', self)
        if self.process is None or self.process.poll() is not None or self.exited:
            raise LifecycleError('vm-child-has-exited', self)
        if self.qga_recoveries >= 4:
            raise LifecycleError('qga-recovery-limit', self)
        if self.qga_observations >= 32:
            raise LifecycleError('qga-observation-limit', self)
        self.qga_recoveries += 1
        self.guest_observation = None
        old = self.qga.session_id
        deadline = time.monotonic() + self.timeout
        try:
            self.qga.close()
            if not self.qga.closed:
                raise LifecycleError('qga-close-unconfirmed', self)
            self._check()
            self._new_qga()
        except (OSError, ValueError):
            self.qga.invalidate()
            self.qga_observations += 1
            self._guest_row(dict(self._observation_row(), operation='recovery',
                                 old_session_id=old, reason=self.qga_reason,
                                 new_session_id=None,
                                 recovery_attempt=self.qga_recoveries,
                                 result='qga-session-replacement-failed'))
            raise LifecycleError('qga-session-replacement-failed', self) from None
        return self._observe_guest(deadline=deadline, old_session_id=old)

    def _observation_row(self):
        return {'run_id': self.run._identity[0], 'vm_uuid': self.vm_uuid,
                'qga_session_id': self.qga.session_id,
                'sync_id': self.qga.sync_id,
                'utc': datetime.now(timezone.utc).isoformat(), 'result': 'error',
                'agent': None, 'boot_id': None, 'previous_boot_id': self.last_boot_id,
                'reset_boot_id': self.reset_boot_id, 'reset_pending': self.reset_pending,
                'boot_comparison': 'unobserved', 'new_boot_confirmed': False}

    def _guest_row(self, row):
        try:
            append_row(self.run, 'qga-observations.jsonl', row, forbid=self.run._identity[2])
        except (OSError, ValueError):
            self.evidence_failed = True
            raise LifecycleError('qga-evidence-write-failed', self) from None

    def _observe_guest(self, *, deadline=None, old_session_id=None):
        """Observe agent availability and Linux boot identity, never OS readiness."""
        self._check()
        self.guest_observation = None
        if self.qga is None:
            raise LifecycleError('qga-not-configured', self)
        if self.qga_observations >= 32:
            raise LifecycleError('qga-observation-limit', self)
        self.qga_observations += 1
        row = dict(self._observation_row(), operation='recovery' if old_session_id else 'observe',
                   old_session_id=old_session_id, reason=self.qga_reason,
                   new_session_id=self.qga.session_id if old_session_id else None,
                   recovery_attempt=self.qga_recoveries)
        self.qga.deadline = deadline if deadline is not None else time.monotonic() + self.timeout
        try:
            if not self.qga.attempted:
                remaining = self.qga.deadline - time.monotonic()
                self.qga.connect(_limit(remaining))
            row['agent'] = self.qga.probe(self.timeout)
            # Guest supplied strings must never publish the local owner token.
            if self.run._identity[2] in json.dumps(row):
                row['agent'] = None
                raise LifecycleError('invalid-qga-observation')
            row['boot_id'] = self.qga.read_boot_id(self.timeout)
            baseline = self.reset_boot_id if self.reset_pending else self.last_boot_id
            row['boot_comparison'] = ('unknown' if baseline is None else
                                      'same' if baseline == row['boot_id'] else 'changed')
            row['new_boot_confirmed'] = self.reset_pending and row['boot_comparison'] == 'changed'
            self.last_boot_id = row['boot_id']
            if row['new_boot_confirmed']:
                self.reset_pending = False
            row['result'] = 'observed'
            row['sync_id'] = self.qga.sync_id
            self.qga_reason = 'explicit'
        except QgaError as error:
            row['result'] = str(error)
            self.qga_reason = str(error)
            raise LifecycleError(str(error), self) from None
        except (OSError, ValueError):
            self.qga_reason = row['result'] = 'guest-observation-failed'
            raise LifecycleError('guest-observation-failed', self) from None
        finally:
            if row['result'] != 'observed':
                self.qga.invalidate()
            self._guest_row(row)
        self.guest_observation = row
        return row

    def status(self):
        self._check()
        if self.process.poll() is not None:
            raise LifecycleError('vm-child-has-exited')
        if self.stderr is not None and (self.stderr.overflow or self.stderr.error):
            raise LifecycleError('stderr-limit-or-error', self)
        value = self.qmp.command('query-status', self.timeout)
        if (type(value) is not dict or type(value.get('running')) is not bool
                or type(value.get('status')) is not str):
            raise LifecycleError('invalid-qmp-status')
        return value

    def _control(self, name, expected=None):
        self._check()
        if self.process.poll() is not None:
            raise LifecycleError('vm-child-has-exited')
        self._reserve(4)  # intent, command-accepted, confirmed or requested, error
        self._event(name, 'intent')
        try:
            self.qmp.command(name, self.timeout)
            self._event(name, 'command-accepted')
            value = self.status()
            if expected is not None and (value['status'] != expected
                    or value['running'] is not (expected == 'running')):
                raise LifecycleError('qmp-state-not-confirmed')
            self._event(name, 'confirmed' if expected else 'requested')
            return value
        except (OSError, ValueError):
            self.operation_errors.append(name + '-unconfirmed')
            self._event(name, 'error')
            raise LifecycleError('control-operation-unconfirmed', self) from None

    def pause(self):
        return self._control('stop', 'paused')

    def resume(self):
        return self._control('cont', 'running')

    @_guest_serialized
    def reset(self):
        """Confirm RESET, not guest boot readiness or a new guest boot ID."""
        self._check()
        # intent, command-accepted, RESET-observed, confirmed, then on failure
        # command-accepted-event-unconfirmed and error.
        self._reserve(6)
        self.guest_observation = None
        self.reset_boot_id = self.last_boot_id
        self.reset_pending = True
        self.qga_reason = 'reset'
        if self.qga is not None:
            self.qga.invalidate()
        self._event('reset', 'intent')
        try:
            self.qmp.command('system_reset', self.timeout, event='RESET')
            self._event('reset', 'command-accepted')
            self._event('reset', 'RESET-observed')
            self._event('reset', 'confirmed')
            return self.status()
        except (OSError, ValueError):
            self.operation_errors.append('reset-unconfirmed')
            if getattr(self.qmp, 'last_command_accepted', False):
                self._event('reset', 'command-accepted-event-unconfirmed')
            self._event('reset', 'error')
            raise LifecycleError('reset-unconfirmed', self) from None

    def powerdown(self):
        """Compatibility API: request ACPI only, without confirming shutdown."""
        return self._control('system_powerdown')

    def request_shutdown(self, *, timeout=None):
        """ACPI request plus bounded child-exit observation. Timeout stays an error."""
        timeout = self.timeout if timeout is None else _limit(timeout)
        self._check()
        self._reserve(4)  # intent, command-accepted, child-exit-observed, confirmed
        self._event('shutdown', 'intent')
        try:
            self.qmp.command('system_powerdown', timeout)
            self._event('shutdown', 'command-accepted')
            self.process.wait(timeout=timeout)
            self._event('shutdown', 'child-exit-observed')
        except (OSError, ValueError, subprocess.TimeoutExpired):
            self.operation_errors.append('shutdown-unconfirmed')
            self._event('shutdown', 'error')
            raise LifecycleError('shutdown-unconfirmed', self) from None
        self._event('shutdown', 'confirmed')
        self.close()
        return self.process.returncode

    def hard_off(self):
        """Kill/reap the owned process; no ACPI and no physical disk power-loss claim."""
        return self.close(hard=True)

    @_guest_serialized
    def close(self, *, hard=False):
        if self.completed:
            return
        self._check()
        try:
            self._close(hard)
        except KeyboardInterrupt:
            # Preserve interruption after a second bounded teardown attempt.
            self.operation_errors.append('close-interrupted')
            try:
                self._event('close', 'interrupted', teardown=True)
            except (OSError, ValueError):
                pass
            self._close(True)
            raise

    def _close(self, hard):
        try:
            try:
                if self.run._read()['state'] != 'stopping':
                    self.run.mark('stopping')
                self._event('hard-off' if hard else 'close', 'intent', teardown=True)
            except (OSError, ValueError):
                self.evidence_failed = True
            if self.process is not None and not self.exited:
                if not hard and self.process.poll() is None and self.qmp is not None:
                    try:
                        self.qmp.command('quit', self.timeout)
                    except (OSError, ValueError):
                        pass
                for action in (('kill',) if hard else (None, 'terminate', 'kill')):
                    if self.process.poll() is not None:
                        break
                    if action:
                        self.run._read()
                        getattr(self.process, action)()
                    try:
                        self.process.wait(timeout=self.timeout)
                    except subprocess.TimeoutExpired:
                        continue
                if self.process.poll() is None:
                    raise LifecycleError('vm-exit-unconfirmed', self)
                self.process.wait(timeout=self.timeout)
            self.exited = True
            self._event('exit', 'child-reaped', teardown=True)
            for stream in list(self.launch_sockets):
                stream.close()
                self.launch_sockets.remove(stream)
            if self.qmp is not None:
                self.qmp.close()
            if self.qga is not None:
                self.qga.close()
            if self.qga_endpoint is not None:
                self.qga_endpoint.close()
            if self.qga is not None:
                self._event('qga', 'closed', teardown=True)
            if self.stderr is not None:
                self.stderr.close()
                if self.stderr.overflow:
                    self._event('stderr', 'truncated', teardown=True)
            self.controls_closed = True
            if self.evidence_failed:
                raise LifecycleError('completion-evidence-unavailable', self)
            manifest = self.run._read()
            processes = [r for r in manifest['resources'] if r['kind'] == 'process']
            if self.process is None or len(processes) != 1 or processes[0]['pid'] != self.process.pid:
                raise LifecycleError('completion-process-identity-missing', self)
            self._event('hard-off' if hard else 'close', 'confirmed', teardown=True)
            self.run.mark('exited')
            self._event('completion', 'controls-closed-child-reaped', teardown=True)
            self.run._complete([{'resource': processes[0], 'returncode': self.process.returncode}], self.vm_uuid)
            self.completed = True
        except (OSError, ValueError, subprocess.TimeoutExpired):
            reason = ('vm-exit-unconfirmed' if not self.exited else
                      'vm-control-close-unconfirmed' if not self.controls_closed else
                      'completion-evidence-unconfirmed')
            self.operation_errors.append(reason)
            try:
                self._event('close', reason, teardown=True)
            except (OSError, ValueError):
                pass
            try:
                self.run.mark('quarantined', reason)
            except (OSError, ValueError):
                pass
            raise LifecycleError(reason, self) from None
        finally:
            # A reaped child permits dropping the in-memory guard only after
            # controls are closed. Quarantined ledger still blocks a new lease.
            if self.exited:
                controls_closed = True
                for control in (*self.launch_sockets, self.qmp, self.qga, self.qga_endpoint, self.stderr):
                    if control is not None:
                        try:
                            control.close()
                        except (OSError, ValueError):
                            controls_closed = False
                if controls_closed:
                    self.run._lease._active.discard(self)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def start(run, *, timeout=5, executor=execute, lab=None):
    """Launch one verified prepared VM, initially paused, with optional lab ownership.

    Executor replaces only prelaunch qemu-img observations in offline tests.
    Startup failures expose .vm for a bounded close retry if exit is unconfirmed.
    """
    timeout = _limit(timeout)
    manifest = run._read()
    if lab is not None:
        from .lab import LabPair
        if not isinstance(lab, LabPair):
            raise LifecycleError('invalid-lab-capability')
        lab.check_start(run)
    if manifest['state'] != 'prepared' or (lab is None and run._lease._active):
        raise LifecycleError('launch-requires-prepared-idle-run')
    _host()
    expected = {'preparation': 'preparation.jsonl', 'launch-plan': 'launch-plan.json',
                'overlay': 'root.qcow2'}
    expected.update({r['id']: r['path'] for r in execution_resources(manifest)})
    if lab is not None:
        expected.update(lab.resources(run))
    if any(r['id'].startswith('l2-media-') for r in manifest['resources']):
        from .l2_media import RESOURCES
        expected.update({'l2-media-' + str(i): n for i, n in enumerate(RESOURCES)})
    if {r['id']: r.get('path') for r in manifest['resources']} != expected:
        raise LifecycleError('incomplete-preparation-resources')
    plan_path = local_file(resource_path(run.directory, 'launch-plan.json'))
    if plan_path.stat().st_size > OUTPUT_LIMIT:
        raise LifecycleError('launch-plan-too-large')
    plan = _json(plan_path.read_bytes())
    try:
        if run._identity[2] in json.dumps(plan):
            raise LifecycleError('ownership-identity-in-launch-input')
        image = ImageDescriptor(**plan['image'])
        config = QemuConfig(**plan['config'])
        overlay = local_file(resource_path(run.directory, 'root.qcow2'))
        image.validate(run.directory)
        media = plan.get('l2_media')
        if (media is not None) != any(r['id'].startswith('l2-media-') for r in manifest['resources']):
            raise LifecycleError('l2-media-preparation-incomplete')
        if media is not None:
            from .l2_media import verify_media
            if media['path'] != str(resource_path(run.directory, 'l2-media.iso')):
                raise LifecycleError('l2-media-path-mismatch')
            verify_media(media)
        if plan != _launch_plan(config, image, overlay, plan['uuid'], media=media):
            raise LifecycleError('launch-plan-mismatch')
        result = executor([config.image_executable, 'info', '--output=json', '--backing-chain',
                           '-f', 'qcow2', str(overlay)], timeout=timeout, output_limit=OUTPUT_LIMIT)
        if (not isinstance(result, CommandResult) or result.returncode != 0
                or type(result.stdout) is not bytes or type(result.stderr) is not bytes
                or max(len(result.stdout), len(result.stderr)) > OUTPUT_LIMIT):
            raise LifecycleError('prelaunch-image-check-failed')
        image_chain(result.stdout, [overlay, Path(image.path)])
        image.verify_bytes()
    except (KeyError, TypeError, OSError, ValueError):
        raise LifecycleError('prelaunch-validation-failed') from None
    # No process exists yet, so a failure here leaves partial resources and a
    # quarantined run instead of a prepared one that later starts refuse.
    try:
        for name in (('qemu-stderr.log', 'completion.json', 'qga-observations.jsonl', 'job-evidence.jsonl')
                     if config.qga else ('qemu-stderr.log', 'completion.json')):
            run.register({'id': name.split('.')[0], 'kind': 'file', 'path': name})
        if config.qga:
            from .linux_l2 import EVIDENCE_FILES
            for index, name in enumerate(EVIDENCE_FILES):
                relative = 'linux-l2/' + name
                run.register({'id': 'linux-l2-' + str(index), 'kind': 'file', 'path': relative})
                path = resource_path(run.directory, relative)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch(exist_ok=False)
            # Reserve one fixed smoke package before running; registration stays closed.
            for index, name in enumerate(('guest/launch.sh', 'guest/start.sh', 'guest/lib.sh',
                                          'guest/run-smoke.sh', 'job.env', 'manifest.sha256',
                                          'digest.sha256', 'staging.jsonl')):
                path = resource_path(run.directory, 'smoke-package/' + name)
                run.register({'id': 'smoke-stage-' + str(index), 'kind': 'file',
                              'path': 'smoke-package/' + name})
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch(exist_ok=False)
        journal = resource_path(run.directory, 'lifecycle.jsonl')
        run.register({'id': 'lifecycle', 'kind': 'file', 'path': 'lifecycle.jsonl'})
        with journal.open('x', encoding='utf-8'):
            pass
    except BaseException as error:
        try:
            run.mark('quarantined', 'vm-start-failed')
        except (OSError, ValueError):
            pass
        if not isinstance(error, Exception) or isinstance(error, AssertionError):
            raise
        raise LifecycleError('vm-start-failed') from None
    vm = Vm(run, timeout)
    vm.vm_uuid = plan['uuid']
    vm._l2_media = media
    run._lease._active.add(vm)
    child = None
    parent = None
    qga_parent = qga_child = None
    try:
        run.mark('starting')
        vm._event('start', 'intent', teardown=True)
        vm.stderr = StderrSink(resource_path(run.directory, 'qemu-stderr.log'), run._identity[2])
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        vm.launch_sockets.extend((parent, child))
        vm.qmp = Qmp(parent)
        vm.launch_sockets.remove(parent)
        argv = [*plan['argv'], '-S', '-chardev', f'socket,id=control,fd={child.fileno()}',
                '-mon', 'chardev=control,mode=control']
        descriptors = [child.fileno()]
        if lab is not None:
            network_argv, network_fd = lab.network(run)
            argv += network_argv
            descriptors.append(network_fd)
        if config.qga:
            qga_parent, qga_child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            vm.launch_sockets.extend((qga_parent, qga_child))
            vm.qga_endpoint = qga_parent
            vm.launch_sockets.remove(qga_parent)
            vm._new_qga()
            argv += ['-chardev', f'socket,id=guestagent,fd={qga_child.fileno()}',
                     '-device', 'virtio-serial-pci,id=guestserial',
                     '-device', 'virtserialport,bus=guestserial.0,chardev=guestagent,name=org.qemu.guest_agent.0']
            descriptors.append(qga_child.fileno())
            resource_path(run.directory, 'qga-observations.jsonl').touch(exist_ok=False)
            resource_path(run.directory, 'job-evidence.jsonl').touch(exist_ok=False)
        run._read()
        if media is not None:
            verify_media(media)
        vm.process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                      stderr=subprocess.PIPE, shell=False, close_fds=True, bufsize=0,
                                      pass_fds=tuple(descriptors), start_new_session=True)
        child.close()
        vm.launch_sockets.remove(child)
        child = None
        if qga_child is not None:
            qga_child.close()
            vm.launch_sockets.remove(qga_child)
            qga_child = None
        vm.stderr.start(vm.process.stderr)
        run.register(_identity(vm.process, config.executable))
        vm.qmp.handshake(timeout)
        if vm.qmp.command('query-uuid', timeout) != {'UUID': plan['uuid']}:
            raise LifecycleError('qmp-uuid-mismatch')
        kvm = vm.qmp.command('query-kvm', timeout)
        if type(kvm) is not dict or kvm.get('enabled') is not True or kvm.get('present') is not True:
            raise LifecycleError('qmp-kvm-not-enabled')
        if vm.status()['status'] != 'prelaunch':
            raise LifecycleError('qmp-initial-state-mismatch')
        run.mark('running')
        vm._event('start', 'qmp-ready-paused', teardown=True)
        return vm
    except BaseException as error:
        try:
            vm.close()
        except BaseException:
            pass
        try:
            if not vm.completed:
                vm._event('start', 'interrupted' if not isinstance(error, Exception) else 'error',
                      teardown=True)
        except (OSError, ValueError):
            pass
        try:
            run.mark('quarantined', 'vm-start-failed')
        except (OSError, ValueError):
            pass
        if not isinstance(error, Exception) or isinstance(error, AssertionError):
            raise
        raise LifecycleError('vm-start-failed', vm) from None
    finally:
        pending = [child, qga_child]
        if vm.qmp is None:
            pending.append(parent)
        if vm.qga is None:
            pending.append(qga_parent)
        for stream in pending:
            if stream is not None:
                try:
                    stream.close()
                except (OSError, ValueError):
                    # Keep the original LifecycleError and its VM handle. The
                    # VM retains failed endpoints and cannot confirm completion.
                    vm.evidence_failed = True
                    vm.operation_errors.append('launch-socket-close-unconfirmed')
