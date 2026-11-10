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
from datetime import datetime, timezone

from .qmp_adapter import Qmp
from .diagnostics import StderrSink

from .images import ImageDescriptor, image_chain, local_file
from .qemu import QemuConfig, CommandResult, _launch_plan, execute, OUTPUT_LIMIT
from .report import _unique_object, _invalid_constant
from .resources import resource_path


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


class Vm:
    def __init__(self, run, timeout):
        self.run = run
        self.timeout = timeout
        self.process = None
        self.qmp = None
        self.exited = False
        self.events = 0
        self.vm_uuid = None
        self.stderr = None
        self.evidence_failed = False
        self.completed = False
        self.controls_closed = False
        self.operation_errors = []

    def _check(self):
        self.run._read()
        if self.completed or self not in self.run._lease._active:
            raise LifecycleError('vm-is-not-active')

    def _event(self, action, result):
        try:
            self.run._read()
            if self.events >= 128:
                raise ValueError('lifecycle-journal-limit')
            self.events += 1
            row = {'schema': 'rosetun.matrix.lifecycle.v2',
                   'sequence': self.events, 'action': action, 'result': result,
                   'utc': datetime.now(timezone.utc).isoformat(),
                   'run_id': self.run._identity[0], 'stand_id': self.run._identity[1],
                   'vm_uuid': self.vm_uuid}
            with resource_path(self.run.directory, 'lifecycle.jsonl').open(
                    'a', encoding='utf-8', newline='\n') as stream:
                stream.write(json.dumps(row, sort_keys=True) + '\n')
                stream.flush()
                os.fsync(stream.fileno())
        except (OSError, ValueError):
            self.evidence_failed = True
            raise LifecycleError('lifecycle-evidence-write-failed', self) from None

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

    def reset(self):
        """Confirm RESET, not guest boot readiness or a new guest boot ID."""
        self._check()
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
                self._event('close', 'interrupted')
            except (OSError, ValueError):
                pass
            self._close(True)
            raise

    def _close(self, hard):
        try:
            try:
                if self.run._read()['state'] != 'stopping':
                    self.run.mark('stopping')
                self._event('hard-off' if hard else 'close', 'intent')
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
            self._event('exit', 'child-reaped')
            if self.qmp is not None:
                self.qmp.close()
            if self.stderr is not None:
                self.stderr.close()
                if self.stderr.overflow:
                    self._event('stderr', 'truncated')
            self.controls_closed = True
            if self.evidence_failed:
                raise LifecycleError('completion-evidence-unavailable', self)
            manifest = self.run._read()
            processes = [r for r in manifest['resources'] if r['kind'] == 'process']
            if self.process is None or len(processes) != 1 or processes[0]['pid'] != self.process.pid:
                raise LifecycleError('completion-process-identity-missing', self)
            self._event('hard-off' if hard else 'close', 'confirmed')
            self.run.mark('exited')
            self._event('completion', 'controls-closed-child-reaped')
            self.run._complete([{'resource': processes[0], 'returncode': self.process.returncode}], self.vm_uuid)
            self.completed = True
        except (OSError, ValueError, subprocess.TimeoutExpired):
            reason = ('vm-exit-unconfirmed' if not self.exited else
                      'vm-control-close-unconfirmed' if not self.controls_closed else
                      'completion-evidence-unconfirmed')
            self.operation_errors.append(reason)
            try:
                self._event('close', reason)
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
                for control in (self.qmp, self.stderr):
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


def start(run, *, timeout=5, executor=execute):
    """Launch exactly one verified prepared VM, initially paused; no CLI entry.

    Executor replaces only prelaunch qemu-img observations in offline tests.
    Startup failures expose .vm for a bounded close retry if exit is unconfirmed.
    """
    timeout = _limit(timeout)
    manifest = run._read()
    if manifest['state'] != 'prepared' or run._lease._active:
        raise LifecycleError('launch-requires-prepared-idle-run')
    _host()
    expected = {'preparation': 'preparation.jsonl', 'launch-plan': 'launch-plan.json',
                'overlay': 'root.qcow2'}
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
        if plan != _launch_plan(config, image, overlay, plan['uuid']):
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
    for name in ('qemu-stderr.log', 'completion.json'):
        run.register({'id': name.split('.')[0], 'kind': 'file', 'path': name})
    journal = resource_path(run.directory, 'lifecycle.jsonl')
    run.register({'id': 'lifecycle', 'kind': 'file', 'path': 'lifecycle.jsonl'})
    with journal.open('x', encoding='utf-8'):
        pass
    vm = Vm(run, timeout)
    vm.vm_uuid = plan['uuid']
    run._lease._active.add(vm)
    child = None
    parent = None
    try:
        run.mark('starting')
        vm._event('start', 'intent')
        vm.stderr = StderrSink(resource_path(run.directory, 'qemu-stderr.log'), run._identity[2])
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        vm.qmp = Qmp(parent)
        argv = [*plan['argv'], '-S', '-chardev', f'socket,id=control,fd={child.fileno()}',
                '-mon', 'chardev=control,mode=control']
        run._read()
        vm.process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                      stderr=subprocess.PIPE, shell=False, close_fds=True, bufsize=0,
                                      pass_fds=(child.fileno(),), start_new_session=True)
        child.close()
        child = None
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
        vm._event('start', 'qmp-ready-paused')
        return vm
    except BaseException as error:
        try:
            vm.close()
        except BaseException:
            pass
        try:
            vm._event('start', 'interrupted' if not isinstance(error, Exception) else 'error')
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
        if child is not None:
            child.close()
        if parent is not None and vm.qmp is None:
            parent.close()
