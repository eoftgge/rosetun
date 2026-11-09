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
import time

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


class Qmp:
    """One in-flight command; bounded framing, events, bytes and absolute deadline."""

    def __init__(self, stream):
        self.stream = stream
        self.buffer = bytearray()
        self.sequence = 0
        self.valid = True

    def close(self):
        self.valid = False
        self.stream.close()

    def _message(self, deadline, budget):
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise LifecycleError('qmp-timeout')
            if b'\n' in self.buffer:
                line, _, tail = self.buffer.partition(b'\n')
                self.buffer = bytearray(tail)
                budget[0] -= len(line) + 1
                if budget[0] < 0:
                    raise LifecycleError('qmp-output-limit')
                value = _json(line)
                if type(value) is not dict:
                    raise LifecycleError('invalid-qmp-message')
                return value
            if len(self.buffer) >= min(65536, budget[0]):
                raise LifecycleError('qmp-output-limit')
            self.stream.settimeout(remaining)
            block = self.stream.recv(min(4096, 65536 - len(self.buffer)))
            if not block:
                raise LifecycleError('qmp-disconnected')
            self.buffer.extend(block)

    def handshake(self, timeout):
        deadline = time.monotonic() + _limit(timeout)
        try:
            greeting = self._message(deadline, [OUTPUT_LIMIT]).get('QMP')
            if (type(greeting) is not dict or type(greeting.get('version')) is not dict
                    or type(greeting.get('capabilities')) is not list):
                raise LifecycleError('invalid-qmp-greeting')
            return self._command('qmp_capabilities', deadline)
        except (OSError, ValueError):
            self.close()
            raise LifecycleError('qmp-handshake-failed') from None

    def command(self, name, timeout):
        if name not in ('query-status', 'query-uuid', 'query-kvm', 'stop', 'cont',
                        'system_reset', 'system_powerdown', 'quit'):
            raise LifecycleError('unsupported-qmp-command')
        try:
            return self._command(name, time.monotonic() + _limit(timeout))
        except (OSError, ValueError):
            self.close()
            raise LifecycleError('qmp-command-failed') from None

    def _command(self, name, deadline):
        if not self.valid:
            raise LifecycleError('qmp-unavailable')
        self.sequence += 1
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise LifecycleError('qmp-timeout')
        self.stream.settimeout(remaining)
        self.stream.sendall(json.dumps({'execute': name, 'id': self.sequence}).encode() + b'\r\n')
        budget = [OUTPUT_LIMIT]
        for _ in range(128):
            message = self._message(deadline, budget)
            if 'event' in message:
                if type(message['event']) is not str or any(k in message for k in ('id', 'return', 'error')):
                    raise LifecycleError('invalid-qmp-event')
                continue
            if type(message.get('id')) is not int or message['id'] != self.sequence:
                raise LifecycleError('qmp-response-id-mismatch')
            if 'error' in message or 'return' not in message:
                raise LifecycleError('qmp-command-error')
            return message['return']
        raise LifecycleError('qmp-message-limit')


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

    def _check(self):
        self.run._read()
        if self.exited or self not in self.run._lease._active:
            raise LifecycleError('vm-is-not-active')

    def _event(self, action, result):
        self.run._read()
        if self.events >= 128:
            raise LifecycleError('lifecycle-journal-limit')
        self.events += 1
        with resource_path(self.run.directory, 'lifecycle.jsonl').open(
                'a', encoding='utf-8', newline='\n') as stream:
            stream.write(json.dumps({'sequence': self.events, 'action': action,
                                     'result': result}, sort_keys=True) + '\n')
            stream.flush()
            os.fsync(stream.fileno())

    def status(self):
        self._check()
        if self.process.poll() is not None:
            raise LifecycleError('vm-child-has-exited')
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
        self.qmp.command(name, self.timeout)
        value = self.status()
        if expected is not None and value['status'] != expected:
            raise LifecycleError('qmp-state-not-confirmed')
        self._event(name, 'confirmed' if expected else 'requested')
        return value

    def pause(self):
        return self._control('stop', 'paused')

    def resume(self):
        return self._control('cont', 'running')

    def reset(self):
        return self._control('system_reset')

    def powerdown(self):
        """Request ACPI shutdown; this does not confirm guest shutdown or exit."""
        return self._control('system_powerdown')

    def close(self):
        """Try QMP quit, then terminate/kill only the original owned child."""
        if self.exited:
            return
        self._check()
        try:
            self.run.mark('stopping')
            self._event('close', 'intent')
        except (OSError, ValueError):
            # Evidence failure must not strand an otherwise owned live child.
            pass
        try:
            if self.process is not None:
                if self.process.poll() is None and self.qmp is not None:
                    try:
                        self.qmp.command('quit', self.timeout)
                    except (OSError, ValueError):
                        pass
                for signal in (None, 'terminate', 'kill'):
                    if self.process.poll() is not None:
                        break
                    if signal:
                        self.run._read()
                        getattr(self.process, signal)()
                    try:
                        self.process.wait(timeout=self.timeout)
                    except subprocess.TimeoutExpired:
                        continue
                if self.process.poll() is None:
                    raise LifecycleError('vm-exit-unconfirmed', self)
                self.process.wait(timeout=self.timeout)
            self.exited = True
            self.run._lease._active.discard(self)
            self.run.mark('exited')
            self._event('close', 'child-exit-confirmed')
        except (OSError, ValueError, subprocess.TimeoutExpired):
            try:
                self.run.mark('quarantined', 'vm-exit-or-evidence-unconfirmed')
            except (OSError, ValueError):
                pass
            raise LifecycleError('vm-exit-or-evidence-unconfirmed', self) from None
        finally:
            if self.qmp is not None:
                self.qmp.close()

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
    journal = resource_path(run.directory, 'lifecycle.jsonl')
    run.register({'id': 'lifecycle', 'kind': 'file', 'path': 'lifecycle.jsonl'})
    with journal.open('x', encoding='utf-8'):
        pass
    vm = Vm(run, timeout)
    run._lease._active.add(vm)
    child = None
    try:
        run.mark('starting')
        vm._event('start', 'intent')
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        vm.qmp = Qmp(parent)
        argv = [*plan['argv'], '-S', '-chardev', f'socket,id=control,fd={child.fileno()}',
                '-mon', 'chardev=control,mode=control']
        run._read()
        vm.process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL, shell=False, close_fds=True,
                                      pass_fds=(child.fileno(),), start_new_session=True)
        child.close()
        child = None
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
