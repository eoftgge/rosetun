"""A controller process that tests kill: a real ledger, run state and lifecycle.start on the fake QEMU.

`python3 -m tools.vm.matrix.tests.fake_controller STATE PHASE` prepares one
run under STATE, starts the fake QEMU and walks the steps of `run linux-l2`
as the orchestrator records them, up to PHASE. There it prints `READY` with
the run id and waits to be killed. With PHASE `end` it closes the VM itself.
The guest steps are only recorded (no import or job runs in the fake guest);
the VM, its sockets, the journal and the budgets are real.

With the argument `reboot` the run plans one guest reset: after the submit the
fake guest resets with a new boot ID (steered through FAKE_QEMU_CONTROL), the
controller takes the RESET from QMP (`reset`, and `reset-seen` once it has) and
recovers the agent session on the new boot (`reboot`), as the wait of a job does.
"""

import hashlib
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
from unittest.mock import patch

from tools.vm.matrix import lifecycle, orchestrator
from tools.vm.matrix.images import ImageDescriptor
from tools.vm.matrix.qemu import QemuConfig
from tools.vm.matrix.qga import Qga
from tools.vm.matrix.qmp_adapter import Qmp
from tools.vm.matrix.resources import StandLease, create_run, EXECUTION_FILES
from tools.vm.matrix.tests import test_qemu
from tools.vm.matrix.tests.mini_qmp import MiniClient

FAKE_QEMU = Path(__file__).resolve().parent / 'fake_qemu.py'
FAKE_SWTPM = Path(__file__).resolve().parent / 'fake_swtpm.py'
PHASES = ('preparing', 'boot', 'submit', 'reset-seen', 'wait', 'collect', 'close', 'end')
NEW_BOOT = '22345678-1234-4234-8234-123456789abc'
REAL_POPEN = subprocess.Popen


def fake_popen(argv, **kwargs):
    # The recorded executable stays the interpreter, so the process identity check is the real one.
    # swtpm is told from QEMU by its first argument: QEMU always starts with `-no-user-config`.
    return REAL_POPEN([argv[0], '-I', str(FAKE_SWTPM if argv[1:2] == ['socket'] else FAKE_QEMU), *argv[1:]], **kwargs)


def patches():
    """What the controller and a later attacher share: the fake QEMU and the stand-in QMP client."""
    return [patch.object(lifecycle, '_host'),
            patch.object(lifecycle.subprocess, 'Popen', fake_popen),
            patch.object(lifecycle, 'Qmp', lambda stream, **kw: Qmp(stream, client_factory=MiniClient, **kw)),
            patch.object(lifecycle, 'Qga', lambda stream, **kw: Qga(stream, client_factory=MiniClient, **kw))]


class Fixture(test_qemu.PreparationTests):
    """The preparation fixture of the offline tests, its files beside the given state directory."""

    def __init__(self, state):
        super().__init__()
        self.root = Path(state).parent

    def setUp(self):
        self.base = self.root / 'base image.qcow2'
        self.original = b'not a real disk; executor must be fake'
        self.base.write_bytes(self.original)
        self.image = ImageDescriptor('rosetun.matrix.image.v1', 'linux-test', 'linux', 'x86_64', str(self.base),
                                     len(self.original), hashlib.sha256(self.original).hexdigest(), 'qcow2',
                                     'bios-i440fx-v1')
        self.config = QemuConfig('rosetun.matrix.qemu.v1', os.path.realpath(sys.executable), str(self.base),
                                 str(self.base), 'pc-i440fx-9.2', qga=True)
        self.calls = []
        self.hook = None


def steer(command):
    """One line to the fake guest's control socket; it answers once the command is done."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(10)
        stream.connect(os.environ['FAKE_QEMU_CONTROL'])
        stream.sendall(command.encode() + b'\n')
        stream.recv(4096)


def main(state, phase, reboot=False):
    fixture = Fixture(state)
    fixture.setUp()
    lease = StandLease(state, 'stand').acquire()
    config = dict(suite='linux-reboot-smoke' if reboot else 'linux-l2', timeouts=dict(job=60), synthetic=True)
    run = create_run(lease)
    fixture.run = run
    for identifier, name in EXECUTION_FILES.items():
        run.register(dict(id=identifier, kind='file', path=name))
    state_record = orchestrator.begin_state(run, config, {}, host_run_id=run._identity[0],
                                            guest_run_id='20261115T000000Z-0a0b0c0d', import_id='0' * 32)
    summary = dict(schema=orchestrator.SUMMARY_SCHEMA, suite=config['suite'], identities={}, configuration=config,
                   stages=[], evidence=[], assessment=None, delivery=None, execution=None, completion=False,
                   manual_recovery_required=False, errors=[], attached=False, attachments=0,
                   security_invariants='UNVERIFIED', release_gate=False, exit_code=2)
    orchestrator.save(run, 'execution-identity.json', dict(schema='rosetun.matrix.execution-identity.v1'),
                      initial=True)
    orchestrator.save(run, 'execution-summary.json', summary, initial=True)

    def step(name, operation=lambda: None):
        orchestrator.mark_step([state_record], name, 'intent')
        if name == phase or (phase == 'preparing' and name == 'prepare'):
            print('READY', run._identity[0], flush=True)
            threading.Event().wait()
        value = operation()
        orchestrator.mark_step([state_record], name, 'done')
        return value

    def prepare():
        fixture.prepare()
        # The prelaunch check repeats the overlay observation, the third call of the fake.
        fixture.calls = fixture.calls[:2]

    step('prepare', prepare)
    for item in patches():
        item.start()

    def info(argv, *, timeout, output_limit):
        return fixture.fake(argv, timeout=30, output_limit=output_limit)

    vm = step('start', lambda: lifecycle.start(run, timeout=5, executor=info))
    vm.planned_reboots = 1 if reboot else 0
    step('resume', vm.resume)
    step('boot', vm.observe_guest)
    state_record.update('identities', boot_id=vm.last_boot_id, vm_uuid=vm.vm_uuid)
    state_record.deadline('job_deadline', 600)
    state_record.update('job', submission='launcher-spawned', launcher='running', job='unknown', pid=4242,
                        session=vm.qga.session_id)
    step('submit', lambda: vm.status())
    if reboot:
        step('reset', lambda: (steer('guest-reset ' + NEW_BOOT), vm.watch_resets()))
        step('reset-seen')
        step('reboot', lambda: vm.await_rebooted_guest(timeout=30, sleep=lambda seconds: None))
    state_record.deadline('wait_until', 0.5)
    step('wait')
    step('collect', lambda: vm.status())
    step('close', vm.close)
    print('CLOSED', run._identity[0], flush=True)
    lease.release()


def main_windows(state, phase):
    """A Windows run as `run windows-boot-smoke` walks it, up to PHASE: `preparing`, `start`, `watch` or `end`."""
    from tools.vm.matrix.tests import windows_fixture
    fixture = windows_fixture.WindowsFixture(state)
    fixture.build(Path(state).parent)
    lease = StandLease(state, 'stand').acquire()
    config = dict(suite='windows-boot-smoke', synthetic=True)
    run = create_run(lease)
    fixture.run = run
    for identifier, name in EXECUTION_FILES.items():
        run.register(dict(id=identifier, kind='file', path=name))
    state_record = orchestrator.begin_state(run, config, {}, host_run_id=run._identity[0])
    summary = dict(schema=orchestrator.SUMMARY_SCHEMA, suite=config['suite'], identities={}, configuration=config,
                   stages=[], evidence=[], assessment=None, delivery=None, execution=None, completion=False,
                   manual_recovery_required=False, errors=[], attached=False, attachments=0,
                   security_invariants='UNVERIFIED', release_gate=False, exit_code=2)
    orchestrator.save(run, 'execution-identity.json', dict(schema='rosetun.matrix.execution-identity.v1'),
                      initial=True)
    orchestrator.save(run, 'execution-summary.json', summary, initial=True)

    def step(name, operation=lambda: None):
        orchestrator.mark_step([state_record], name, 'intent')
        if name == phase or (phase == 'preparing' and name == 'prepare'):
            print('READY', run._identity[0], flush=True)
            threading.Event().wait()
        value = operation()
        orchestrator.mark_step([state_record], name, 'done')
        return value

    def prepare():
        fixture.prepare()
        fixture.calls = fixture.calls[:2]

    step('prepare', prepare)
    for item in patches():
        item.start()

    def info(argv, *, timeout, output_limit):
        return fixture.fake(argv, timeout=30, output_limit=output_limit)

    vm = step('start', lambda: lifecycle.start(run, timeout=5, executor=info))
    step('resume', vm.resume)
    step('watch')
    step('shutdown', lambda: vm.request_shutdown(wait=30))
    step('close', vm.close)
    print('CLOSED', run._identity[0], flush=True)
    lease.release()


if __name__ == '__main__':
    if sys.argv[3:] == ['windows']:
        main_windows(sys.argv[1], sys.argv[2])
    else:
        main(sys.argv[1], sys.argv[2], sys.argv[3:] == ['reboot'])
