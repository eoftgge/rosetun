"""One owned Linux/KVM child, private QMP, and bounded confirmed termination.

QMP and QGA are UNIX sockets that QEMU listens on inside the private run
directory, so a later controller can connect to a live run again. One
controller at a time holds the run's control lock. There is no file cleanup,
guest readiness or qualification. Calls must be serialized by the caller.
Startup failures carry the VM handle so an unconfirmed child can still be
stopped without surrendering its lease.
"""

import json
import math
import os
from pathlib import Path
import platform
import select
import signal
import socket
import stat
import subprocess
import sys
import secrets
import threading
import time
from functools import wraps
from datetime import datetime, timezone

from .qmp_adapter import Qmp
from .qga import Qga, QgaError, LINE_LIMIT, DIAGNOSTIC_LINE_LIMIT
from .diagnostics import StderrSink

from .images import ImageDescriptor, image_chain, local_file
from .qemu import QemuConfig, CommandResult, _launch_plan, execute, OUTPUT_LIMIT
from .report import _unique_object, _invalid_constant
from .evidence import append_row
from .resources import resource_path, execution_resources, lock_run, unlock_run, RUN_LOCK
from . import run_state


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
QMP_SOCKET = 'qmp.sock'
QGA_SOCKET = 'qga.sock'
# sun_path holds 108 bytes with the terminating zero.
SOCKET_PATH_LIMIT = 107
# One planned guest reset takes two rows of the ordinary journal: `guest-reset-observed` when the controller sees
# the RESET event and `boot-chain-extended` when the new boot ID is confirmed. A refused reset takes one. Every RESET
# merged into it (below) takes one more, `guest-reset-coalesced`: 2 + RESET_MERGE_LIMIT = 6 rows for a reboot at most.
RESET_ROWS = 2
# Linux tries several ways to reset a machine in a row (the ACPI reset register, port 0xCF9, the keyboard controller),
# tens of milliseconds apart, and QEMU reports each one as a RESET. A guest RESET that QEMU stamped within this long of
# the first of a reboot belongs to it: no guest gets through firmware, bootloader and kernel to a userspace whose agent
# answers in one second, while the attempts of one reboot are two orders of magnitude closer (67 ms was seen).
RESET_MERGE_US = 1_000_000
# How many RESETs one reboot may take in after its first: Linux has about five ways to reset, so a fifth merged one is
# no reboot but a guest that keeps resetting, and ends the run.
RESET_MERGE_LIMIT = 4
# How long the controller lets QMP read events that already arrived, and how many agent sessions one reset may try.
RESET_PUMP_SECONDS = 0.25
# A guest that was reset may need most of a minute to answer, and a job may reboot it again soon after (Linux L4 did
# so 27 seconds after the first reset), so a boot not taken before the next RESET is `guest-reboot-unobserved`. The
# tries are therefore close together: 10 seconds at most for each and 5 between them, 12 in all. That covers about
# the time the 8 tries 15 seconds apart did (180 seconds against 200).
RESET_ATTEMPTS = 12
RESET_RETRY_SECONDS = 5
# What a refusal of a boot is called; each ends the run, so none of them is retried.
BOOT_REFUSALS = ('unplanned-guest-reset', 'host-reset-outside-reset', 'guest-reset-before-first-boot',
                 'boot-id-changed-without-reset', 'guest-reset-boot-id-unchanged', 'boot-id-repeated',
                 'guest-reboot-unobserved')


class LifecycleError(ValueError):
    def __init__(self, reason, vm=None):
        super().__init__(reason)
        self.vm = vm


class _BootRefused(Exception):
    """A boot ID the controller must not take; the observation row says why."""


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


def _private_directory(directory):
    """The run directory must be the controller user's alone: the sockets inside carry no other check."""
    if os.name != 'posix':
        return
    info = os.lstat(directory)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) & 0o077):
        raise LifecycleError('run-directory-not-private')


def socket_path(run_directory, name):
    path = resource_path(run_directory, name)
    if len(os.fsencode(str(path))) > SOCKET_PATH_LIMIT or ',' in str(path):
        raise LifecycleError('control-socket-path-unusable')
    return path


def _own_socket(path):
    info = os.lstat(path)
    if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) & 0o077):
        raise LifecycleError('control-socket-not-private')


def _open_control(path, timeout, alive, *, sleep=time.sleep, clock=time.monotonic):
    """Connect to one of QEMU's listening control sockets within `timeout` seconds.

    QEMU binds the socket while it starts, so a missing or refusing socket is
    retried while `alive()` holds. The socket is checked without following links.
    """
    deadline = clock() + _limit(timeout)
    while True:
        stream = None
        try:
            _own_socket(path)
            stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            stream.settimeout(max(.05, min(1, deadline - clock())))
            stream.connect(str(path))
            stream.settimeout(None)
            return stream
        except (FileNotFoundError, ConnectionRefusedError, socket.timeout):
            if stream is not None:
                stream.close()
            if not alive() or clock() >= deadline:
                raise LifecycleError('control-socket-unavailable') from None
            sleep(.05)
        except BaseException:
            if stream is not None:
                stream.close()
            raise


class ForeignProcess:
    """The QEMU of a run whose controller is gone, reached through a pidfd.

    The process is recorded by pid, host boot and start time; it is accepted
    only if all three still match, checked again after the pidfd is open, so a
    reused pid is refused and a signal can never reach another process. Its
    exit status belongs to its real parent: `returncode` stays None and
    `poll()` answers EXITED once the pidfd reports the exit.
    """

    EXITED = 'exit-status-unobservable'

    def __init__(self, resource):
        from .resources import _process_status
        self.pid = resource['pid']
        self.returncode = None
        self.fd = None
        if _process_status(resource) != 'alive':
            raise LifecycleError('vm-process-not-alive')
        try:
            self.fd = os.pidfd_open(self.pid)
        except (OSError, AttributeError):
            raise LifecycleError('vm-process-not-alive') from None
        try:
            same = (_process_status(resource) == 'alive'
                    and os.readlink(f'/proc/{self.pid}/exe') == os.path.realpath(resource['executable']))
        except OSError:
            same = False
        if not same:
            self.close()
            raise LifecycleError('vm-process-identity-mismatch')

    def poll(self):
        if self.fd is None:
            return self.EXITED
        ready, _, _ = select.select([self.fd], [], [], 0)
        return self.EXITED if ready else None

    def wait(self, timeout):
        if self.fd is not None and not select.select([self.fd], [], [], timeout)[0]:
            raise subprocess.TimeoutExpired('qemu', timeout)
        return None

    def terminate(self):
        signal.pidfd_send_signal(self.fd, signal.SIGTERM)

    def kill(self):
        signal.pidfd_send_signal(self.fd, signal.SIGKILL)

    def close(self):
        if self.fd is not None:
            fd, self.fd = self.fd, None
            os.close(fd)


def _journal_rows(run):
    """The number of rows of a complete, consecutive lifecycle journal: the journal is its own counter."""
    raw = resource_path(run.directory, 'lifecycle.jsonl').read_bytes()
    if raw and not raw.endswith(b'\n'):
        raise LifecycleError('lifecycle-journal-incomplete')
    rows = raw.splitlines()
    for index, line in enumerate(rows, 1):
        row = _json(line)
        if type(row) is not dict or row.get('sequence') != index or row.get('run_id') != run._identity[0]:
            raise LifecycleError('lifecycle-journal-incomplete')
    return len(rows)


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
        self.qga_path = None
        self.control_lock = None
        # The run's state on disk: the budgets below are recorded there before they are spent.
        self.state = None
        # Connected again by a later controller: the child is not ours to reap.
        self.attached = False
        self.qga_line_limit = LINE_LIMIT
        self._guest_lock = threading.Lock()
        self.qga_recoveries = 0
        self._sync_seed = secrets.randbits(63)
        self.last_boot_id = None
        self.reset_boot_id = None
        self.reset_pending = False
        # The boot IDs the controller confirmed, the first being the boot the job started on; the last is `last_boot_id`.
        self.boot_chain = []
        # Who made the pending reset: `guest` (a RESET event seen by the controller) or `controller` (`reset()`).
        self.reset_kind = None
        self.guest_resets = 0
        # QEMU's time (microseconds) of the first RESET of the reboot pending, and how many more were merged into it.
        self.reset_first_us = None
        self.reset_merged = 0
        self.unplanned_reset = None
        self._planned_reboots = 0
        self.qga_reason = 'initial'
        self.launch_sockets = []
        self.guest_observation = None
        self.wire = None
        self.qga_observations = 0
        self.exited = False
        self.events = 0
        self.vm_uuid = None
        self.stderr = None
        self.evidence_failed = False
        self.completed = False
        self.controls_closed = False
        self.operation_errors = []

    def _new_qmp(self, stream):
        if self.state is None:
            return Qmp(stream)
        budgets = self.state.document['budgets']
        return Qmp(stream, spent=dict(calls=budgets['qmp_calls'], events=budgets['qmp_events'],
                                      bytes=(budgets['qmp_bytes_o'], budgets['qmp_bytes_i'])),
                   persist=self.state.record)

    @property
    def planned_reboots(self):
        return self._planned_reboots

    @planned_reboots.setter
    def planned_reboots(self, value):
        """How many guest resets the run plans: more than that is an error, and each earns one QGA recovery."""
        if type(value) is not int or not 0 <= value <= run_state.MAX_PLANNED_REBOOTS:
            raise ValueError('invalid-planned-reboots')
        self._planned_reboots = value
        if self.state is not None:
            self.state.planned_reboots = value

    @property
    def qga_recovery_limit(self):
        return run_state.limit('qga_recoveries', self._planned_reboots)

    def _spend(self, name):
        """Record one more of a per-run budget before it is used; no record, no use."""
        if self.state is not None:
            self.state.planned_reboots = self._planned_reboots
            try:
                self.state.spend(name)
            except (OSError, ValueError):
                raise LifecycleError('run-state-budget-record-failed', self) from None

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

    def _alive(self):
        return self.process is not None and self.process.poll() is None

    def _new_qga(self):
        """A new session is a new connection; QEMU serves one client of the agent socket at a time."""
        if self.qga is not None and not self.qga.closed:
            raise LifecycleError('qga-old-session-not-closed', self)
        stream = _open_control(self.qga_path, self.timeout, self._alive)
        self.launch_sockets.append(stream)
        # Only a session that asks for a longer line says so, so that nothing else is told of the option.
        extra = {} if self.qga_line_limit == LINE_LIMIT else dict(line_limit=self.qga_line_limit)
        extra.update(self._qga_options())
        self.qga = Qga(stream, sync_id=(self._sync_seed + self.qga_recoveries) % 2**63, **extra)
        self.launch_sockets.remove(stream)

    def _qga_options(self):
        return {}

    @_guest_serialized
    def observe_guest(self):
        return self._observe_guest()

    @_guest_serialized
    def attach_guest(self):
        """Open an agent session for an attached VM; it is one of the run's recoveries."""
        self._check()
        if self.qga_path is None:
            raise LifecycleError('qga-not-configured', self)
        if self.qga is not None:
            raise LifecycleError('qga-session-exists', self)
        if self.qga_recoveries >= self.qga_recovery_limit:
            raise LifecycleError('qga-recovery-limit', self)
        self._spend('qga_recoveries')
        self.qga_recoveries += 1
        self.qga_reason = 'attach'
        try:
            self._new_qga()
        except (OSError, ValueError):
            raise LifecycleError('qga-attach-failed', self) from None
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
        if self.qga_path is None:
            raise LifecycleError('qga-not-configured', self)
        if self.process is None or self.process.poll() is not None or self.exited:
            raise LifecycleError('vm-child-has-exited', self)
        if self.qga_recoveries >= self.qga_recovery_limit:
            raise LifecycleError('qga-recovery-limit', self)
        if self.qga_observations >= 32:
            raise LifecycleError('qga-observation-limit', self)
        self._spend('qga_recoveries')
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
            self._spend('qga_observations')
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
        # A reset the guest made is told by QMP, not by the agent: take it in before judging any boot ID.
        self._sync_resets()
        if self.qga_observations >= 32:
            raise LifecycleError('qga-observation-limit', self)
        self._spend('qga_observations')
        self.qga_observations += 1
        row = dict(self._observation_row(), operation='recovery' if old_session_id else 'observe',
                   old_session_id=old_session_id, reason=self.qga_reason,
                   new_session_id=self.qga.session_id if old_session_id else None,
                   recovery_attempt=self.qga_recoveries)
        self.qga.deadline = deadline if deadline is not None else time.monotonic() + self.timeout
        kind = self.reset_kind
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
            if row['boot_comparison'] == 'changed' and not self.reset_pending:
                raise _BootRefused('boot-id-changed-without-reset')
            if self.reset_kind == 'guest' and self.reset_pending and row['boot_comparison'] == 'same':
                # The guest that made the reset is gone: an agent that still reports the old boot is no new boot.
                raise _BootRefused('guest-reset-boot-id-unchanged')
            if row['new_boot_confirmed'] and row['boot_id'] in self.boot_chain:
                raise _BootRefused('boot-id-repeated')
            self.last_boot_id = row['boot_id']
            if row['new_boot_confirmed']:
                self.reset_pending = False
                self.reset_kind = None
                self.reset_first_us, self.reset_merged = None, 0
            elif not self.boot_chain:
                self.boot_chain = [row['boot_id']]
            row['result'] = 'observed'
            row['sync_id'] = self.qga.sync_id
            self.qga_reason = 'explicit'
        except _BootRefused as error:
            self.qga_reason = row['result'] = str(error)
            self.operation_errors.append(str(error))
            raise LifecycleError(str(error), self) from None
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
        if row['new_boot_confirmed']:
            self._extend_chain(row['boot_id'], kind)
        self.guest_observation = row
        return row

    def watch_resets(self):
        """Read the resets QEMU has reported since the last look; an unplanned one is an error.

        The wait of a job calls it every few seconds, because QMP events are only read while the controller
        looks. It sends no command and spends no QMP budget, and it writes a row only for a reset it finds.
        """
        self._check()
        self._sync_resets()

    def _sync_resets(self):
        if self.unplanned_reset is not None:
            raise LifecycleError(self.unplanned_reset, self)
        if self.qmp is None:
            return
        try:
            self.qmp.pump(RESET_PUMP_SECONDS)
            resets = self.qmp.take_resets()
        except (OSError, ValueError):
            # A channel that failed earlier cannot tell a reset. A run that plans none still has the boot ID to
            # catch one (`boot-id-changed-without-reset`); a run that plans one cannot go on without the event.
            if self._planned_reboots == 0:
                return
            raise LifecycleError('qmp-events-unavailable', self) from None
        self._ingest_resets(resets)

    def _ingest_resets(self, resets, *, expected_host=0):
        """Register each RESET: only a guest's own reset within the plan is accepted, the host's `reset()` apart.

        A guest RESET that comes while the boot of an earlier one is unconfirmed, within `RESET_MERGE_US` of that one
        by QEMU's time, is the same reboot and spends nothing of the plan. One after that window is a reboot of a guest
        whose earlier boot was never observed, and ends the run: `guest-reboot-unobserved`.
        """
        for event in resets:
            if not event.guest and expected_host > 0:
                expected_host -= 1
                continue
            if not event.guest:
                self._refuse_reset('host-reset-outside-reset', event)
            if self._merges(event):
                self._merge_guest_reset(event)
                continue
            if self.reset_pending and self.reset_kind == 'guest':
                # The boot of the earlier reboot was never taken, so the chain would lose a boot ID.
                self._refuse_reset('guest-reboot-unobserved', event)
            if not self.boot_chain:
                self._refuse_reset('guest-reset-before-first-boot', event)
            if self.guest_resets >= self._planned_reboots:
                self._refuse_reset('unplanned-guest-reset', event)
            self._register_guest_reset(event)

    @staticmethod
    def _described(event):
        """What QEMU said of a RESET, as the tail of a journal result: its reason and its time, as far as it gave them."""
        text = '' if event is None or event.reason is None else ' reason=%s' % event.reason
        if event is not None and event.at is not None:
            text += ' qemu=%d.%06d' % divmod(event.at, 10**6)
        return text

    def _refuse_reset(self, reason, event=None):
        """An unplanned reset ends the run: no boot ID is taken after it, and the row says what was seen."""
        self.unplanned_reset = reason
        self.reset_pending = True
        self.operation_errors.append(reason)
        self._event('guest-reset-observed', reason + self._described(event))
        raise LifecycleError(reason, self)

    def _merges(self, event):
        """Whether a guest RESET is one more of the reboot already pending; with no time to judge by, it is not."""
        if not (self.reset_pending and self.reset_kind == 'guest' and self.unplanned_reset is None):
            return False
        if self.reset_first_us is None or event.at is None:
            return False
        return 0 <= event.at - self.reset_first_us <= RESET_MERGE_US

    def _merge_guest_reset(self, event):
        if self.reset_merged >= RESET_MERGE_LIMIT:
            self._refuse_reset('guest-reset-merge-limit', event)
        # The row of the merge and, still to come, the one that confirms the boot.
        self._reserve(RESET_ROWS)
        self.reset_merged += 1
        self._record_reset_time()
        self._event('guest-reset-coalesced', '%d-of-%d merged=%d +%dms%s' % (
            self.guest_resets, self._planned_reboots, self.reset_merged,
            (event.at - self.reset_first_us) // 1000, self._described(event)))

    def _record_reset_time(self):
        """Keep the first RESET's time and the merged count with the run state, so that an attached controller goes on."""
        if self.state is None or self.reset_first_us is None:
            return
        try:
            self.state.update('collected', **{'guest_reset_%d_us' % self.guest_resets: self.reset_first_us,
                                              'guest_reset_%d_merged' % self.guest_resets: self.reset_merged})
        except (OSError, ValueError):
            self.evidence_failed = True
            raise LifecycleError('run-state-write-failed', self) from None

    def _step(self, name, status):
        """One step of the run state, in the phase it is in; it says that a reset was seen or that its boot was taken."""
        if self.state is not None:
            try:
                self.state.transition(self.state.phase, name, status)
            except (OSError, ValueError):
                self.evidence_failed = True
                raise LifecycleError('run-state-write-failed', self) from None

    def _register_guest_reset(self, event):
        self._reserve(RESET_ROWS)
        self.guest_resets += 1
        self.reset_first_us, self.reset_merged = event.at, 0
        self._record_reset_time()
        # The intent goes to disk first: a controller that dies from here on is attached with the reset pending.
        self._step('guest-reset-%d' % self.guest_resets, 'intent')
        self.reset_boot_id = self.boot_chain[-1]
        self.reset_pending = True
        self.reset_kind = 'guest'
        self.qga_reason = 'guest-reset'
        self.guest_observation = None
        if self.qga is not None:
            self.qga.invalidate()
        self._event('guest-reset-observed', '%d-of-%d%s' % (self.guest_resets, self._planned_reboots,
                                                            self._described(event)))

    def _extend_chain(self, boot_id, kind):
        """Take a boot ID the controller confirmed: the run state first, then the journal."""
        if self.state is not None:
            try:
                self.state.planned_reboots = self._planned_reboots
                if not self.state.boot_chain:
                    # The run that never wrote its first boot into the state starts the chain here.
                    self.state.update('identities', boot_id=self.boot_chain[0])
                self.state.extend_boot_chain(boot_id)
            except (OSError, ValueError):
                self.evidence_failed = True
                raise LifecycleError('run-state-write-failed', self) from None
            if kind == 'guest':
                self._step('guest-reset-%d' % self.guest_resets, 'done')
        self.boot_chain.append(boot_id)
        self._event('boot-chain-extended', str(len(self.boot_chain)))

    def await_rebooted_guest(self, *, timeout, clock=time.monotonic, sleep=time.sleep):
        """After a planned guest reset: the one recovery it earns, then bounded tries until the new boot answers.

        The first try is `recover_guest` and spends the recovery. The guest needs a while to boot, so a try that
        fails is followed by new sessions that, like those of the first boot, spend no recovery but each one an
        observation. Every outcome that refuses a boot ends the run at once.
        """
        if not self.reset_pending or self.reset_kind != 'guest':
            raise LifecycleError('no-guest-reset-pending', self)
        deadline, previous = clock() + timeout, self.timeout
        try:
            for attempt in range(RESET_ATTEMPTS):
                remaining = deadline - clock()
                if remaining <= 0:
                    break
                self.timeout = min(10, remaining)
                try:
                    if attempt:
                        return self.observe_guest()
                    # A controller that attaches to a run with a reset pending has no session yet.
                    return self.attach_guest() if self.qga is None else self.recover_guest()
                except LifecycleError as error:
                    if (str(error) in BOOT_REFUSALS or self.process.poll() is not None or self.evidence_failed
                            or str(error) in ('qga-recovery-limit', 'qga-observation-limit')):
                        raise
                    if self.qga is not None:
                        self.qga.close()
                        if not self.qga.closed:
                            raise LifecycleError('rebooted-qga-close-unconfirmed', self)
                    self._sync_seed = (self._sync_seed + 1) % 2**63
                    self._new_qga()
                    sleep(min(RESET_RETRY_SECONDS, max(0, deadline - clock())))
            raise LifecycleError('rebooted-guest-deadline', self)
        finally:
            self.timeout = previous

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

    def set_link(self, up):
        """Raise or drop the carrier of this machine's lab wire; the journal says which and whether QEMU took it."""
        if type(up) is not bool:
            raise ValueError('invalid-link-state')
        self._check()
        if self.wire is None:
            raise LifecycleError('vm-has-no-wire', self)
        if self.process.poll() is not None:
            raise LifecycleError('vm-child-has-exited')
        action = 'link-up' if up else 'link-down'
        self._reserve(3)  # intent, command-accepted, error
        self._event(action, 'intent')
        try:
            self.qmp.command('set_link', self.timeout, arguments=dict(name=self.wire, up=up))
            self._event(action, 'command-accepted')
        except (OSError, ValueError):
            self.operation_errors.append(action + '-unconfirmed')
            self._event(action, 'error')
            raise LifecycleError('control-operation-unconfirmed', self) from None

    def pause(self):
        return self._control('stop', 'paused')

    def resume(self):
        return self._control('cont', 'running')

    @_guest_serialized
    def reset(self):
        """Confirm RESET, not guest boot readiness or a new guest boot ID."""
        self._check()
        # A reset the guest made before this one is registered first, so that this one is told apart from it.
        self._sync_resets()
        # intent, command-accepted, RESET-observed, confirmed, then on failure
        # command-accepted-event-unconfirmed and error.
        self._reserve(6)
        self.guest_observation = None
        self.reset_boot_id = self.last_boot_id
        self.reset_pending = True
        self.reset_kind = 'controller'
        self.qga_reason = 'reset'
        if self.qga is not None:
            self.qga.invalidate()
        self._event('reset', 'intent')
        try:
            self.qmp.command('system_reset', self.timeout, event='RESET')
            self._event('reset', 'command-accepted')
            self._event('reset', 'RESET-observed')
            self._event('reset', 'confirmed')
            value = self.status()
        except (OSError, ValueError):
            self.operation_errors.append('reset-unconfirmed')
            if getattr(self.qmp, 'last_command_accepted', False):
                self._event('reset', 'command-accepted-event-unconfirmed')
            self._event('reset', 'error')
            raise LifecycleError('reset-unconfirmed', self) from None
        # The one RESET this command caused has been read; anything else read with it is the guest's.
        self._ingest_resets(self.qmp.take_resets(), expected_host=1)
        return value

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
            self._event('exit', 'exit-observed' if self.attached else 'child-reaped', teardown=True)
            for stream in list(self.launch_sockets):
                stream.close()
                self.launch_sockets.remove(stream)
            if self.qmp is not None:
                self.qmp.close()
            if self.qga is not None:
                self.qga.close()
                self._event('qga', 'closed', teardown=True)
            elif self.attached and self.qga_path is not None:
                # This controller never opened an agent session, so none is left open.
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
                for control in (*self.launch_sockets, self.qmp, self.qga, self.stderr):
                    if control is not None:
                        try:
                            control.close()
                        except (OSError, ValueError):
                            controls_closed = False
                if controls_closed:
                    self.run._lease._active.discard(self)
                    if self.completed:
                        self._release_control_lock()

    def _release_control_lock(self):
        if isinstance(self.process, ForeignProcess):
            self.process.close()
        if self.control_lock is not None:
            lock, self.control_lock = self.control_lock, None
            try:
                unlock_run(lock)
            except (OSError, ValueError):
                pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def attach(run, *, timeout=5):
    """Connect again to the live VM of a run whose controller is gone.

    Refuses and leaves the run as it was unless the recorded process is alive
    with the same boot and start identity, this controller takes the run's
    control lock and QMP answers with the recorded UUID. The budgets continue
    from the run state; the journal continues from its last row.
    """
    timeout = _limit(timeout)
    manifest = run._read()
    resources = {r['id']: r for r in manifest['resources']}
    processes = [r for r in manifest['resources'] if r['kind'] == 'process']
    if (manifest['state'] not in ('starting', 'running', 'stopping') or len(processes) != 1
            or resources.get('qmp-socket', {}).get('kind') != 'socket'):
        raise LifecycleError('run-not-attachable')
    try:
        plan = _json(local_file(resource_path(run.directory, 'launch-plan.json')).read_bytes())
        vm_uuid = plan['uuid']
        # One in-memory copy per run: a second one would write back stale budgets.
        state = run_state.of(run) or run_state.RunState.load(run)
        events = _journal_rows(run)
    except (KeyError, TypeError, OSError, ValueError):
        raise LifecycleError('run-records-unusable') from None
    if state.document['host']['boot_id'] != run_state.host_boot_id():
        raise LifecycleError('host-boot-changed')
    process = ForeignProcess(processes[0])
    vm = Vm(run, timeout)
    vm.process, vm.attached, vm.state, vm.vm_uuid, vm.events = process, True, state, vm_uuid, events
    vm.qga_recoveries = state.budget('qga_recoveries')
    vm.qga_observations = state.budget('qga_observations')
    vm.boot_chain = list(state.document['boot_chain'])
    vm.last_boot_id = vm.boot_chain[-1] if vm.boot_chain else state.document['identities']['boot_id']
    # A reset whose intent is the last of its kind was seen by the dead controller, who did not confirm its boot.
    resets = [row for row in state.document['transitions'] if row['step'].startswith('guest-reset-')]
    vm.guest_resets = sum(row['status'] == 'intent' for row in resets)
    if resets and resets[-1]['status'] == 'intent' and vm.boot_chain:
        vm.reset_boot_id, vm.reset_pending, vm.reset_kind = vm.boot_chain[-1], True, 'guest'
        vm.qga_reason = 'guest-reset'
        # The merge window goes on from the time of the first RESET the dead controller recorded, if it recorded one.
        collected = state.document['collected']
        first = collected.get('guest_reset_%d_us' % vm.guest_resets)
        merged = collected.get('guest_reset_%d_merged' % vm.guest_resets)
        if type(first) is int and type(merged) is int and 0 <= merged <= RESET_MERGE_LIMIT:
            vm.reset_first_us, vm.reset_merged = first, merged
    try:
        vm.control_lock = lock_run(run.directory)
    except (OSError, ValueError):
        process.close()
        raise LifecycleError('run-control-locked') from None
    if 'qga-socket' in resources:
        vm.qga_path = socket_path(run.directory, QGA_SOCKET)
    run._lease._active.add(vm)
    try:
        stream = _open_control(socket_path(run.directory, QMP_SOCKET), timeout, vm._alive)
        vm.launch_sockets.append(stream)
        vm.qmp = vm._new_qmp(stream)
        vm.launch_sockets.remove(stream)
        vm.qmp.handshake(timeout)
        if vm.qmp.command('query-uuid', timeout) != {'UUID': vm_uuid}:
            raise LifecycleError('qmp-uuid-mismatch')
        vm._event('attach', 'qmp-connected')
    except BaseException as error:
        # Leave the run as it was found: disconnect, give the lock back, never signal.
        for control in (*vm.launch_sockets, vm.qmp):
            if control is not None:
                try:
                    control.close()
                except (OSError, ValueError):
                    pass
        run._lease._active.discard(vm)
        vm._release_control_lock()
        if not isinstance(error, Exception):
            raise
        raise LifecycleError(str(error) if isinstance(error, LifecycleError) else 'qmp-attach-failed') from None
    return vm


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
    stage = 'l2'
    if any(r['id'].startswith('l2-media-') for r in manifest['resources']):
        from .l2_media import resources
        # The media registers the paths of its own stage profile, named by its record.
        try:
            record = _json(local_file(resource_path(run.directory, 'launch-plan.json')).read_bytes())
            stage = record['l2_media']['package'].get('profile', 'l2')
            resources(stage)
        except (KeyError, TypeError, AttributeError, OSError, ValueError):
            raise LifecycleError('l2-media-preparation-incomplete') from None
        expected.update({'l2-media-' + str(i): n for i, n in enumerate(resources(stage))})
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
    _private_directory(run.directory)
    sockets = {'qmp-socket': socket_path(run.directory, QMP_SOCKET)}
    if config.qga:
        sockets['qga-socket'] = socket_path(run.directory, QGA_SOCKET)
    if any(os.path.lexists(path) for path in (*sockets.values(), resource_path(run.directory, RUN_LOCK))):
        raise LifecycleError('control-path-exists')
    # No process exists yet, so a failure here leaves partial resources and a
    # quarantined run instead of a prepared one that later starts refuse.
    try:
        run.register({'id': 'control-lock', 'kind': 'file', 'path': RUN_LOCK})
        for identifier, path in sockets.items():
            run.register({'id': identifier, 'kind': 'socket', 'path': path.name})
        if not any(r['id'] == run_state.RESOURCE['id'] for r in manifest['resources']):
            # A run whose controller keeps no state of its own still gets one for its budgets.
            run.register(dict(run_state.RESOURCE))
        state = run_state.of(run) or run_state.RunState.create(run, phase='running')
        for name in (('qemu-stderr.log', 'completion.json', 'qga-observations.jsonl', 'job-evidence.jsonl')
                     if config.qga else ('qemu-stderr.log', 'completion.json')):
            run.register({'id': name.split('.')[0], 'kind': 'file', 'path': name})
        if config.qga:
            from .linux_l2 import evidence_files
            for index, name in enumerate(evidence_files(stage)):
                relative = 'linux-' + stage + '/' + name
                run.register({'id': 'linux-' + stage + '-' + str(index), 'kind': 'file', 'path': relative})
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
    vm.state = state
    if lab is not None and getattr(lab, 'journal_full', False) and lab.role(run) == 'test':
        # The whole journal of the service comes back in one reply, which the ordinary limit would end.
        vm.qga_line_limit = DIAGNOSTIC_LINE_LIMIT
    vm.vm_uuid = plan['uuid']
    vm.wire = f'{lab.role(run)}-wire' if lab is not None else None
    vm._l2_media = media
    run._lease._active.add(vm)
    try:
        run.mark('starting')
        vm._event('start', 'intent', teardown=True)
        vm.control_lock = lock_run(run.directory)
        vm.stderr = StderrSink(resource_path(run.directory, 'qemu-stderr.log'), run._identity[2])
        # QEMU listens and the controller connects, so the channels outlive the controller.
        argv = [*plan['argv'], '-S', '-chardev', f'socket,id=control,path={sockets["qmp-socket"]},server=on,wait=off',
                '-mon', 'chardev=control,mode=control']
        descriptors = []
        if lab is not None:
            network_argv, network_fd = lab.network(run)
            argv += network_argv
            descriptors.append(network_fd)
        if config.qga:
            vm.qga_path = sockets['qga-socket']
            argv += ['-chardev', f'socket,id=guestagent,path={vm.qga_path},server=on,wait=off',
                     '-device', 'virtio-serial-pci,id=guestserial',
                     '-device', 'virtserialport,bus=guestserial.0,chardev=guestagent,name=org.qemu.guest_agent.0']
            resource_path(run.directory, 'qga-observations.jsonl').touch(exist_ok=False)
            resource_path(run.directory, 'job-evidence.jsonl').touch(exist_ok=False)
        run._read()
        if media is not None:
            verify_media(media)
        # umask 0177: QEMU creates the sockets owner read-write only.
        vm.process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                      stderr=subprocess.PIPE, shell=False, close_fds=True, bufsize=0,
                                      pass_fds=tuple(descriptors), start_new_session=True, umask=0o177)
        vm.stderr.start(vm.process.stderr)
        run.register(_identity(vm.process, config.executable))
        stream = _open_control(sockets['qmp-socket'], timeout, vm._alive)
        vm.launch_sockets.append(stream)
        vm.qmp = vm._new_qmp(stream)
        vm.launch_sockets.remove(stream)
        vm.qmp.handshake(timeout)
        if vm.qmp.command('query-uuid', timeout) != {'UUID': plan['uuid']}:
            raise LifecycleError('qmp-uuid-mismatch')
        kvm = vm.qmp.command('query-kvm', timeout)
        if type(kvm) is not dict or kvm.get('enabled') is not True or kvm.get('present') is not True:
            raise LifecycleError('qmp-kvm-not-enabled')
        if vm.status()['status'] != 'prelaunch':
            raise LifecycleError('qmp-initial-state-mismatch')
        if config.qga:
            vm._new_qga()
        state.update('identities', vm_uuid=plan['uuid'])
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
        if vm.process is None and not vm.completed:
            # Nothing was spawned, so nothing can still need the lock.
            vm._release_control_lock()
