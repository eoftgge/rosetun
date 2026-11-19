"""Bounded, serialized QGA client session of a Linux or a Windows guest.

Only the initial delimited sync is framed here. All subsequent RPC framing and
IDs belong to public qemu.qmp. Any uncertain exchange poisons this session.

A Windows guest (stage 9c) differs in three things: its boot identity is read by a PowerShell command, as it has no
`boot_id` file; the agent's `guest-exec` starts a program without a shell and the console's code page is not UTF-8, so
a command writes its answer to the raw standard streams as UTF-8 bytes; and a program is waited for by polling its
status, with the output of each stream bounded.
"""

import asyncio
import base64
import json
import math
import secrets
import time
import uuid
from importlib.metadata import version

from . import windows_guest
from .qmp_adapter import ByteRelay
from .report import _unique_object, _invalid_constant

REQUIRED = ('guest-sync-delimited', 'guest-ping', 'guest-info',
            'guest-file-open', 'guest-file-read', 'guest-file-close')


# The longest line of the agent's reply that the client reads, and the longer one the test machine of a
# diagnostic run allows itself: the reply that carries the output of `journalctl` is one line, the output
# arrives base64-encoded and the agent captures up to 16 MiB, so it needs 4/3 of that and some room.
LINE_LIMIT = 65536
DIAGNOSTIC_LINE_LIMIT = 24 * 1024 * 1024
# The relay between the agent's socket and the client also stops a session that passes a megabyte in one direction
# (`ByteRelay`), so the session that reads the long reply is given the room for it and for what comes before it.
DIAGNOSTIC_RELAY_LIMIT = 2 * DIAGNOSTIC_LINE_LIMIT


# What one program started through `guest-exec` may say on each of its two streams, and how often its status is asked
# for: the first look comes soon (a small program is done within a second), the later ones are spaced out because each
# one spends one of the session's 128 calls: a program that is waited for 300 seconds takes about 60 of them.
EXEC_OUTPUT_LIMIT = 64 * 1024
EXEC_POLL_SECONDS = (0.25, 0.5, 1.0, 2.0, 5.0)
GUEST_SYSTEMS = ('linux', 'windows')


class QgaError(ValueError):
    pass


class ExecResult:
    """What a program run through the agent returned: its exit code and the bytes of its two streams."""

    def __init__(self, exitcode, stdout, stderr):
        self.exitcode, self.stdout, self.stderr = exitcode, stdout, stderr


def _timeout(value):
    if type(value) not in (int, float) or not math.isfinite(value) or not 0 < value <= 60:
        raise QgaError('invalid-qga-timeout')
    return value


class Qga:
    def __init__(self, stream, *, client_factory=None, relay_factory=ByteRelay, sync_id=None, line_limit=LINE_LIMIT,
                 on_call=None, guest_os='linux'):
        if line_limit not in (LINE_LIMIT, DIAGNOSTIC_LINE_LIMIT):
            raise QgaError('invalid-qga-line-limit')
        if guest_os not in GUEST_SYSTEMS:
            raise QgaError('invalid-qga-guest-os')
        self.guest_os = guest_os
        self.sleep = time.sleep
        self.line_limit = line_limit
        self.stream = stream
        self.client_factory = client_factory
        self.relay_factory = relay_factory
        self.session_id = str(uuid.uuid4())
        self.client = self.relay = self.loop = None
        self.attempted = self.closed = self.valid = False
        self.info = None
        self.stderr_text = None
        self.calls = 0
        self.rpc_error = ()
        self.sync_id = sync_id
        self.deadline = None
        self.jobs_enabled = False
        self.staging_enabled = False
        self._operation_limit = 128
        # Records one more call of the run before it is sent; raises when it cannot.
        self.on_call = on_call

    def connect(self, timeout):
        """Synchronize once, then hand the clean stream to the library."""
        timeout = _timeout(timeout)
        if self.attempted or self.closed:
            raise QgaError('qga-reconnect-unsupported')
        self.attempted = True
        try:
            factory = self.client_factory
            if factory is None:
                if version('qemu.qmp') != '0.0.6':
                    raise QgaError('qemu-qmp-0.0.6-required')
                from qemu.qmp import QMPClient, ExecuteError
                self.rpc_error = ExecuteError
                factory = QMPClient
            deadline = time.monotonic() + timeout
            if self.deadline is not None:
                deadline = min(deadline, self.deadline)
            sync_id = self.sync_id if self.sync_id is not None else secrets.randbits(63)
            self.sync_id = sync_id
            self.stream.settimeout(_timeout(deadline - time.monotonic()))
            self.stream.sendall(b'\xff' + json.dumps({
                'execute': 'guest-sync-delimited', 'arguments': {'id': sync_id}}).encode() + b'\n')
            buffer = bytearray()
            sentinel = False
            for _ in range(65536):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise QgaError('qga-sync-timeout')
                self.stream.settimeout(remaining)
                byte = self.stream.recv(1)
                if not byte:
                    raise QgaError('qga-sync-eof')
                if byte == b'\xff':
                    buffer.clear()
                    sentinel = True
                elif sentinel:
                    buffer.extend(byte)
                    if byte == b'\n':
                        try:
                            value = json.loads(buffer.decode('utf-8'), object_pairs_hook=_unique_object,
                                               parse_constant=_invalid_constant)
                        except (ValueError, UnicodeError, RecursionError):
                            value = None
                        buffer.clear()
                        if (type(value) is dict and type(value.get('return')) is int
                                and value['return'] == sync_id and 'error' not in value):
                            break
            else:
                raise QgaError('qga-sync-byte-limit')
            self.loop = asyncio.new_event_loop()
            self.client = factory(readbuflen=self.line_limit)
            self.client.await_greeting = False
            self.client.negotiate = False
            self.client.events.accept = lambda event: False
            # Only a session that asked for the longer line is told of the longer relay, as with the line.
            options = {} if self.line_limit == LINE_LIMIT else dict(limit=DIAGNOSTIC_RELAY_LIMIT)
            self.relay = self.relay_factory(self.stream, **options)
            self.valid = True
            remaining = deadline - time.monotonic()
            remaining = _timeout(remaining)
            self._run(self.client.connect(self.relay.client), remaining)
        except BaseException as error:
            self.valid = False
            if not isinstance(error, Exception):
                raise
            raise QgaError('qga-connect-failed') from None

    def _run(self, coroutine, timeout):
        try:
            return self.loop.run_until_complete(asyncio.wait_for(coroutine, timeout))
        except BaseException as error:
            if isinstance(error, self.rpc_error):
                raise QgaError('qga-rpc-rejected') from None
            self.valid = False
            if not isinstance(error, Exception):
                raise
            raise QgaError('qga-exchange-failed') from None

    def _rpc(self, name, timeout, arguments=None):
        timeout = _timeout(timeout)
        if not self.valid or self.closed:
            raise QgaError('qga-unavailable-explicit-recovery-required')
        if self.deadline is not None:
            timeout = min(timeout, self.deadline - time.monotonic())
            if timeout <= 0:
                self.invalidate()
                raise QgaError('qga-operation-timeout')
        # Reserve the final RPC for closing a known guest file handle. A local
        # budget rejection does not make the stream's last result uncertain.
        limit = min(128, self._operation_limit)
        if self.calls >= limit or (self.calls >= limit - 1 and name != 'guest-file-close'):
            raise QgaError('qga-command-limit')
        if self.on_call is not None:
            try:
                self.on_call()
            except (OSError, ValueError):
                raise QgaError('qga-budget-record-failed') from None
        self.calls += 1
        return self._run(self.client.execute(name, arguments), timeout)

    def probe(self, timeout):
        self.info = None
        info = self._rpc('guest-info', timeout)
        if (type(info) is not dict or type(info.get('version')) is not str
                or not 0 < len(info['version']) <= 128
                or any(ord(c) < 32 for c in info['version'])
                or type(info.get('supported_commands')) is not list):
            raise QgaError('invalid-qga-info')
        commands = {}
        for entry in info['supported_commands']:
            if (type(entry) is not dict or type(entry.get('name')) is not str
                    or entry['name'] in commands or type(entry.get('enabled')) is not bool
                    or type(entry.get('success-response')) is not bool):
                raise QgaError('invalid-qga-capability')
            commands[entry['name']] = entry
        # A Windows guest has no boot ID file: its identity and its evidence come from programs the agent runs.
        required = REQUIRED + (('guest-exec', 'guest-exec-status') if self.jobs_enabled or self.windows else ())
        if self.staging_enabled:
            required += ('guest-file-write',)
            if not (self.jobs_enabled or self.windows):
                required += ('guest-exec', 'guest-exec-status')
        if any(name not in commands or not commands[name]['enabled']
               or not commands[name]['success-response'] for name in required):
            raise QgaError('qga-required-rpc-unsupported')
        if self._rpc('guest-ping', timeout) != {}:
            raise QgaError('invalid-qga-ping')
        self.info = {'version': info['version'], 'required_commands': list(required)}
        return dict(self.info)

    @property
    def windows(self):
        return self.guest_os == 'windows'

    def start_program(self, path, arguments, timeout, *, capture=False):
        """Start one program in the guest and return its process id, without waiting for it.

        `guest-exec` is CreateProcess without a shell, so `path` is a full path and `arguments` are the words of the
        command line. A program that takes the guest down (a restart) must be started this way: the agent goes with
        the guest, and its status would never be answered.
        """
        if self.info is None:
            raise QgaError('qga-probe-required')
        if (type(path) is not str or not path or type(arguments) is not list
                or any(type(item) is not str for item in arguments)):
            raise QgaError('invalid-qga-exec-request')
        started = self._rpc('guest-exec', timeout,
                            {'path': path, 'arg': arguments, 'capture-output': 'separated' if capture else False})
        if (type(started) is not dict or set(started) != {'pid'} or type(started['pid']) is not int
                or not 0 < started['pid'] < 2**31):
            self.invalidate()
            raise QgaError('invalid-qga-exec-pid')
        return started['pid']

    def run_program(self, path, arguments, timeout, *, seconds=60, output_limit=EXEC_OUTPUT_LIMIT):
        """Start one program in the guest and wait for it: its exit code and both streams, each within `output_limit`.

        `timeout` is for each exchange and `seconds` for the whole program, which the session's own deadline shortens.
        The streams come back apart (`separated`; the agent has no merged mode on Windows). A program that outlives
        the time leaves the session unusable: it may be running, and nothing here kills it.
        """
        pid = self.start_program(path, arguments, timeout, capture=True)
        end = time.monotonic() + seconds
        if self.deadline is not None:
            end = min(end, self.deadline)
        for poll in range(1000):
            self.sleep(max(0, min(EXEC_POLL_SECONDS[min(poll, len(EXEC_POLL_SECONDS) - 1)], end - time.monotonic())))
            status = self._rpc('guest-exec-status', timeout, {'pid': pid})
            if type(status) is not dict or type(status.get('exited')) is not bool:
                self.invalidate()
                raise QgaError('invalid-qga-exec-status')
            if status['exited']:
                return self._exec_result(status, output_limit)
            if time.monotonic() >= end:
                self.invalidate()
                raise QgaError('qga-exec-timeout')
        self.invalidate()
        raise QgaError('qga-exec-poll-limit')

    @staticmethod
    def _exec_result(status, output_limit):
        exitcode = status.get('exitcode')
        # On Windows an unhandled exception is told as `signal`, not as an exit code.
        if type(exitcode) is not int or 'signal' in status:
            raise QgaError('qga-exec-no-exit-code')
        streams = []
        for name in ('out', 'err'):
            encoded = status.get(name + '-data', '')
            if (type(encoded) is not str or len(encoded) > 4 * output_limit // 3 + 4
                    or status.get(name + '-truncated', False) is not False):
                raise QgaError('qga-exec-output-limit')
            try:
                data = base64.b64decode(encoded, validate=True)
            except (ValueError, UnicodeError):
                raise QgaError('invalid-qga-exec-output') from None
            if base64.b64encode(data).decode() != encoded or len(data) > output_limit:
                raise QgaError('invalid-qga-exec-output')
            streams.append(data)
        return ExecResult(exitcode, *streams)

    def powershell(self, script, timeout, *, seconds=60):
        """Run a PowerShell 5.1 script in a Windows guest: the text it returned, decoded as UTF-8.

        A non-zero exit code or an answer that is not UTF-8 is an error that names no guest text; what the script
        wrote on its error stream stays in `stderr_text` for the evidence.
        """
        if not self.windows:
            raise QgaError('qga-powershell-needs-windows')
        result = self.run_program(windows_guest.POWERSHELL, windows_guest.arguments(script), timeout,
                                  seconds=seconds)
        try:
            text, self.stderr_text = result.stdout.decode('utf-8'), result.stderr.decode('utf-8')
        except UnicodeError:
            raise QgaError('invalid-qga-powershell-output') from None
        if result.exitcode != 0:
            raise QgaError('qga-powershell-failed')
        return text

    def read_boot_id(self, timeout):
        if self.info is None:
            raise QgaError('qga-probe-required')
        if self.windows:
            # `reg.exe` answers at once; a PowerShell would take a minute on the first boot of the image.
            result = self.run_program(windows_guest.REG, list(windows_guest.BOOT_ARGUMENTS), timeout, seconds=30)
            if result.exitcode != 0:
                raise QgaError('qga-boot-id-failed')
            try:
                return windows_guest.boot_id(result.stdout)
            except windows_guest.GuestAnswerError:
                raise QgaError('invalid-windows-boot-id') from None
        handle = self._rpc('guest-file-open', timeout,
                           {'path': '/proc/sys/kernel/random/boot_id', 'mode': 'r'})
        if type(handle) is not int or not 0 <= handle < 2**63:
            self.valid = False
            raise QgaError('invalid-qga-file-handle')
        try:
            data = bytearray()
            for _ in range(64):
                value = self._rpc('guest-file-read', timeout, {'handle': handle, 'count': 64})
                if (type(value) is not dict or type(value.get('count')) is not int
                        or not 0 <= value['count'] <= 64 or type(value.get('eof')) is not bool
                        or type(value.get('buf-b64')) is not str
                        or len(value['buf-b64']) > 88):
                    raise QgaError('invalid-qga-file-read')
                try:
                    block = base64.b64decode(value['buf-b64'], validate=True)
                except (ValueError, UnicodeError):
                    raise QgaError('invalid-qga-base64') from None
                if (base64.b64encode(block).decode() != value['buf-b64']
                        or len(block) != value['count'] or len(data) + len(block) > 64):
                    raise QgaError('invalid-qga-file-count')
                data.extend(block)
                if value['eof']:
                    break
                if not block:
                    raise QgaError('qga-file-no-progress')
            else:
                raise QgaError('qga-file-read-limit')
            try:
                text = data.decode('ascii')
                boot = text.removesuffix('\n')
                if str(uuid.UUID(boot)) != boot or uuid.UUID(boot).int == 0:
                    raise ValueError
            except (ValueError, UnicodeError):
                raise QgaError('invalid-linux-boot-id') from None
            return boot
        finally:
            # After timeout _rpc refuses further traffic: handle closure is then
            # uncertain and the session cannot be reused. Never retry an open.
            if self.valid:
                if self._rpc('guest-file-close', timeout, {'handle': handle}) != {}:
                    self.valid = False
                    raise QgaError('invalid-qga-file-close')

    def invalidate(self):
        self.attempted = True
        self.valid = False
        self.info = None

    def close(self):
        if self.closed:
            return
        self.invalidate()
        disconnected = True
        try:
            if self.client is not None:
                try:
                    self.loop.run_until_complete(asyncio.wait_for(self.client.disconnect(), 1))
                except Exception:
                    # A failed exchange can be re-raised by disconnect after
                    # reaching IDLE. Only that public state confirms quiescence.
                    state = getattr(self.client, 'runstate', None)
                    disconnected = getattr(state, 'name', None) == 'IDLE'
        finally:
            if self.relay is not None:
                self.relay.close()
            self.stream.close()
            if self.loop is not None and not self.loop.is_closed():
                tasks = asyncio.all_tasks(self.loop)
                for task in tasks:
                    task.cancel()
                if tasks:
                    _, pending = self.loop.run_until_complete(asyncio.wait(tasks, timeout=1))
                    if pending:
                        raise QgaError('qga-close-unconfirmed')
                if not disconnected:
                    raise QgaError('qga-disconnect-unconfirmed')
                self.loop.close()
            self.closed = True
