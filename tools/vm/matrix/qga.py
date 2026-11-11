"""Bounded, serialized Linux QGA client session.

Only the initial delimited sync is framed here. All subsequent RPC framing and
IDs belong to public qemu.qmp. Any uncertain exchange poisons this session.
"""

import asyncio
import base64
import json
import math
import secrets
import time
import uuid
from importlib.metadata import version

from .qmp_adapter import ByteRelay
from .report import _unique_object, _invalid_constant

REQUIRED = ('guest-sync-delimited', 'guest-ping', 'guest-info',
            'guest-file-open', 'guest-file-read', 'guest-file-close')


class QgaError(ValueError):
    pass


def _timeout(value):
    if type(value) not in (int, float) or not math.isfinite(value) or not 0 < value <= 60:
        raise QgaError('invalid-qga-timeout')
    return value


class Qga:
    def __init__(self, stream, *, client_factory=None, relay_factory=ByteRelay, sync_id=None):
        self.stream = stream
        self.client_factory = client_factory
        self.relay_factory = relay_factory
        self.session_id = str(uuid.uuid4())
        self.client = self.relay = self.loop = None
        self.attempted = self.closed = self.valid = False
        self.info = None
        self.calls = 0
        self.rpc_error = ()
        self.sync_id = sync_id
        self.deadline = None
        self.jobs_enabled = False
        self.staging_enabled = False
        self._operation_limit = 128

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
            self.client = factory(readbuflen=65536)
            self.client.await_greeting = False
            self.client.negotiate = False
            self.client.events.accept = lambda event: False
            self.relay = self.relay_factory(self.stream)
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
        required = REQUIRED + (('guest-exec', 'guest-exec-status') if self.jobs_enabled else ())
        if self.staging_enabled:
            required += ('guest-file-write',)
            if not self.jobs_enabled:
                required += ('guest-exec', 'guest-exec-status')
        if any(name not in commands or not commands[name]['enabled']
               or not commands[name]['success-response'] for name in required):
            raise QgaError('qga-required-rpc-unsupported')
        if self._rpc('guest-ping', timeout) != {}:
            raise QgaError('invalid-qga-ping')
        self.info = {'version': info['version'], 'required_commands': list(required)}
        return dict(self.info)

    def read_boot_id(self, timeout):
        if self.info is None:
            raise QgaError('qga-probe-required')
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
