"""Synchronous serialized facade over public qemu.qmp 0.0.6 APIs.

The byte relay enforces a lifetime budget without inspecting or framing JSON.
No library internals or legacy APIs are used. Imports remain execution-only.
"""

import asyncio
import json
import math
from importlib.metadata import version
from typing import NamedTuple
import re
import select
import socket
import threading


_REASON = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}')


class ResetEvent(NamedTuple):
    """One QMP `RESET`: whether the guest made it, QEMU's `reason` (since 6.0) and its time, each None if absent.

    `at` is QEMU's own timestamp of the event in microseconds since the epoch; it is read from the event, never from
    the moment the controller looked, so two resets QEMU sent a few milliseconds apart stay that far apart.
    """

    guest: bool
    reason: str = None
    at: int = None


def _arguments_valid(name, arguments):
    if name == 'set_link':
        return (set(arguments) == {'name', 'up'} and type(arguments['up']) is bool
                and arguments['name'] in ('test-wire', 'lab-wire'))
    # A screenshot goes to one absolute file of the run directory, which the caller chose; QEMU writes it.
    path = arguments.get('filename')
    return (set(arguments) == {'filename', 'format'} and arguments['format'] in ('png', 'ppm')
            and type(path) is str and path.startswith('/') and ',' not in path
            and not any(ord(c) < 32 for c in path))


# Bytes the relay may move past what is already on record before it records more.
RESERVATION_BYTES = 65536


class ByteRelay:
    """Copy bytes between a control socket and the client within a byte budget.

    `used` is what earlier relays of the same budget already moved; `reserve`,
    when given, records a new ceiling before bytes past the previous one are
    forwarded, so a controller that dies mid-exchange never hands a fresh
    budget to the next one. A failed record stops the relay.
    """

    def __init__(self, stream, limit=1024 * 1024, *, used=(0, 0), reserve=None):
        self.client, self.peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.stream = stream
        self.limit = limit
        self.counts = list(used)
        self.reserved = list(used)
        self.reserve = reserve
        self.stop = threading.Event()
        self.failed = False
        self.thread = threading.Thread(target=self._run, daemon=True)
        try:
            self.thread.start()
        except BaseException:
            for endpoint in (self.client, self.peer):
                try:
                    endpoint.close()
                except (OSError, ValueError):
                    pass
            raise

    def _run(self):
        sockets = [self.stream, self.peer]
        buffers = [bytearray(), bytearray()]
        counts = self.counts
        eof = set()
        try:
            for stream in sockets:
                stream.setblocking(False)
            while not self.stop.is_set():
                if eof and not any(buffers):
                    return
                readers = [s for i, s in enumerate(sockets)
                           if s not in eof and len(buffers[1-i]) < 65536]
                writers = [s for i, s in enumerate(sockets) if buffers[i]]
                ready, writable, _ = select.select(readers, writers, [], 0.05)
                for stream in ready:
                    index = sockets.index(stream)
                    block = stream.recv(min(4096, 65536 - len(buffers[1-index])))
                    if not block:
                        # Preserve replies already read before a peer's EOF.
                        eof.add(stream)
                        continue
                    counts[index] += len(block)
                    if counts[index] > self.limit:
                        self.failed = True
                        return
                    if self.reserve is not None and counts[index] > self.reserved[index]:
                        self.reserved[index] = min(self.limit, counts[index] + RESERVATION_BYTES)
                        self.reserve(index, self.reserved[index])
                    buffers[1-index].extend(block)
                for stream in writable:
                    index = sockets.index(stream)
                    sent = stream.send(buffers[index])
                    del buffers[index][:sent]
        except (OSError, ValueError):
            self.failed = True
        finally:
            for stream in sockets:
                try:
                    stream.close()
                except (OSError, ValueError):
                    self.failed = True

    def close(self):
        self.stop.set()
        errors = False
        try:
            self.client.close()
        except (OSError, ValueError):
            errors = True
        self.thread.join(timeout=1)
        if self.thread.is_alive():
            raise ValueError('qmp-relay-close-unconfirmed')
        # A stopped worker alone does not confirm closure: its finally may have
        # encountered an endpoint error. Retry every endpoint under this owner.
        for stream in (self.stream, self.peer):
            try:
                stream.close()
            except (OSError, ValueError):
                errors = True
        if errors:
            raise ValueError('qmp-relay-close-unconfirmed')


class Qmp:
    """`spent` and `persist` carry the run's QMP budget across controllers.

    `spent` holds what earlier connections used (`calls`, `events`, `bytes`);
    `persist(name, value)` records a new count before it is used and raises on
    failure. Without them the budget belongs to this object, as before.
    """

    def __init__(self, stream, *, client_factory=None, relay_factory=ByteRelay, spent=None, persist=None):
        if client_factory is None:
            if version('qemu.qmp') != '0.0.6':
                raise ValueError('qemu-qmp-0.0.6-required')
            from qemu.qmp import QMPClient
            client_factory = QMPClient
        self.loop = asyncio.new_event_loop()
        self.client = client_factory(readbuflen=65536)
        # The default listener cannot be removed. Its public accept hook is
        # explicitly extensible; reject retention while counting every event.
        self.client.events.accept = self._event
        spent = spent or {}
        self.events = spent.get('events', 0)
        self.calls = spent.get('calls', 0)
        self.persist = persist
        # What each RESET event said, in order, as `ResetEvent`s.
        self.resets = []
        self.valid = True
        self.closed = False
        if persist is None:
            self.relay = relay_factory(stream)
        else:
            self.relay = relay_factory(stream, used=tuple(spent.get('bytes', (0, 0))),
                                       reserve=lambda index, value: persist('qmp_bytes_' + 'oi'[index], value))

    def _event(self, event):
        self.events += 1
        if self.events > 128 or len(bytes(event)) > 65536:
            raise ValueError('qmp-event-limit')
        if self.persist is not None:
            self.persist('qmp_events', self.events)
        self._note_reset(event)
        return False

    def _note_reset(self, event):
        try:
            message = json.loads(bytes(event))
        except ValueError:
            return
        if type(message) is dict and message.get('event') == 'RESET':
            data = message.get('data')
            data = data if type(data) is dict else {}
            reason = data.get('reason')
            stamp = message.get('timestamp')
            stamp = stamp if type(stamp) is dict else {}
            seconds, micro = stamp.get('seconds'), stamp.get('microseconds')
            ok = (type(seconds) is int and type(micro) is int and 0 <= seconds < 2**40 and 0 <= micro < 10**6)
            self.resets.append(ResetEvent(
                data.get('guest') is True,
                reason if type(reason) is str and _REASON.fullmatch(reason) else None,
                seconds * 10**6 + micro if ok else None))

    def take_resets(self):
        """The RESET events read since the last call, oldest first, each a `ResetEvent`."""
        taken, self.resets = self.resets, []
        return taken

    def pump(self, seconds):
        """Let events that already arrived be read, which only happens while the loop runs; no command, no budget."""
        async def idle():
            await asyncio.sleep(seconds)

        return self._run(idle(), seconds + 1)

    def _run(self, coroutine, timeout):
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 60:
            coroutine.close()
            raise ValueError('invalid-qmp-timeout')
        if not self.valid:
            coroutine.close()
            raise ValueError('qmp-unavailable')
        try:
            return self.loop.run_until_complete(asyncio.wait_for(coroutine, timeout))
        except BaseException as error:
            self.valid = False
            if not isinstance(error, Exception):
                raise
            raise ValueError('qmp-exchange-failed') from None

    def handshake(self, timeout):
        return self._run(self.client.connect(self.relay.client), timeout)

    def command(self, name, timeout, *, event=None, arguments=None):
        if name not in ('query-status', 'query-uuid', 'query-kvm', 'stop', 'cont',
                        'system_reset', 'system_powerdown', 'quit', 'set_link', 'screendump'):
            raise ValueError('unsupported-qmp-command')
        # Only the carrier of a lab wire and a screenshot take arguments, and only these.
        if (arguments is not None) != (name in ('set_link', 'screendump')) or (
                arguments is not None and not _arguments_valid(name, arguments)):
            raise ValueError('invalid-qmp-arguments')
        self.last_command_accepted = False
        # The last of the 128 calls belongs to quit, so that an exhausted budget
        # cannot push teardown onto signals alone.
        if self.calls >= 128 or (self.calls >= 127 and name != 'quit'):
            raise ValueError('qmp-command-limit')
        if self.persist is not None:
            # Nothing is sent when the record fails, so the channel stays usable.
            try:
                self.persist('qmp_calls', self.calls + 1)
            except (OSError, ValueError):
                raise ValueError('qmp-budget-record-failed') from None
        self.calls += 1

        async def execute():
            if event is None:
                value = await (self.client.execute(name) if arguments is None
                               else self.client.execute(name, dict(arguments)))
                self.last_command_accepted = True
                return value
            # Register before execute: events may arrive before the reply.
            with self.client.listener(event) as listener:
                await self.client.execute(name)
                self.last_command_accepted = True
                await listener.get()
                return {'event': event}

        return self._run(execute(), timeout)

    def close(self):
        if self.closed:
            return
        self.valid = False
        try:
            self.loop.run_until_complete(asyncio.wait_for(self.client.disconnect(), 1))
        except Exception:
            pass
        finally:
            self.relay.close()
            tasks = asyncio.all_tasks(self.loop)
            for task in tasks:
                task.cancel()
            if tasks:
                _, pending = self.loop.run_until_complete(asyncio.wait(tasks, timeout=1))
                if pending:
                    raise ValueError('qmp-tasks-close-unconfirmed')
            self.loop.close()
            self.closed = True
