"""Synchronous serialized facade over public qemu.qmp 0.0.6 APIs.

The byte relay enforces a lifetime budget without inspecting or framing JSON.
No library internals or legacy APIs are used. Imports remain execution-only.
"""

import asyncio
import math
from importlib.metadata import version
import select
import socket
import threading


class ByteRelay:
    def __init__(self, stream, limit=1024 * 1024):
        self.client, self.peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.stream = stream
        self.limit = limit
        self.stop = threading.Event()
        self.failed = False
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        sockets = [self.stream, self.peer]
        buffers = [bytearray(), bytearray()]
        counts = [0, 0]
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
                    buffers[1-index].extend(block)
                for stream in writable:
                    index = sockets.index(stream)
                    sent = stream.send(buffers[index])
                    del buffers[index][:sent]
        except (OSError, ValueError):
            self.failed = True
        finally:
            for stream in sockets:
                stream.close()

    def close(self):
        self.stop.set()
        self.client.close()
        self.thread.join(timeout=1)
        if self.thread.is_alive():
            raise ValueError('qmp-relay-close-unconfirmed')


class Qmp:
    def __init__(self, stream, *, client_factory=None, relay_factory=ByteRelay):
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
        self.events = 0
        self.calls = 0
        self.valid = True
        self.closed = False
        self.relay = relay_factory(stream)

    def _event(self, event):
        self.events += 1
        if self.events > 128 or len(bytes(event)) > 65536:
            raise ValueError('qmp-event-limit')
        return False

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

    def command(self, name, timeout, *, event=None):
        if name not in ('query-status', 'query-uuid', 'query-kvm', 'stop', 'cont',
                        'system_reset', 'system_powerdown', 'quit'):
            raise ValueError('unsupported-qmp-command')
        self.last_command_accepted = False
        self.calls += 1
        if self.calls > 128:
            raise ValueError('qmp-command-limit')

        async def execute():
            if event is None:
                value = await self.client.execute(name)
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
