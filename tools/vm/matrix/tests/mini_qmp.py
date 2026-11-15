"""The part of qemu.qmp's QMPClient the adapters use, for offline tests over real sockets.

Not a qualification of qemu.qmp: the installed-library tests stay as they are.
"""

import asyncio
import json
from types import SimpleNamespace


class ExecuteError(Exception):
    pass


class MiniClient:
    def __init__(self, readbuflen=65536):
        self.events = SimpleNamespace(accept=lambda event: False)
        self.await_greeting = True
        self.negotiate = True
        self.runstate = SimpleNamespace(name='IDLE')
        self.limit = readbuflen
        self.reader = self.writer = None
        self.ident = 0

    async def connect(self, sock):
        self.reader, self.writer = await asyncio.open_unix_connection(sock=sock, limit=self.limit)
        self.runstate.name = 'RUNNING'
        if self.await_greeting:
            greeting = await self._read()
            if 'QMP' not in greeting:
                raise ValueError('no greeting')
        if self.negotiate:
            await self.execute('qmp_capabilities')

    async def _read(self):
        line = await self.reader.readline()
        if not line:
            raise EOFError('peer closed')
        return json.loads(line)

    async def execute(self, name, arguments=None):
        self.ident += 1
        request = {'execute': name, 'id': self.ident}
        if arguments is not None:
            request['arguments'] = arguments
        self.writer.write(json.dumps(request).encode() + b'\n')
        await self.writer.drain()
        while True:
            message = await self._read()
            if 'event' in message:
                self.events.accept(json.dumps(message).encode())
                continue
            if message.get('id') != self.ident:
                continue
            if 'error' in message:
                raise ExecuteError(message['error'].get('class'))
            return message['return']

    async def disconnect(self):
        if self.writer is not None:
            self.writer.close()
            try:
                await self.writer.wait_closed()
            except (OSError, ConnectionError):
                pass
        self.runstate.name = 'IDLE'
