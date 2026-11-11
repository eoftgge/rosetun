"""Fake public API contract tests, not qemu.qmp integration qualification."""

import asyncio
import json
from importlib.metadata import version, PackageNotFoundError
import socket
from contextlib import contextmanager
import tempfile
from pathlib import Path
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from tools.vm.matrix.qmp_adapter import Qmp, ByteRelay
from tools.vm.matrix.diagnostics import StderrSink

try:
    INSTALLED = version('qemu.qmp') == '0.0.6' and hasattr(socket, 'AF_UNIX')
except PackageNotFoundError:
    INSTALLED = False


class Relay:
    client = object()
    def __init__(self, stream):
        self.closed = False
    def close(self):
        self.closed = True


class Client:
    def __init__(self, **kwargs):
        assert kwargs == {'readbuflen': 65536}
        self.events = SimpleNamespace(accept=None)
        self.listeners = []
        self.emit = True
        self.connected = False

    def remove_listener(self, listener):
        raise AssertionError('the real API forbids removing the default listener')

    @contextmanager
    def listener(self, names=None, event_filter=None):
        class Listener:
            def __init__(self):
                self.queue = asyncio.Queue()
            async def get(self):
                return await self.queue.get()
        listener = Listener()
        self.listeners.append((names, listener))
        try:
            yield listener
        finally:
            self.listeners.remove((names, listener))

    async def connect(self, stream):
        self.connected = True

    async def disconnect(self):
        self.connected = False

    async def execute(self, name):
        if name == 'system_reset':
            listeners = [l for n, l in self.listeners if n == 'RESET']
            assert len(listeners) == 1, 'must subscribe before command'
            if self.emit:
                listeners[0].queue.put_nowait({'event': 'RESET'})
            await asyncio.sleep(0)
        return {}


class AdapterTests(unittest.TestCase):
    @unittest.skipUnless(hasattr(socket, 'AF_UNIX'), 'Unix sockets unavailable')
    def test_sequential_relays_close_duplicates_without_shutting_down_vm_endpoint(self):
        parent, guest = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        copies = []
        try:
            guest.settimeout(2)
            for _ in range(2):
                stream = parent.dup()
                copies.append(stream)
                relay = ByteRelay(stream)
                try:
                    relay.client.settimeout(2)
                    guest.sendall(b'reply')
                    self.assertEqual(b'reply', relay.client.recv(5))
                    relay.client.sendall(b'command')
                    self.assertEqual(b'command', guest.recv(7))
                finally:
                    relay.close()
                self.assertFalse(relay.thread.is_alive())
                self.assertEqual(-1, stream.fileno())
                self.assertGreaterEqual(parent.fileno(), 0)
            parent.close()
            self.assertEqual(b'', guest.recv(1))
        finally:
            parent.close()
            guest.close()
        self.assertTrue(all(stream.fileno() == -1 for stream in copies))

    def adapter(self):
        adapter = Qmp(object(), client_factory=Client, relay_factory=Relay)
        self.addCleanup(adapter.close)
        adapter.handshake(0.1)
        return adapter

    def test_reset_before_command_response_is_retained(self):
        adapter = self.adapter()
        self.assertEqual({'event': 'RESET'}, adapter.command('system_reset', 0.1, event='RESET'))
        self.assertTrue(adapter.last_command_accepted)

    def test_command_response_without_event_times_out(self):
        adapter = self.adapter()
        adapter.client.emit = False
        with self.assertRaises(ValueError):
            adapter.command('system_reset', 0.01, event='RESET')
        self.assertTrue(adapter.last_command_accepted)
        self.assertFalse(adapter.valid)

    def test_unsupported_commands_and_event_limits(self):
        adapter = self.adapter()
        for timeout in (0, -1, True, float('nan'), float('inf'), 61):
            with self.assertRaises(ValueError):
                adapter.command('query-status', timeout)
        with self.assertRaises(ValueError):
            adapter.command('human-monitor-command', 0.1)
        class Message:
            def __bytes__(self):
                return b'{}'
        for _ in range(128):
            self.assertFalse(adapter._event(Message()))
        with self.assertRaises(ValueError):
            adapter._event(Message())

    def test_quit_keeps_the_last_command_after_ordinary_commands_are_exhausted(self):
        adapter = self.adapter()
        for _ in range(127):
            adapter.command('query-status', 0.1)
        for name in ('query-status', 'stop', 'system_powerdown'):
            with self.assertRaisesRegex(ValueError, 'qmp-command-limit'):
                adapter.command(name, 0.1)
        self.assertTrue(adapter.valid)
        self.assertEqual({}, adapter.command('quit', 0.1))
        with self.assertRaisesRegex(ValueError, 'qmp-command-limit'):
            adapter.command('quit', 0.1)

    def test_byte_relay_overflow_closes_only_owned_sockets(self):
        class Stream:
            closed = False
            def setblocking(self, value):
                pass
            def recv(self, size):
                return b'xx'
            def close(self):
                self.closed = True
        relay = ByteRelay.__new__(ByteRelay)
        relay.stream, relay.peer = Stream(), Stream()
        relay.stop = threading.Event()
        relay.limit = 1
        relay.failed = False
        with patch('select.select', return_value=([relay.stream], [], [])):
            relay._run()
        self.assertTrue(relay.failed)
        self.assertTrue(relay.stream.closed and relay.peer.closed)

    def test_relay_close_failure_attempts_every_endpoint_and_blocks_confirmation(self):
        from unittest.mock import Mock
        relay = ByteRelay.__new__(ByteRelay)
        relay.stop = threading.Event()
        relay.client, relay.stream, relay.peer = Mock(), Mock(), Mock()
        relay.thread = Mock()
        relay.thread.is_alive.return_value = False
        relay.stream.close.side_effect = OSError('cannot confirm close')
        with self.assertRaisesRegex(ValueError, 'relay-close-unconfirmed'):
            relay.close()
        relay.client.close.assert_called_once()
        relay.peer.close.assert_called_once()
        relay.stream.close.side_effect = None
        relay.close()

    def test_relay_thread_start_failure_closes_new_pair(self):
        from unittest.mock import Mock
        client, peer, external = Mock(), Mock(), Mock()
        with patch('socket.AF_UNIX', 1, create=True), patch(
                'socket.socketpair', return_value=(client, peer)), patch(
                'threading.Thread.start', side_effect=RuntimeError('thread unavailable')):
            with self.assertRaises(RuntimeError):
                ByteRelay(external)
        client.close.assert_called_once()
        peer.close.assert_called_once()
        # Construction did not transfer the caller's stream to a worker.
        external.close.assert_not_called()

    def test_byte_relay_flushes_a_reply_before_peer_eof(self):
        class Stream:
            def __init__(self):
                self.blocks = [b'reply', b'']
                self.sent = bytearray()
            def setblocking(self, value):
                pass
            def recv(self, size):
                return self.blocks.pop(0)
            def send(self, block):
                self.sent.extend(block)
                return len(block)
            def close(self):
                pass
        relay = ByteRelay.__new__(ByteRelay)
        relay.stream, relay.peer = Stream(), Stream()
        relay.stop = threading.Event()
        relay.limit, relay.failed = 100, False
        with patch('select.select', side_effect=[([relay.stream], [], []),
                                                ([relay.stream], [relay.peer], [])]):
            relay._run()
        self.assertEqual(b'reply', relay.peer.sent)
        self.assertFalse(relay.failed)


class StderrTests(unittest.TestCase):
    def test_cross_chunk_token_redaction_and_bounded_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'stderr.log'
            token = 'a' * 64
            sink = StderrSink(path, token, limit=100)
            sink.feed(b'prefix' + token[:20].encode())
            sink.feed(token[20:].encode() + b'x' * 1000)
            sink.feed(b'', final=True)
            sink.close()
            self.assertTrue(sink.overflow)
            self.assertLessEqual(path.stat().st_size, 100)
            self.assertNotIn(token.encode(), path.read_bytes())
            self.assertIn(b'[owner-redacted]', path.read_bytes())

    def test_stuck_reader_has_bounded_close_and_can_be_retried(self):
        with tempfile.TemporaryDirectory() as directory:
            gate = threading.Event()
            class Pipe:
                def read(self, size):
                    gate.wait(5)
                    return b''
                def close(self):
                    pass
            sink = StderrSink(Path(directory) / 'stderr.log', 'b' * 64)
            sink.start(Pipe())
            try:
                with self.assertRaises(ValueError):
                    sink.close()
            finally:
                gate.set()
                sink.thread.join(timeout=1)
                sink.close()


@unittest.skipUnless(INSTALLED, 'optional qemu.qmp 0.0.6 and Unix socket support')
class InstalledAdapterTests(unittest.TestCase):
    def test_public_client_accepts_socket_and_reset_before_reply(self):
        parent, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        errors = []
        observations = []

        def server():
            try:
                peer.settimeout(3)
                with peer.makefile('rwb', buffering=0) as stream:
                    def send(value):
                        stream.write(json.dumps(value).encode() + b'\r\n')
                    def request():
                        # QMP clients need not append newlines to commands.
                        buffer = bytearray()
                        while len(buffer) < 4096:
                            block = stream.read(1)
                            if not block:
                                raise EOFError
                            buffer.extend(block)
                            try:
                                return json.loads(buffer)
                            except ValueError:
                                pass
                        raise AssertionError('oversize test request')
                    send({'QMP': {'version': {'qemu': {'major': 10, 'minor': 0, 'micro': 0},
                                             'package': 'synthetic'}, 'capabilities': []}})
                    negotiate = request()
                    observations.append(negotiate)
                    assert negotiate['execute'] == 'qmp_capabilities'
                    reply = {'return': {}}
                    if 'id' in negotiate:
                        reply['id'] = negotiate['id']
                    send(reply)
                    reset = request()
                    assert reset['execute'] == 'system_reset'
                    send({'event': 'RESET', 'data': {},
                          'timestamp': {'seconds': 0, 'microseconds': 0}})
                    send({'return': {}, 'id': reset['id']})
                    stream.read(1)
            except BaseException as error:
                errors.append(type(error).__name__)
            finally:
                peer.close()

        thread = threading.Thread(target=server, daemon=True)
        thread.start()
        adapter = Qmp(parent)
        try:
            try:
                adapter.handshake(2)
            except ValueError:
                raise AssertionError((observations, errors)) from None
            self.assertEqual({'event': 'RESET'}, adapter.command('system_reset', 2, event='RESET'))
            self.assertTrue(adapter.last_command_accepted)
            self.assertEqual(1, adapter.events)
            self.assertTrue(adapter.client.events.empty())
            self.assertEqual((), tuple(adapter.client.events.history))
        finally:
            adapter.close()
            thread.join(timeout=3)
        self.assertFalse(thread.is_alive())
        self.assertEqual([], errors)
