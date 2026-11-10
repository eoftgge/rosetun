"""Offline QGA protocol tests; synthetic peers are not real qemu-ga."""

import base64
import json
import socket
import threading
import unittest
from importlib.metadata import version, PackageNotFoundError
from types import SimpleNamespace
from unittest.mock import patch

from tools.vm.matrix.qga import Qga, QgaError, REQUIRED

BOOT = '12345678-1234-4234-8234-123456789abc'


def info():
    return {'version': '9.2.0', 'supported_commands': [
        {'name': name, 'enabled': True, 'success-response': True} for name in REQUIRED]}


def read(data=(BOOT + '\n').encode(), **changes):
    return dict({'count': len(data), 'eof': True,
                 'buf-b64': base64.b64encode(data).decode()}, **changes)


class Stream:
    def __init__(self, data):
        self.data = bytearray(data)
        self.closed = False
        self.sent = []
    def dup(self):
        return Stream(bytes(self.data))
    def settimeout(self, timeout):
        assert 0 < timeout <= 60
    def sendall(self, data):
        self.sent.append(data)
    def recv(self, size):
        if not self.data:
            raise TimeoutError
        result = bytes(self.data[:size])
        del self.data[:size]
        return result
    def close(self):
        self.closed = True


class Relay:
    def __init__(self, stream):
        self.stream = stream
        self.client = object()
    def close(self):
        self.stream.close()


class Client:
    def __init__(self, **kwargs):
        self.events = SimpleNamespace()
        self.commands = []
        self.responses = {'guest-info': info(), 'guest-ping': {},
                          'guest-file-open': 7, 'guest-file-read': read(), 'guest-file-close': {}}
    async def connect(self, stream):
        assert self.await_greeting is False
        assert self.negotiate is False
    async def execute(self, name, arguments):
        self.commands.append((name, arguments))
        value = self.responses[name]
        if isinstance(value, Exception):
            raise value
        return value() if callable(value) else value
    async def disconnect(self):
        pass


class QgaTests(unittest.TestCase):
    def test_job_commands_are_required_only_after_explicit_opt_in(self):
        adapter = self.adapter()
        self.assertEqual(list(REQUIRED), adapter.probe(1)['required_commands'])
        adapter.jobs_enabled = True
        with self.assertRaisesRegex(QgaError, 'required-rpc-unsupported'):
            adapter.probe(1)

    def adapter(self, prefix=b'', suffix=b''):
        stream = Stream(prefix + b'\xff{"return":123}\n' + suffix)
        adapter = Qga(stream, client_factory=Client, relay_factory=Relay)
        self.addCleanup(adapter.close)
        with patch('secrets.randbits', return_value=123):
            adapter.connect(1)
        return adapter

    def test_sync_discards_garbage_stale_replies_and_partial_json(self):
        adapter = self.adapter(b'garbage{"return":123}\n\xff{"return":321}\n{"ret')
        self.assertTrue(adapter.valid)
        request = adapter.stream.sent[0]
        self.assertEqual(255, request[0])
        self.assertEqual('guest-sync-delimited', json.loads(request[1:])['execute'])
        self.assertEqual([], adapter.client.commands)
        self.assertEqual(BOOT, (adapter.probe(1), adapter.read_boot_id(1))[1])
        self.assertEqual(('guest-file-open', {'path': '/proc/sys/kernel/random/boot_id', 'mode': 'r'}),
                         adapter.client.commands[2])
        self.assertEqual('guest-file-close', adapter.client.commands[-1][0])

    def test_wrong_id_missing_sentinel_truncated_reply_and_byte_limit(self):
        for data in (b'\xff{"return":124}\n', b'{"return":123}\n',
                     b'\xff{"return":', b'x' * 65537, b'\xff{"return":true}\n'):
            with self.subTest(data=data[:50]):
                adapter = Qga(Stream(data), client_factory=Client, relay_factory=Relay)
                with patch('secrets.randbits', return_value=123), self.assertRaises(QgaError):
                    adapter.connect(.01)
                with self.assertRaisesRegex(QgaError, 'reconnect-unsupported'):
                    adapter.connect(1)
                adapter.close()
                self.assertTrue(adapter.stream.closed)

    def test_sync_deadline_is_total(self):
        adapter = Qga(Stream(b'x'), client_factory=Client)
        with patch('time.monotonic', side_effect=[0, 2]), self.assertRaises(QgaError):
            adapter.connect(1)
        adapter.close()

    def test_disabled_missing_and_no_success_response_are_unsupported(self):
        for name in REQUIRED:
            for field in ('enabled', 'success-response', 'missing'):
                with self.subTest(name=name, field=field):
                    adapter = self.adapter()
                    value = info()
                    entry = next(c for c in value['supported_commands'] if c['name'] == name)
                    if field == 'missing':
                        value['supported_commands'].remove(entry)
                    else:
                        entry[field] = False
                    adapter.client.responses['guest-info'] = value
                    with self.assertRaisesRegex(QgaError, 'unsupported'):
                        adapter.probe(1)

    def test_invalid_info_types(self):
        for value in (None, [], {'version': True, 'supported_commands': []},
                      {'version': 'x', 'supported_commands': {}},
                      {'version': 'x', 'supported_commands': [None]}):
            adapter = self.adapter()
            adapter.client.responses['guest-info'] = value
            with self.assertRaises(QgaError):
                adapter.probe(1)

    def test_invalid_handles_are_not_closed_or_retried(self):
        for handle in (True, '7', -1, None, {}, 2**63):
            adapter = self.adapter()
            adapter.probe(1)
            adapter.client.responses['guest-file-open'] = handle
            with self.assertRaises(QgaError):
                adapter.read_boot_id(1)
            self.assertFalse(adapter.valid)
            self.assertEqual('guest-file-open', adapter.client.commands[-1][0])

    def test_bad_reads_close_handle_in_finally(self):
        values = [None, [], read(count=True), read(count=1), read(eof=1),
                  read(**{'buf-b64': '!!!'}), read(**{'buf-b64': 7}),
                  read(**{'buf-b64': '☃'}), read(b'invalid'), read(b'x' * 65),
                  read((BOOT.upper() + '\n').encode()), read((BOOT + '\n\n').encode()),
                  read(b'', eof=False), read(b'00000000-0000-0000-0000-000000000000')]
        for value in values:
            with self.subTest(value=value):
                adapter = self.adapter()
                adapter.probe(1)
                adapter.client.responses['guest-file-read'] = value
                with self.assertRaises(QgaError):
                    adapter.read_boot_id(1)
                self.assertEqual('guest-file-close', adapter.client.commands[-1][0])

    def test_fragmented_file_reads_require_final_eof(self):
        adapter = self.adapter()
        adapter.probe(1)
        replies = iter([read(BOOT[:12].encode(), eof=False),
                        read((BOOT[12:] + '\n').encode(), eof=False), read(b'')])
        adapter.client.responses['guest-file-read'] = lambda: next(replies)
        self.assertEqual(BOOT, adapter.read_boot_id(1))
        self.assertEqual(3, sum(name == 'guest-file-read' for name, _ in adapter.client.commands))

    def test_failed_close_is_explicit_and_session_is_unusable(self):
        adapter = self.adapter()
        adapter.probe(1)
        adapter.client.responses['guest-file-close'] = TimeoutError()
        with self.assertRaises(QgaError):
            adapter.read_boot_id(1)
        self.assertFalse(adapter.valid)
        with patch.object(adapter.relay, 'close', side_effect=ValueError('unconfirmed')):
            with self.assertRaises(ValueError):
                adapter.close()
        self.assertFalse(adapter.closed)
        adapter.close()
        self.assertTrue(adapter.closed)

    def test_reset_before_initial_connection_also_blocks_observation(self):
        adapter = Qga(Stream(b''), client_factory=Client)
        adapter.invalidate()
        with self.assertRaisesRegex(QgaError, 'reconnect-unsupported'):
            adapter.connect(1)
        adapter.close()

    def test_rpc_budget_reserves_handle_close(self):
        adapter = self.adapter()
        adapter.probe(1)
        adapter.calls = 126
        with self.assertRaisesRegex(QgaError, 'qga-command-limit'):
            adapter.read_boot_id(1)
        self.assertEqual(['guest-file-open', 'guest-file-close'],
                         [name for name, _ in adapter.client.commands[-2:]])
        self.assertEqual(128, adapter.calls)

    def test_confirmed_rpc_rejection_still_closes_known_handle(self):
        class ExecuteError(Exception):
            pass
        adapter = self.adapter()
        adapter.rpc_error = ExecuteError
        adapter.probe(1)
        adapter.client.responses['guest-file-read'] = ExecuteError('private guest detail')
        with self.assertRaisesRegex(QgaError, '^qga-rpc-rejected$'):
            adapter.read_boot_id(1)
        self.assertTrue(adapter.valid)
        self.assertEqual('guest-file-close', adapter.client.commands[-1][0])

    def test_sync_accepts_utf8_only(self):
        stream = Stream(b'\xff' + '{"return":123}'.encode('utf-16-le') + b'\n')
        adapter = Qga(stream, client_factory=Client)
        with patch('secrets.randbits', return_value=123), self.assertRaises(QgaError):
            adapter.connect(1)
        adapter.close()

    def test_noncanonical_base64_is_rejected_and_handle_closed(self):
        adapter = self.adapter()
        adapter.probe(1)
        adapter.client.responses['guest-file-read'] = read(b'f', **{'buf-b64': 'Zh=='})
        with self.assertRaises(QgaError):
            adapter.read_boot_id(1)
        self.assertEqual('guest-file-close', adapter.client.commands[-1][0])

    def test_timeout_poison_prevents_late_answers_and_uncertain_retry(self):
        adapter = self.adapter()
        adapter.probe(1)
        adapter.client.responses['guest-file-read'] = TimeoutError()
        with self.assertRaises(QgaError):
            adapter.read_boot_id(.01)
        adapter.client.responses['guest-file-read'] = read()
        count = len(adapter.client.commands)
        with self.assertRaises(QgaError):
            adapter.read_boot_id(1)
        self.assertEqual(count, len(adapter.client.commands))
        self.assertFalse(adapter.valid)

    def test_reset_invalidation_cannot_confirm_same_boot(self):
        adapter = self.adapter()
        adapter.probe(1)
        self.assertEqual(BOOT, adapter.read_boot_id(1))
        adapter.invalidate()
        with self.assertRaises(QgaError):
            adapter.probe(1)
        with self.assertRaises(QgaError):
            adapter.read_boot_id(1)


try:
    INSTALLED = version('qemu.qmp') == '0.0.6' and hasattr(socket, 'AF_UNIX')
except PackageNotFoundError:
    INSTALLED = False


@unittest.skipUnless(INSTALLED, 'optional qemu.qmp 0.0.6 is not installed')
class InstalledQgaTests(unittest.TestCase):
    def test_real_public_api_without_greeting_or_negotiation(self):
        self.exercise_peer(reject_read=False)

    def test_real_public_api_rejected_read_still_closes_guest_handle(self):
        self.exercise_peer(reject_read=True)

    def exercise_peer(self, *, reject_read):
        parent, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        errors = []
        seen = []
        def server():
            try:
                peer.settimeout(3)
                def request():
                    data = bytearray()
                    while len(data) < 4096:
                        byte = peer.recv(1)
                        if not byte:
                            raise EOFError
                        if byte in (b'\xff', b'\n') and not data:
                            continue
                        data.extend(byte)
                        try:
                            return json.loads(data)
                        except ValueError:
                            pass
                    raise AssertionError('request limit')
                sync = request()
                seen.append(sync['execute'])
                peer.sendall(b'junk{"return":0}\n\xff' + json.dumps(
                    {'return': sync['arguments']['id']}).encode() + b'\n')
                responses = {'guest-info': info(), 'guest-ping': {}, 'guest-file-open': 5,
                             'guest-file-read': read(), 'guest-file-close': {}}
                for _ in range(5):
                    rpc = request()
                    seen.append(rpc['execute'])
                    reply = {'return': responses[rpc['execute']], 'id': rpc['id']}
                    if reject_read and rpc['execute'] == 'guest-file-read':
                        reply = {'error': {'class': 'GenericError', 'desc': 'synthetic rejection'},
                                 'id': rpc['id']}
                    peer.sendall(json.dumps(reply).encode() + b'\n')
                peer.recv(1)
            except BaseException as error:
                errors.append(type(error).__name__)
            finally:
                peer.close()
        thread = threading.Thread(target=server, daemon=True)
        thread.start()
        adapter = Qga(parent)
        try:
            adapter.connect(2)
            adapter.probe(2)
            if reject_read:
                with self.assertRaisesRegex(QgaError, '^qga-rpc-rejected$'):
                    adapter.read_boot_id(2)
                self.assertTrue(adapter.valid)
            else:
                self.assertEqual(BOOT, adapter.read_boot_id(2))
        finally:
            adapter.close()
            thread.join(4)
        self.assertFalse(thread.is_alive())
        self.assertEqual([], errors)
        self.assertEqual(['guest-sync-delimited', 'guest-info', 'guest-ping',
                          'guest-file-open', 'guest-file-read', 'guest-file-close'], seen)
