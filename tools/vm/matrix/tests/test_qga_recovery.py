"""Explicit recovery under a live owner; all children and agents are synthetic."""
import json
import socket
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from tools.vm.matrix import lifecycle
from tools.vm.matrix.qga import Qga, QgaError
from tools.vm.matrix.tests import test_lifecycle
from tools.vm.matrix.tests.test_lifecycle import Stream, REAL_SOCKETPAIR
from tools.vm.matrix.tests.test_qga import Client, Relay, Stream as AgentStream, BOOT, info, read, INSTALLED

OTHER_BOOT = '22345678-1234-4234-8234-123456789abc'


class Endpoint(AgentStream):
    def __init__(self):
        super().__init__(b'')
        self.copies = []
    def dup(self):
        stream = AgentStream(b'')
        def send(data):
            stream.sent.append(data)
            sync = json.loads(data[1:])['arguments']['id']
            stream.data.extend(b'late reply\n{"ret\xff{"return":0}\n\xff' +
                               json.dumps({'return': sync}).encode() + b'\n')
        stream.sendall = send
        self.copies.append(stream)
        return stream


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_lifecycle.LifecycleTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.enable_qga()
        self.endpoint = Endpoint()
        factory = patch.object(lifecycle, 'Qga', side_effect=lambda stream, **kw:
                               Qga(stream, client_factory=Client, relay_factory=Relay, **kw))
        factory.start()
        self.addCleanup(factory.stop)
        with patch.object(lifecycle.socket, 'socketpair', side_effect=[
                (Stream(), Stream()), (self.endpoint, Stream())]):
            self.vm = self.fixture.start()
        self.vm.timeout = 1
        real_sockets = patch.object(lifecycle.socket, 'socketpair', REAL_SOCKETPAIR)
        real_sockets.start()
        self.addCleanup(real_sockets.stop)
        self.addCleanup(self.vm.hard_off)

    def test_timeout_then_recovery_same_boot_and_bounded_sessions(self):
        vm = self.vm
        first = vm.observe_guest()
        old = vm.qga
        old.client.responses['guest-file-open'] = TimeoutError()
        with self.assertRaises(lifecycle.LifecycleError):
            vm.observe_guest()
        self.assertIsNone(vm.guest_observation)
        recovered = vm.recover_guest()
        self.assertTrue(old.closed)
        self.assertFalse(self.endpoint.closed)
        self.assertNotEqual(first['qga_session_id'], recovered['qga_session_id'])
        self.assertNotEqual(old.sync_id, vm.qga.sync_id)
        self.assertEqual('same', recovered['boot_comparison'])
        self.assertFalse(recovered['new_boot_confirmed'])
        self.assertEqual(2, sum(name == 'guest-file-open' for name, _ in
                               old.client.commands))
        for _ in range(3):
            vm.recover_guest()
        with self.assertRaisesRegex(lifecycle.LifecycleError, 'recovery-limit'):
            vm.recover_guest()
        self.assertEqual(5, len(self.endpoint.copies))
        vm.hard_off()
        self.assertTrue(self.endpoint.closed)
        self.assertTrue(all(s.closed for s in self.endpoint.copies))
        rows = (vm.run.directory / 'qga-observations.jsonl').read_text()
        self.assertNotIn(vm.run._identity[2], rows)

    def test_reset_before_first_observation_cannot_claim_changed_boot(self):
        self.vm.reset()
        with self.assertRaises(lifecycle.LifecycleError):
            self.vm.observe_guest()
        row = self.vm.recover_guest()
        self.assertEqual('unknown', row['boot_comparison'])
        self.assertFalse(row['new_boot_confirmed'])
        self.assertIsNone(row['reset_boot_id'])

    def test_reset_same_then_changed_boot_compares_to_pre_reset_baseline(self):
        self.vm.observe_guest()
        self.vm.reset()
        row = self.vm.recover_guest()
        self.assertEqual('same', row['boot_comparison'])
        self.assertFalse(row['new_boot_confirmed'])
        self.vm.qga.client.responses['guest-file-read'] = read((OTHER_BOOT + '\n').encode())
        row = self.vm.observe_guest()
        self.assertEqual(BOOT, row['reset_boot_id'])
        self.assertEqual('changed', row['boot_comparison'])
        self.assertTrue(row['new_boot_confirmed'])

    def test_unconfirmed_old_relay_blocks_new_reader_and_completion(self):
        self.vm.observe_guest()
        old = self.vm.qga
        with patch.object(old.relay, 'close', side_effect=ValueError('uncertain')):
            with self.assertRaisesRegex(lifecycle.LifecycleError, 'replacement-failed'):
                self.vm.recover_guest()
            self.assertIs(old, self.vm.qga)
            self.assertFalse(old.closed)
            self.assertEqual(1, len(self.endpoint.copies))
            with self.assertRaises(lifecycle.LifecycleError):
                self.vm.hard_off()
            self.assertFalse(self.vm.completed)
        self.vm.hard_off()

    def test_parallel_reader_is_rejected(self):
        self.vm._guest_lock.acquire()
        try:
            for method in (self.vm.observe_guest, self.vm.recover_guest, self.vm.reset):
                with self.assertRaisesRegex(lifecycle.LifecycleError, 'in-progress'):
                    method()
        finally:
            self.vm._guest_lock.release()
        self.assertEqual(1, len(self.endpoint.copies))

    def test_unknown_disconnect_blocks_replacement(self):
        self.vm.observe_guest()
        old = self.vm.qga
        async def fail():
            raise ValueError('unknown disconnect')
        with patch.object(old.client, 'disconnect', side_effect=fail):
            with self.assertRaisesRegex(lifecycle.LifecycleError, 'replacement-failed'):
                self.vm.recover_guest()
            self.assertFalse(old.closed)
            self.assertIs(old, self.vm.qga)
            self.assertEqual(1, len(self.endpoint.copies))

    def test_failed_replacements_consume_recovery_budget(self):
        self.vm.observe_guest()
        with patch.object(self.vm.qga.relay, 'close', side_effect=ValueError('uncertain')):
            for _ in range(4):
                with self.assertRaisesRegex(lifecycle.LifecycleError, 'replacement-failed'):
                    self.vm.recover_guest()
            with self.assertRaisesRegex(lifecycle.LifecycleError, 'recovery-limit'):
                self.vm.recover_guest()
        self.assertEqual(1, len(self.endpoint.copies))

    def test_recovery_cannot_reset_vm_observation_budget(self):
        self.vm.qga_observations = 32
        with self.assertRaisesRegex(lifecycle.LifecycleError, 'observation-limit'):
            self.vm.recover_guest()
        self.assertEqual(0, self.vm.qga_recoveries)
        self.assertEqual(1, len(self.endpoint.copies))

    def test_recovery_uses_one_deadline_for_probe_and_read(self):
        import time
        original = Qga.probe
        def probe(agent, timeout):
            result = original(agent, timeout)
            agent.deadline = time.monotonic() - 1
            return result
        with patch.object(Qga, 'probe', probe):
            with self.assertRaises(lifecycle.LifecycleError):
                self.vm.recover_guest()
        self.assertFalse(self.vm.qga.valid)
        self.assertNotIn('guest-file-open', [name for name, _ in self.vm.qga.client.commands])

    def test_lease_loss_and_foreign_vm_block_recovery_before_dup(self):
        vm = self.vm
        with patch.object(vm.run._lease, '_check_live', side_effect=ValueError('lost')):
            with self.assertRaises(ValueError):
                vm.recover_guest()
        vm.run._lease._active.remove(vm)
        try:
            with self.assertRaisesRegex(lifecycle.LifecycleError, 'not-active'):
                vm.recover_guest()
        finally:
            vm.run._lease._active.add(vm)
        original = vm.run
        vm.run = SimpleNamespace()
        try:
            with self.assertRaisesRegex(lifecycle.LifecycleError, 'owner-mismatch'):
                vm.recover_guest()
        finally:
            vm.run = original
        self.assertEqual(1, len(self.endpoint.copies))

    def test_failed_sync_keeps_qmp_and_hard_off_available(self):
        with patch.object(Qga, 'connect', side_effect=QgaError('synthetic-sync-error')):
            with self.assertRaises(lifecycle.LifecycleError):
                self.vm.recover_guest()
        self.assertFalse(self.vm.qga.valid)
        self.assertIsNone(self.vm.guest_observation)
        self.assertEqual('running', self.vm.resume()['status'])
        self.vm.hard_off()
        self.assertTrue(self.vm.completed)

    def test_retained_endpoint_close_failure_blocks_completion(self):
        from tools.vm.matrix.resources import completion_verified
        with patch.object(self.endpoint, 'close', side_effect=OSError('uncertain')):
            with self.assertRaises(lifecycle.LifecycleError):
                self.vm.hard_off()
            self.assertFalse(self.vm.completed)
            self.assertFalse(completion_verified(self.vm.run.directory, self.vm.run._read()))
        self.vm.hard_off()

    def test_without_qga_recovery_is_explicitly_unavailable(self):
        endpoint = self.vm.qga_endpoint
        self.vm.qga_endpoint = None
        try:
            with self.assertRaisesRegex(lifecycle.LifecycleError, 'not-configured'):
                self.vm.recover_guest()
        finally:
            self.vm.qga_endpoint = endpoint


@unittest.skipUnless(INSTALLED, 'optional qemu.qmp 0.0.6 is not installed')
class InstalledSequentialSessionTests(unittest.TestCase):
    def test_timeout_late_open_reply_and_new_session_on_same_transport(self):
        parent, peer = REAL_SOCKETPAIR(socket.AF_UNIX, socket.SOCK_STREAM)
        vm = lifecycle.Vm(None, 1)
        vm.qga_endpoint = parent
        errors, syncs, sessions, copies = [], [], [], []
        def server():
            try:
                peer.settimeout(5)
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
                late = None
                for attempt in range(2):
                    sync = request()
                    self.assertEqual('guest-sync-delimited', sync['execute'])
                    syncs.append(sync['arguments']['id'])
                    if late is not None:
                        peer.sendall(json.dumps({'return': 99, 'id': late}).encode() +
                                     b'\npartial{\xff{"return":' + str(syncs[0]).encode() + b'}\n')
                    peer.sendall(b'\xff' + json.dumps({'return': syncs[-1]}).encode() + b'\n')
                    responses = {'guest-info': info(), 'guest-ping': {}, 'guest-file-open': 5,
                                 'guest-file-read': read(), 'guest-file-close': {}}
                    for _ in range(3 if attempt == 0 else 5):
                        rpc = request()
                        if attempt == 0 and rpc['execute'] == 'guest-file-open':
                            late = rpc['id']
                            break
                        peer.sendall(json.dumps({'return': responses[rpc['execute']],
                                                 'id': rpc['id']}).encode() + b'\n')
                self.assertEqual(b'', peer.recv(1))
            except BaseException as error:
                errors.append(repr(error))
            finally:
                peer.close()
        thread = threading.Thread(target=server, daemon=True)
        thread.start()
        try:
            for attempt in range(2):
                vm.qga_recoveries = attempt
                vm._new_qga()
                copies.append(vm.qga.stream)
                sessions.append(vm.qga.session_id)
                vm.qga.connect(2)
                vm.qga.probe(2)
                if attempt == 0:
                    with self.assertRaises(QgaError):
                        vm.qga.read_boot_id(.05)
                else:
                    self.assertEqual(BOOT, vm.qga.read_boot_id(2))
                vm.qga.close()
                self.assertTrue(vm.qga.closed)
                self.assertEqual(-1, copies[-1].fileno())
                self.assertGreaterEqual(parent.fileno(), 0)
        finally:
            if vm.qga is not None:
                vm.qga.close()
            parent.close()
            thread.join(6)
        self.assertFalse(thread.is_alive())
        self.assertEqual([], errors)
        self.assertEqual(2, len(set(syncs)))
        self.assertEqual(2, len(set(sessions)))
        self.assertTrue(all(s.fileno() == -1 for s in copies))
