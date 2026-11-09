"""Offline lifecycle tests: fake children and scripted QMP, no QEMU processes."""

import json
import subprocess
import unittest
from unittest.mock import patch

from tools.vm.matrix import lifecycle
from tools.vm.matrix.tests import test_qemu

REAL_HOST = lifecycle._host


class Stream:
    def __init__(self, chunks=()):
        self.chunks = list(chunks)
        self.sent = []
        self.closed = False

    def settimeout(self, timeout):
        assert 0 < timeout <= 60

    def sendall(self, data):
        self.sent.append(json.loads(data))

    def recv(self, size):
        if not self.chunks:
            raise TimeoutError('untrusted peer details')
        block = self.chunks.pop(0)
        if len(block) > size:
            self.chunks.insert(0, block[size:])
        return block[:size]

    def close(self):
        self.closed = True

    def fileno(self):
        return 42


def line(value):
    return json.dumps(value).encode() + b'\r\n'


class QmpTests(unittest.TestCase):
    def test_fragmented_greeting_and_events_before_response(self):
        greeting = line({'QMP': {'version': {}, 'capabilities': []}})
        stream = Stream([greeting[:5], greeting[5:],
                         line({'return': {}, 'id': 1}),
                         line({'event': 'STOP'}) + line({'return': {}, 'id': 2})])
        qmp = lifecycle.Qmp(stream)
        qmp.handshake(1)
        self.assertEqual({}, qmp.command('stop', 1))
        self.assertEqual(['qmp_capabilities', 'stop'], [m['execute'] for m in stream.sent])

    def test_invalid_replies_invalidate_connection_and_hide_peer_data(self):
        for response in (b'', b'[]\n', b'{"id":1,"id":1}\n', b'NaN\n', b'\xff\n',
                         line({'return': {}, 'id': 2}),
                         line({'error': {'desc': 'SECRET'}, 'id': 1}),
                         b'x' * 65537, line({'event': 'STOP'}) * 129):
            with self.subTest(response=response[:40]):
                stream = Stream([response])
                qmp = lifecycle.Qmp(stream)
                with self.assertRaisesRegex(lifecycle.LifecycleError, '^qmp-command-failed$'):
                    qmp.command('stop', 0.1)
                self.assertTrue(stream.closed)
                self.assertFalse(qmp.valid)

    def test_timeout_and_arbitrary_commands_are_rejected(self):
        qmp = lifecycle.Qmp(Stream())
        for timeout in (0, -1, True, float('nan'), float('inf'), 61):
            with self.assertRaises(ValueError):
                lifecycle.start(None, timeout=timeout)
        with self.assertRaises(ValueError):
            qmp.command('human-monitor-command', 1)
        with self.assertRaises(ValueError):
            qmp.command('query-status', 0.01)


class Child:
    pid = 12345

    def __init__(self):
        self.returncode = None
        self.signals = []
        self.stubborn = False

    def poll(self):
        return self.returncode

    def wait(self, timeout):
        assert 0 < timeout <= 60
        if self.returncode is None:
            raise subprocess.TimeoutExpired('private', timeout)
        return self.returncode

    def terminate(self):
        self.signals.append('terminate')

    def kill(self):
        self.signals.append('kill')
        if not self.stubborn:
            self.returncode = -9


class Control:
    def __init__(self, plan):
        self.plan = plan
        self.state = 'prelaunch'
        self.commands = []
        self.bad_uuid = False

    def handshake(self, timeout):
        pass

    def command(self, name, timeout):
        self.commands.append(name)
        if name == 'query-uuid':
            return {'UUID': 'wrong' if self.bad_uuid else self.plan['uuid']}
        if name == 'query-kvm':
            return {'enabled': True, 'present': True}
        if name == 'query-status':
            return {'status': self.state, 'running': self.state == 'running'}
        if name == 'stop':
            self.state = 'paused'
        if name == 'cont':
            self.state = 'running'
        return {}

    def close(self):
        pass


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        # Reuse preparation fixtures, not its test cases or real command runner.
        self.fixture = test_qemu.PreparationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.plan = self.fixture.prepare()
        self.run = self.fixture.run
        self.child = Child()
        self.control = Control(self.plan)
        self.patches = [patch.object(lifecycle, '_host'),
                        patch.object(lifecycle.socket, 'AF_UNIX', 1, create=True),
                        patch.object(lifecycle.socket, 'socketpair', return_value=(Stream(), Stream())),
                        patch.object(lifecycle, 'Qmp', return_value=self.control),
                        patch.object(lifecycle, '_identity', return_value={
                            'id': 'qemu', 'kind': 'process', 'pid': 12345,
                            'platform': 'posix', 'boot_id': 'test-boot',
                            'start_id': '123', 'executable': self.fixture.config.executable}),
                        patch.object(lifecycle.subprocess, 'Popen', return_value=self.child)]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)
        # Last preparation call was overlay-info; allow exactly that observation.
        self.fixture.calls = self.fixture.calls[:2]

    def start(self):
        def info(argv, *, timeout, output_limit):
            self.assertEqual(0.01, timeout)
            return self.fixture.fake(argv, timeout=30, output_limit=output_limit)
        return lifecycle.start(self.run, timeout=0.01, executor=info)

    def test_controls_confirm_states_and_lease_is_held_until_child_exit(self):
        vm = self.start()
        with self.assertRaises(ValueError):
            self.fixture.lease.release()
        with self.assertRaises(ValueError):
            self.start()
        self.assertEqual('running', vm.resume()['status'])
        self.assertEqual('paused', vm.pause()['status'])
        vm.reset()
        vm.powerdown()
        self.assertFalse(vm.exited)
        vm.close()
        vm.close()
        self.assertTrue(vm.exited)
        self.assertEqual(['terminate', 'kill'], self.child.signals)
        self.assertEqual('exited', self.run._read()['state'])
        self.assertEqual(b'not a real disk; executor must be fake', self.fixture.base.read_bytes())
        self.assertTrue((self.run.directory / 'root.qcow2').exists())
        self.assertNotIn(self.run._identity[2], (self.run.directory / 'lifecycle.jsonl').read_text())
        self.assertFalse(json.loads((self.run.directory / 'launch-plan.json').read_text())['executed'])

    def test_unconfirmed_exit_keeps_lease_and_handle_for_retry(self):
        vm = self.start()
        self.child.stubborn = True
        with self.assertRaises(lifecycle.LifecycleError) as caught:
            vm.close()
        self.assertIs(vm, caught.exception.vm)
        with self.assertRaises(ValueError):
            self.fixture.lease.release()
        self.child.stubborn = False
        vm.close()
        self.assertTrue(vm.exited)

    def test_uuid_mismatch_tears_down_child_and_retains_evidence(self):
        self.control.bad_uuid = True
        with self.assertRaises(lifecycle.LifecycleError) as caught:
            self.start()
        self.assertTrue(caught.exception.vm.exited)
        self.assertEqual('quarantined', self.run._read()['state'])

    def test_startup_failure_preserves_live_handle_when_kill_does_not_finish(self):
        self.control.bad_uuid = True
        self.child.stubborn = True
        with self.assertRaises(lifecycle.LifecycleError) as caught:
            self.start()
        vm = caught.exception.vm
        self.assertFalse(vm.exited)
        with self.assertRaises(ValueError):
            self.fixture.lease.release()
        self.child.stubborn = False
        vm.close()

    def test_early_exit_is_reaped_without_signalling(self):
        vm = self.start()
        self.child.returncode = 7
        with self.assertRaises(lifecycle.LifecycleError):
            vm.resume()
        with self.assertRaises(lifecycle.LifecycleError):
            vm.status()
        vm.close()
        self.assertTrue(vm.exited)
        self.assertEqual([], self.child.signals)

    def test_lost_manifest_ownership_stops_commands_and_signals(self):
        vm = self.start()
        path = self.run.directory / 'manifest.json'
        original = path.read_bytes()
        record = json.loads(original)
        record['owner_token'] = '0' * 64
        path.write_text(json.dumps(record))
        commands = list(self.control.commands)
        try:
            with self.assertRaises(ValueError):
                vm.resume()
            with self.assertRaises(ValueError):
                vm.close()
            self.assertEqual(commands, self.control.commands)
            self.assertEqual([], self.child.signals)
        finally:
            path.write_bytes(original)
            vm.close()

    def test_spawn_failure_retains_safe_evidence_without_leaking_exception(self):
        lifecycle.subprocess.Popen.side_effect = OSError('SECRET')
        with self.assertRaises(lifecycle.LifecycleError):
            self.start()
        self.assertFalse(self.run._lease._active)
        self.assertEqual('quarantined', self.run._read()['state'])
        self.assertNotIn('SECRET', (self.run.directory / 'lifecycle.jsonl').read_text())

    def test_runtime_argv_uses_only_private_qmp_and_original_plan(self):
        vm = self.start()
        try:
            args, kwargs = lifecycle.subprocess.Popen.call_args
            self.assertEqual(self.plan['argv'], args[0][:-5])
            self.assertEqual(['-S', '-chardev', 'socket,id=control,fd=42',
                              '-mon', 'chardev=control,mode=control'], args[0][-5:])
            self.assertEqual((42,), kwargs['pass_fds'])
            self.assertFalse(kwargs['shell'])
            self.assertTrue(kwargs['close_fds'])
            self.assertTrue(kwargs['start_new_session'])
            self.assertEqual(subprocess.DEVNULL, kwargs['stdout'])
            self.assertEqual(subprocess.DEVNULL, kwargs['stderr'])
        finally:
            vm.close()

    def test_plan_tampering_blocks_spawn(self):
        self.plan['argv'].append('-enable-kvm')
        (self.run.directory / 'launch-plan.json').write_text(json.dumps(self.plan))
        with self.assertRaises(lifecycle.LifecycleError):
            self.start()
        lifecycle.subprocess.Popen.assert_not_called()

    def test_real_host_gate_rejects_windows(self):
        with patch.object(lifecycle.sys, 'platform', 'win32'):
            with self.assertRaises(lifecycle.LifecycleError):
                REAL_HOST()


if __name__ == '__main__':
    unittest.main()
