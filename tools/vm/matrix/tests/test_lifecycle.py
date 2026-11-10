"""Offline lifecycle tests: fake children and scripted QMP, no QEMU processes."""

import json
import io
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


class Child:
    pid = 12345

    def __init__(self):
        self.stderr = io.BytesIO(b'synthetic diagnostic')
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

    def command(self, name, timeout, *, event=None):
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
            self.assertEqual(subprocess.PIPE, kwargs['stderr'])
        finally:
            vm.close()

    def test_plan_tampering_blocks_spawn(self):
        self.plan['argv'].append('-enable-kvm')
        (self.run.directory / 'launch-plan.json').write_text(json.dumps(self.plan))
        with self.assertRaises(lifecycle.LifecycleError):
            self.start()
        lifecycle.subprocess.Popen.assert_not_called()

    def test_shutdown_confirmed_child_exit_and_reuse(self):
        from tools.vm.matrix.resources import StandLease, create_run, inspect_runs
        vm = self.start()
        original = self.control.command
        def shutdown(name, timeout, **kwargs):
            if name == 'system_powerdown':
                self.child.returncode = 0
            return original(name, timeout, **kwargs)
        self.control.command = shutdown
        self.assertEqual(0, vm.request_shutdown())
        self.assertTrue(vm.completed)
        self.fixture.lease.release()
        self.assertTrue(inspect_runs(self.fixture.root / 'state')[0]['completion_verified'])
        with StandLease(self.fixture.root / 'state', 'stand') as lease:
            create_run(lease)

    def test_shutdown_timeout_remains_error_after_successful_close(self):
        vm = self.start()
        with self.assertRaisesRegex(lifecycle.LifecycleError, 'shutdown-unconfirmed'):
            vm.request_shutdown(timeout=0.01)
        vm.close()
        self.assertTrue(vm.completed)
        self.assertIn('shutdown-unconfirmed', vm.operation_errors)
        records = (self.run.directory / 'lifecycle.jsonl').read_text()
        self.assertIn('"action": "shutdown",', records)
        self.assertIn('"result": "error"', records)

    def test_hard_off_never_sends_acpi_or_quit(self):
        vm = self.start()
        self.control.commands.clear()
        vm.hard_off()
        self.assertEqual([], self.control.commands)
        self.assertEqual(['kill'], self.child.signals)
        self.assertTrue(vm.completed)

    def test_missing_reset_event_stays_an_operation_error(self):
        vm = self.start()
        original = self.control.command
        def missing(name, timeout, **kwargs):
            if name == 'system_reset':
                self.control.last_command_accepted = True
                raise TimeoutError('SECRET')
            return original(name, timeout, **kwargs)
        self.control.command = missing
        with self.assertRaisesRegex(lifecycle.LifecycleError, 'reset-unconfirmed'):
            vm.reset()
        vm.close()
        self.assertIn('reset-unconfirmed', vm.operation_errors)
        self.assertNotIn('SECRET', (self.run.directory / 'lifecycle.jsonl').read_text())

    def test_pid_persistence_failure_kills_child_and_blocks_reuse(self):
        from tools.vm.matrix.resources import PreparedRun, StandLease
        original = PreparedRun.register
        def register(run, resource):
            if resource['kind'] == 'process':
                raise OSError('PID storage failed')
            return original(run, resource)
        with patch.object(PreparedRun, 'register', register), self.assertRaises(lifecycle.LifecycleError):
            self.start()
        self.assertIsNotNone(self.child.poll())
        self.fixture.lease.release()
        with self.assertRaises(ValueError):
            StandLease(self.fixture.root / 'state', 'stand').acquire()

    def test_completion_write_failure_blocks_new_lease_and_retains_foreign_file(self):
        from pathlib import Path
        from tools.vm.matrix.resources import StandLease
        vm = self.start()
        foreign = self.fixture.root / 'foreign.txt'
        foreign.write_text('retain')
        original = Path.open
        def fail(path, *args, **kwargs):
            if path.name == 'completion.json':
                raise OSError('evidence unavailable')
            return original(path, *args, **kwargs)
        with patch.object(Path, 'open', fail), self.assertRaises(lifecycle.LifecycleError):
            vm.close()
        self.assertTrue(vm.exited)
        self.assertEqual('retain', foreign.read_text())
        self.fixture.lease.release()
        with self.assertRaises(ValueError):
            StandLease(self.fixture.root / 'state', 'stand').acquire()

    def test_keyboard_interrupt_startup_reaps_child(self):
        with patch.object(lifecycle, '_identity', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.start()
        self.assertIsNotNone(self.child.poll())

    def test_keyboard_interrupt_close_preserved_after_hard_teardown(self):
        vm = self.start()
        original = self.child.wait
        first = True
        def interrupt(timeout):
            nonlocal first
            if first:
                first = False
                raise KeyboardInterrupt
            return original(timeout)
        self.child.wait = interrupt
        with self.assertRaises(KeyboardInterrupt):
            vm.close()
        self.assertIsNotNone(self.child.poll())
        self.assertTrue(vm.completed)

    def test_legacy_exited_and_corrupt_completion_block_reuse(self):
        from tools.vm.matrix.resources import StandLease
        vm = self.start()
        vm.close()
        completion = self.run.directory / 'completion.json'
        data = json.loads(completion.read_text())
        data['schema'] = 'unknown'
        completion.write_text(json.dumps(data))
        self.fixture.lease.release()
        with self.assertRaises(ValueError):
            StandLease(self.fixture.root / 'state', 'stand').acquire()

    def test_legacy_exited_without_proof_and_truncated_journal_are_blocking(self):
        from tools.vm.matrix.resources import completion_verified
        vm = self.start()
        vm.close()
        manifest = self.run._read()
        self.assertTrue(completion_verified(self.run.directory, manifest))
        journal = self.run.directory / 'lifecycle.jsonl'
        original = journal.read_bytes()
        journal.write_bytes(original[:-1])
        self.assertFalse(completion_verified(self.run.directory, manifest))
        journal.write_bytes(original)
        # Removing only our own proof simulates an old exited ledger. No disk or
        # unrelated file is removed by the lifecycle/recovery implementation.
        proof = self.run.directory / 'completion.json'
        proof.rename(self.run.directory / 'completion.saved')
        self.assertFalse(completion_verified(self.run.directory, manifest))

    def test_real_host_gate_rejects_windows(self):
        with patch.object(lifecycle.sys, 'platform', 'win32'):
            with self.assertRaises(lifecycle.LifecycleError):
                REAL_HOST()


if __name__ == '__main__':
    unittest.main()
