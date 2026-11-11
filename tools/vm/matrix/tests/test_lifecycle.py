"""Offline lifecycle tests: fake children and scripted QMP, no QEMU processes."""

import json
import io
import subprocess
import unittest
from unittest.mock import patch

from tools.vm.matrix import lifecycle
from tools.vm.matrix.tests import test_qemu

REAL_HOST = lifecycle._host
REAL_SOCKETPAIR = lifecycle.socket.socketpair


class Stream:
    def __init__(self, chunks=()):
        self.chunks = list(chunks)
        self.sent = []
        self.closed = False

    def dup(self):
        return Stream(self.chunks)

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

    def enable_qga(self):
        from dataclasses import replace
        from tools.vm.matrix.qemu import _launch_plan
        self.fixture.config = replace(self.fixture.config, qga=True)
        self.plan = _launch_plan(self.fixture.config, self.fixture.image,
                                 self.run.directory / 'root.qcow2', self.plan['uuid'])
        (self.run.directory / 'launch-plan.json').write_text(json.dumps(self.plan))

    def test_qga_is_separate_and_completion_requires_its_close(self):
        from tools.vm.matrix.resources import completion_verified
        from tools.vm.matrix.tests.test_qga import Client, Relay, Stream as AgentStream
        from tools.vm.matrix.qga import Qga
        self.enable_qga()
        monitor_parent, monitor_child = Stream(), Stream()
        agent_parent = AgentStream(b'\xff{"return":123}\n')
        agent_child = Stream()
        agent_child.fileno = lambda: 43
        agent = Qga(agent_parent, client_factory=Client, relay_factory=Relay)
        self.addCleanup(agent.close)
        with patch.object(lifecycle.socket, 'socketpair', side_effect=[
                (monitor_parent, monitor_child), (agent_parent, agent_child)]), patch.object(
                lifecycle, 'Qga', return_value=agent), patch.object(
                lifecycle.subprocess, 'Popen', return_value=self.child) as popen:
            vm = self.start()
        self.assertEqual((42, 43), popen.call_args.kwargs['pass_fds'])
        argv = popen.call_args.args[0]
        self.assertIn('socket,id=guestagent,fd=43', argv)
        self.assertIn('virtio-serial-pci,id=guestserial', argv)
        self.assertIn('virtserialport,bus=guestserial.0,chardev=guestagent,name=org.qemu.guest_agent.0', argv)
        self.assertTrue(monitor_child.closed)
        self.assertTrue(agent_child.closed)
        self.assertFalse(agent_parent.closed)
        self.assertNotIn(self.run._identity[2], json.dumps(argv))
        vm.timeout = 1
        with patch('secrets.randbits', return_value=123), patch(
                'socket.socketpair', REAL_SOCKETPAIR):
            row = vm.observe_guest()
        self.assertEqual('observed', row['result'])
        self.assertEqual(self.plan['uuid'], row['vm_uuid'])
        vm.reset()
        self.assertIsNone(vm.guest_observation)
        with self.assertRaises(lifecycle.LifecycleError):
            vm.observe_guest()
        self.assertEqual('running', vm.resume()['status'])
        with patch.object(agent, 'close', side_effect=ValueError('close failed')):
            with self.assertRaisesRegex(lifecycle.LifecycleError, 'control-close-unconfirmed'):
                vm.hard_off()
        self.assertTrue(vm.exited)
        self.assertFalse(vm.completed)
        self.assertFalse(completion_verified(self.run.directory, self.run._read()))
        vm.hard_off()
        self.assertTrue(agent_parent.closed)
        self.assertTrue(vm.completed)
        self.assertTrue(completion_verified(self.run.directory, self.run._read()))
        # Even a consistently rehashed journal must carry QGA closure evidence.
        import hashlib
        journal_path = self.run.directory / 'lifecycle.jsonl'
        rows = [json.loads(line) for line in journal_path.read_text().splitlines()]
        for row in rows:
            if row['action'] == 'qga':
                row['result'] = 'unconfirmed'
        raw = ''.join(json.dumps(row) + '\n' for row in rows).encode()
        journal_path.write_bytes(raw)
        proof_path = self.run.directory / 'completion.json'
        proof = json.loads(proof_path.read_text())
        proof['journal_sha256'] = hashlib.sha256(raw).hexdigest()
        proof_path.write_text(json.dumps(proof))
        self.assertFalse(completion_verified(self.run.directory, self.run._read()))
        journal = (self.run.directory / 'qga-observations.jsonl').read_text()
        self.assertNotIn(self.run._identity[2], journal)
        self.assertNotIn(self.run._identity[2].encode(), b''.join(agent_parent.sent))

    def test_qga_parent_and_child_close_when_spawn_fails(self):
        from tools.vm.matrix.tests.test_qga import Stream as AgentStream
        self.enable_qga()
        agent_parent, agent_child = AgentStream(b''), Stream()
        with patch.object(lifecycle.socket, 'socketpair', side_effect=[
                (Stream(), Stream()), (agent_parent, agent_child)]), patch.object(
                lifecycle.subprocess, 'Popen', side_effect=OSError('spawn failed')):
            with self.assertRaises(lifecycle.LifecycleError):
                self.start()
        self.assertTrue(agent_parent.closed)
        self.assertTrue(agent_child.closed)

    def test_completion_rejects_qga_close_before_final_reap_and_later_failure(self):
        import hashlib
        from tools.vm.matrix.resources import completion_verified
        from unittest.mock import Mock
        self.enable_qga()
        with patch.object(lifecycle, 'Qga', return_value=Mock()):
            vm = self.start()
        vm.hard_off()
        manifest = self.run._read()
        journal = self.run.directory / 'lifecycle.jsonl'
        proof_path = self.run.directory / 'completion.json'
        original = [json.loads(line) for line in journal.read_text().splitlines()]
        self.assertTrue(completion_verified(self.run.directory, manifest))
        for mode in ('before-reap', 'later-failure'):
            rows = json.loads(json.dumps(original))
            closed = next(row for row in rows if row['action'] == 'qga')
            if mode == 'before-reap':
                rows.remove(closed)
                index = next(i for i, row in enumerate(rows) if row['action'] == 'exit')
                rows.insert(index, closed)
            else:
                row = dict(closed, result='unconfirmed')
                rows.insert(-1, row)
            for index, row in enumerate(rows, 1):
                row['sequence'] = index
            raw = ''.join(json.dumps(row) + '\n' for row in rows).encode()
            journal.write_bytes(raw)
            proof = json.loads(proof_path.read_text())
            proof['journal_sha256'] = hashlib.sha256(raw).hexdigest()
            proof_path.write_text(json.dumps(proof))
            self.assertFalse(completion_verified(self.run.directory, manifest), mode)

    def test_pending_launch_endpoint_blocks_otherwise_complete_vm(self):
        vm = self.start()
        endpoint = Stream()
        vm.launch_sockets.append(endpoint)
        with patch.object(endpoint, 'close', side_effect=OSError('close failed')):
            with self.assertRaisesRegex(lifecycle.LifecycleError, 'control-close-unconfirmed'):
                vm.hard_off()
        self.assertTrue(vm.exited)
        self.assertFalse(vm.completed)
        self.assertFalse((self.run.directory / 'completion.json').exists())
        vm.hard_off()
        self.assertTrue(endpoint.closed)
        self.assertTrue(vm.completed)

    def test_failed_child_endpoint_close_blocks_completion_and_retains_vm_handle(self):
        from tools.vm.matrix.tests.test_qga import Stream as AgentStream
        self.enable_qga()
        agent_parent, agent_child = AgentStream(b''), Stream()
        with patch.object(agent_child, 'close', side_effect=OSError('close failed')), patch.object(
                lifecycle.socket, 'socketpair', side_effect=[
                    (Stream(), Stream()), (agent_parent, agent_child)]):
            with self.assertRaises(lifecycle.LifecycleError) as caught:
                self.start()
        vm = caught.exception.vm
        self.assertIsNotNone(vm)
        self.assertTrue(vm.exited)
        self.assertFalse(vm.completed)
        self.assertIn(agent_child, vm.launch_sockets)
        self.assertFalse((self.run.directory / 'completion.json').exists())
        self.assertTrue(agent_parent.closed)
        # Retry may close descriptors, but cannot erase the failed evidence.
        with self.assertRaises(lifecycle.LifecycleError):
            vm.hard_off()
        self.assertTrue(agent_child.closed)

    def test_lost_qga_does_not_prevent_qmp_quit(self):
        from unittest.mock import Mock
        vm = self.start()
        vm.qga = Mock()
        vm.qga.attempted = True
        vm.qga.session_id = 'synthetic-session'
        vm.qga.sync_id = None
        vm.qga.probe.return_value = {'version': self.run._identity[2], 'required_commands': []}
        with self.assertRaises(lifecycle.LifecycleError):
            vm.observe_guest()
        vm.qga.read_boot_id.assert_not_called()
        self.assertNotIn(self.run._identity[2],
                         (self.run.directory / 'qga-observations.jsonl').read_text())
        vm.qga.probe.side_effect = ValueError('lost agent')
        with self.assertRaises(lifecycle.LifecycleError):
            vm.observe_guest()
        self.assertIsNone(vm.guest_observation)
        vm.close()
        self.assertIn('quit', self.control.commands)
        self.assertTrue(vm.completed)

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

    def assert_failed_before_process(self, caught):
        self.assertEqual('vm-start-failed', str(caught.exception))
        self.assertIsNone(caught.exception.vm)
        self.assertIsNone(caught.exception.__cause__)
        self.assertTrue(caught.exception.__suppress_context__)
        self.assertNotIn('SECRET', str(caught.exception))
        lifecycle.subprocess.Popen.assert_not_called()
        self.assertFalse(self.run._lease._active)
        manifest = self.run._read()
        self.assertEqual('quarantined', manifest['state'])
        self.assertEqual(['vm-start-failed'], manifest['reasons'])

    def test_registration_failure_before_the_process_quarantines_the_run(self):
        from tools.vm.matrix.resources import PreparedRun
        original = PreparedRun.register
        def register(run, resource):
            if resource['id'] == 'completion':
                raise OSError('SECRET')
            return original(run, resource)
        with patch.object(PreparedRun, 'register', register), self.assertRaises(
                lifecycle.LifecycleError) as caught:
            self.start()
        self.assert_failed_before_process(caught)
        self.assertEqual(['qemu-stderr'], [r['id'] for r in self.run._read()['resources']
                                           if r['id'] == 'qemu-stderr'])

    def test_touch_failure_before_the_process_quarantines_the_run(self):
        from pathlib import Path
        self.enable_qga()
        original = Path.touch
        def touch(path, *args, **kwargs):
            if path.parent.name == 'linux-l2':
                raise OSError('SECRET')
            return original(path, *args, **kwargs)
        with patch.object(Path, 'touch', touch), self.assertRaises(lifecycle.LifecycleError) as caught:
            self.start()
        self.assert_failed_before_process(caught)

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

    def exhaust_ordinary_journal(self, vm):
        from tools.vm.matrix.lifecycle import ORDINARY_ROWS
        while True:
            before = list(self.control.commands)
            try:
                vm.pause() if vm.status()['running'] else vm.resume()
            except lifecycle.LifecycleError as error:
                self.assertEqual('lifecycle-journal-limit', str(error))
                self.assertIsNone(error.vm)
                return before
            self.assertLessEqual(vm.events, ORDINARY_ROWS)

    def test_ordinary_journal_limit_refuses_cleanly_and_close_still_completes(self):
        from tools.vm.matrix.resources import completion_verified
        vm = self.start()
        before = self.exhaust_ordinary_journal(vm)
        # The refused operation sent nothing; its only trace is the status poll above.
        self.assertEqual(before + ['query-status'], self.control.commands)
        self.assertFalse(vm.evidence_failed)
        self.assertEqual([], vm.operation_errors)
        for operation in (vm.pause, vm.resume, vm.reset, vm.request_shutdown):
            with self.assertRaisesRegex(lifecycle.LifecycleError, 'lifecycle-journal-limit'):
                operation()
        self.assertEqual(before + ['query-status'], self.control.commands)
        self.assertEqual([], vm.operation_errors)
        self.assertFalse(vm.evidence_failed)
        vm.close()
        self.assertTrue(vm.exited and vm.completed)
        self.assertIn('quit', self.control.commands)
        manifest = self.run._read()
        self.assertEqual('exited', manifest['state'])
        self.assertTrue(completion_verified(self.run.directory, manifest))
        self.assertLessEqual(vm.events, lifecycle.JOURNAL_LIMIT)

    def test_interrupted_close_after_exhausted_ordinary_journal_still_completes(self):
        from tools.vm.matrix.resources import completion_verified
        vm = self.start()
        self.exhaust_ordinary_journal(vm)
        used = vm.events
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
        self.assertTrue(vm.completed)
        self.assertTrue(completion_verified(self.run.directory, self.run._read()))
        self.assertGreater(vm.events, used)
        self.assertLessEqual(vm.events, lifecycle.JOURNAL_LIMIT)

    def test_failed_start_rows_fit_the_teardown_reserve(self):
        self.control.bad_uuid = True
        with self.assertRaises(lifecycle.LifecycleError) as caught:
            self.start()
        vm = caught.exception.vm
        self.assertTrue(vm.exited)
        self.assertLessEqual(vm.events, lifecycle.TEARDOWN_ROWS)

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
