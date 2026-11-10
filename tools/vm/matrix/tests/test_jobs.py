"""Offline jobs and real Vm recovery contracts; all QEMU and QGA peers are fakes."""

import hashlib
import json
import unittest
from unittest.mock import patch

from tools.vm.matrix import lifecycle
from tools.vm.matrix.jobs import SmokeJob, JobError, LAUNCHER, SCHEMA
from tools.vm.matrix.qga import Qga, QgaError
from tools.vm.matrix.tests.test_qga import Client, Relay, Stream, BOOT, info, read
from tools.vm.matrix.tests import test_lifecycle
from tools.vm.matrix.resources import completion_verified

GUEST = '20261111T010203Z-0123abcd'


class JobsTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_lifecycle.LifecycleTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.enable_qga()
        self.agent = self.agent_new()
        with patch.object(lifecycle, 'Qga', return_value=self.agent):
            self.vm = self.fixture.start()
        self.addCleanup(self.close_vm)
        self.vm.timeout = 1
        with patch('socket.socketpair', test_lifecycle.REAL_SOCKETPAIR):
            self.vm.observe_guest()
        self.job = SmokeJob(self.vm, enabled=True, guest_run_id=GUEST, manifest_sha256='a' * 64)
        self.files = {}
        self.current = None
        self.install_files(self.agent)

    def close_vm(self):
        if not self.vm.completed:
            try:
                self.vm.hard_off()
            except lifecycle.LifecycleError:
                # Evidence-failure tests deliberately prohibit completion.
                self.assertTrue(self.vm.exited)

    def agent_new(self):
        agent = Qga(Stream(b'\xff{"return":123}\n'), client_factory=Client, relay_factory=Relay, sync_id=123)
        self.addCleanup(agent.close)
        with patch('socket.socketpair', test_lifecycle.REAL_SOCKETPAIR):
            agent.connect(1)
        agent.rpc_error = QgaError
        commands = info()
        commands['supported_commands'] += [dict(name=n, enabled=True, **{'success-response': True})
                                           for n in ('guest-exec', 'guest-exec-status')]
        agent.client.responses.update({'guest-info': commands, 'guest-exec': {'pid': 42},
                                       'guest-exec-status': {'exited': True, 'exitcode': 0}})
        return agent

    def install_files(self, agent):
        def opened():
            path = agent.client.commands[-1][1]['path']
            if path == '/proc/sys/kernel/random/boot_id':
                self.current = (BOOT + '\n').encode()
            else:
                name = path.rsplit('/', 1)[1]
                if name not in self.files:
                    raise QgaError('qga-rpc-rejected')
                self.current = self.files[name]
            return 7
        agent.client.responses['guest-file-open'] = opened
        agent.client.responses['guest-file-read'] = lambda: read(self.current)

    def record(self, state='succeeded', **changes):
        return json.dumps(dict(self.job.identity, schema=SCHEMA, state=state,
                               artifact_sha256=hashlib.sha256(b'diagnostic\n').hexdigest()
                               if state == 'succeeded' else '', **changes)).encode()

    def terminal(self, state='succeeded'):
        self.files['smoke-terminal.json'] = self.record(state)
        self.files['smoke-artifact.txt'] = b'diagnostic\n'

    def test_submit_is_fixed_and_duplicate_cannot_execute(self):
        self.job.identity['guest_run_id'] = '../escape'
        result = self.job.submit()
        self.assertEqual('UNVERIFIED', result['verification'])
        call = [a for n, a in self.agent.client.commands if n == 'guest-exec'][0]
        self.assertEqual(LAUNCHER, call['path'])
        self.assertEqual([GUEST, '/root/rosetun-l2-stage/' + GUEST, 'a' * 64], call['arg'])
        with self.assertRaises(JobError):
            self.job.submit()
        with self.assertRaises(JobError):
            SmokeJob(self.vm, enabled=True, guest_run_id=GUEST, manifest_sha256='a' * 64)
        self.assertEqual(1, sum(n == 'guest-exec' for n, _ in self.agent.client.commands))

    def test_exec_timeout_never_retries_and_collects_after_real_recover_method(self):
        self.agent.client.responses['guest-exec'] = TimeoutError()
        with self.assertRaises(QgaError):
            self.job.submit()
        self.assertEqual('unknown', self.job.submission)
        replacement = self.agent_new()
        self.install_files(replacement)
        with patch.object(lifecycle, 'Qga', return_value=replacement):
            self.vm.recover_guest()
        self.terminal()
        self.assertEqual('VERIFIED', self.job.collect()['verification'])
        self.assertFalse(any(n == 'guest-exec' for n, _ in replacement.client.commands))
        with self.assertRaises(JobError):
            self.job.submit()

    def test_launcher_exit_does_not_prove_job_and_started_is_not_terminal(self):
        self.job.submit()
        with self.assertRaises(JobError):
            self.job.collect()
        self.assertEqual('exited-zero', self.job.launcher)
        self.files['smoke-started.json'] = self.record('started')
        self.assertEqual('started', self.job.inspect()['job'])
        self.assertEqual('UNVERIFIED', self.job.verification)
        with self.assertRaises(JobError):
            self.job.collect()

    def test_foreign_stale_incomplete_and_corrupt_results_are_unverified(self):
        self.job.submit()
        for key in self.job.identity:
            value = json.loads(self.record())
            value[key] = 'foreign'
            self.files['smoke-terminal.json'] = json.dumps(value).encode()
            with self.assertRaises(JobError):
                self.job.collect()
        for raw in (b'{', b'{}', b'{"schema":1,"schema":2}', b'x' * 4097):
            self.files['smoke-terminal.json'] = raw
            with self.assertRaises(JobError):
                self.job.collect()
            self.assertEqual('UNVERIFIED', self.job.verification)

    def test_artifact_corruption_and_handles_are_retained_in_evidence(self):
        self.job.submit()
        self.terminal()
        self.files['smoke-artifact.txt'] = b'corrupt'
        with self.assertRaises(JobError):
            self.job.collect()
        self.assertIn('closed', self.job.handles.values())
        rows = [json.loads(line) for line in (self.vm.run.directory / 'job-evidence.jsonl').read_text().splitlines()]
        self.assertTrue(any(r['operation'] == 'file' for r in rows))
        self.assertEqual('collect-unverified', rows[-1]['operation'])

    def test_bad_read_fields_and_lost_close_never_verify(self):
        self.job.submit()
        self.terminal()
        for change in ({'count': True}, {'eof': 1}, {'buf-b64': '!'}, {'count': 0}):
            self.agent.client.responses['guest-file-read'] = read(self.record(), **change)
            with self.assertRaises(JobError):
                self.job.collect()
            self.assertTrue(self.agent.valid)
        self.install_files(self.agent)
        self.agent.client.responses['guest-file-close'] = TimeoutError()
        with self.assertRaises(JobError):
            self.job.collect()
        self.assertIn('close-unconfirmed', self.job.handles.values())
        self.assertFalse(self.agent.valid)

    def test_poll_rpc_and_deadline_limits(self):
        self.job.submit()
        self.job.polls = 12
        with self.assertRaises(JobError):
            self.job.collect()
        self.job.polls = 0
        self.job.calls = 64
        with self.assertRaises(JobError):
            self.job.collect()
        self.job.deadline = 0
        with self.assertRaises(JobError):
            self.job.collect()

    def test_completion_does_not_mask_timeout_job(self):
        self.job.submit()
        self.terminal('timeout')
        result = self.job.collect()
        self.assertEqual(('timeout', 'VERIFIED', False),
                         (result['job'], result['verification'], result['release_gate']))
        self.vm.hard_off()
        self.assertTrue(completion_verified(self.vm.run.directory, self.vm.run._read()))
        self.assertEqual('timeout', self.job.snapshot()['job'])

    def test_traversal_and_opt_in(self):
        del self.vm._smoke_job
        for guest in ('../escape', 'x/y', GUEST + '/..', 'a' * 32):
            with self.assertRaises(JobError):
                SmokeJob(self.vm, enabled=True, guest_run_id=guest, manifest_sha256='a' * 64)
        with self.assertRaises(JobError):
            SmokeJob(self.vm, guest_run_id=GUEST, manifest_sha256='a' * 64)

    def test_no_progress_and_missing_eof_close_handles(self):
        self.job.submit()
        self.terminal()
        for value in (read(b'', eof=False), read(b'x' * 4096, eof=False)):
            self.agent.client.responses['guest-file-read'] = value
            with self.assertRaises(JobError):
                self.job.collect()
            self.assertEqual('closed', self.job.handles[self.agent.session_id + ':7'])

    def test_unregistered_or_failed_evidence_prevents_submission(self):
        with patch.object(type(self.vm.run), '_read', return_value={'resources': []}):
            with self.assertRaises(JobError):
                self.job.submit()
        self.assertTrue(self.vm.evidence_failed)
        self.assertFalse(any(n == 'guest-exec' for n, _ in self.agent.client.commands))


if __name__ == '__main__':
    unittest.main()
