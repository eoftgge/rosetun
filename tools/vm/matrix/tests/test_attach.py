"""A controller killed in each phase, then attach or recover --close from this process.

The controller is a real process (`fake_controller`) on a real ledger, run
state and `lifecycle.start`; its QEMU is `fake_qemu`, a real process that
listens on the named sockets. Only the guest job is stood in for: the import
and the job's guest files are not part of the fake guest.
"""

import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools.vm.matrix import lifecycle, orchestrator
from tools.vm.matrix.linux_l2 import LinuxL2Job
from tools.vm.matrix.resources import (StandLease, archive_run, bind_run, completion_verified, inspect_runs,
                                       read_manifest, _process_status)
from tools.vm.matrix.tests import fake_controller

REPOSITORY = Path(__file__).resolve().parents[4]
ORDINARY = [('start', 'intent'), ('start', 'qmp-ready-paused'), ('cont', 'intent'), ('cont', 'command-accepted'),
            ('cont', 'confirmed'), ('close', 'intent'), ('exit', 'child-reaped'), ('qga', 'closed'),
            ('close', 'confirmed'), ('completion', 'controls-closed-child-reaped')]


@unittest.skipUnless(sys.platform.startswith('linux') and hasattr(os, 'pidfd_open'), 'needs Linux /proc and pidfds')
class AttachTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.state = Path(temp.name) / 'state'
        for item in [*fake_controller.patches(), patch.object(orchestrator, '_current_commit', return_value=None)]:
            item.start()
            self.addCleanup(item.stop)
        self.addCleanup(self.stop_leftovers)

    def stop_leftovers(self):
        # A failed test must not leave a fake QEMU behind: only a process whose recorded identity still holds.
        for directory in (self.state / 'runs').glob('*'):
            try:
                for resource in read_manifest(directory)['resources']:
                    if resource['kind'] == 'process' and _process_status(resource) == 'alive':
                        os.kill(resource['pid'], signal.SIGKILL)
            except (OSError, ValueError):
                pass

    def controller(self, phase):
        # The shared patches replace Popen for QEMU; the controller itself is a plain process.
        process = fake_controller.REAL_POPEN([sys.executable, '-B', '-m', 'tools.vm.matrix.tests.fake_controller',
                                    str(self.state), phase], cwd=REPOSITORY, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, start_new_session=True)
        self.addCleanup(lambda: process.poll() is None and process.kill())
        self.addCleanup(process.wait)
        self.addCleanup(process.stdout.close)
        if not select.select([process.stdout], [], [], 60)[0]:
            self.fail('the controller did not reach ' + phase)
        word, run_id = process.stdout.readline().decode().split()
        self.assertEqual('CLOSED' if phase == 'end' else 'READY', word)
        return process, run_id

    def killed(self, phase):
        process, run_id = self.controller(phase)
        os.kill(process.pid, signal.SIGKILL)
        process.wait()
        return run_id

    def directory(self, run_id):
        return self.state / 'runs' / run_id

    def record(self, run_id):
        return json.loads((self.directory(run_id) / 'run-state.json').read_text())

    def journal(self, run_id):
        return (self.directory(run_id) / 'lifecycle.jsonl').read_bytes()

    def process_alive(self, run_id):
        resources = read_manifest(self.directory(run_id))['resources']
        return any(_process_status(r) == 'alive' for r in resources if r['kind'] == 'process')

    def assert_stand_free(self):
        self.assertTrue(all(run['completion_verified'] for run in inspect_runs(self.state)))
        StandLease(self.state, 'stand').acquire().release()

    def fake_job(self):
        job = SimpleNamespace(assessment=None, collects=0, loads=0)
        def collect():
            job.collects += 1
            job.assessment = dict(acceptance=dict(accepted=True, release=False))
        def load():
            job.loads += 1
            job.assessment = dict(acceptance=dict(accepted=True, release=False))
        job.collect = collect
        job.load_assessment = load
        job.snapshot = lambda: dict(accepted=job.assessment is not None)
        return job

    def test_an_ordinary_run_on_named_sockets_keeps_its_journal(self):
        _, run_id = self.controller('end')
        rows = [json.loads(line) for line in self.journal(run_id).splitlines()]
        self.assertEqual(ORDINARY, [(row['action'], row['result']) for row in rows])
        self.assert_stand_free()

    def test_a_controller_killed_while_preparing_leaves_nothing_to_attach_and_the_run_archives(self):
        run_id = self.killed('preparing')
        result = orchestrator.attach_run(self.state, run_id, sleep=lambda s: None, progress=lambda s: None)
        self.assertEqual(('attach-phase-not-resumable', 2, False),
                         (result['refused'], result['exit_code'], result['attached']))
        answer, code = orchestrator.close_run(self.state, run_id)
        self.assertEqual(('run-not-attachable', 1), (answer['refused'], code))
        self.assertTrue(archive_run(self.state, run_id)['archived'])

    def test_a_controller_killed_before_submission_is_refused_and_recover_close_frees_the_stand(self):
        run_id = self.killed('boot')
        journal, before = self.journal(run_id), self.record(run_id)
        result = orchestrator.attach_run(self.state, run_id, sleep=lambda s: None, progress=lambda s: None)
        self.assertEqual('attach-phase-not-resumable', result['refused'])
        self.assertEqual(journal, self.journal(run_id))
        self.assertTrue(self.process_alive(run_id))
        answer, code = orchestrator.close_run(self.state, run_id)
        self.assertEqual(0, code, answer)
        self.assertEqual((True, 'quarantined', 'closed-by-recover'),
                         (answer['completion_verified'], answer['phase'], answer['reason']))
        self.assertFalse(self.process_alive(run_id))
        after = self.record(run_id)
        self.assertGreater(after['budgets']['qmp_calls'], before['budgets']['qmp_calls'])
        rows = [json.loads(line) for line in self.journal(run_id).splitlines()]
        self.assertIn(('exit', 'exit-observed'), [(row['action'], row['result']) for row in rows])
        summary = json.loads((self.directory(run_id) / 'execution-summary.json').read_text())
        self.assertEqual((True, 1, 2), (summary['attached'], summary['attachments'], summary['exit_code']))
        self.assert_stand_free()

    def test_attach_carries_a_run_killed_in_each_later_phase_to_a_completed_summary(self):
        for phase in ('submit', 'wait', 'collect', 'close'):
            with self.subTest(phase=phase):
                run_id = self.killed(phase)
                before = self.record(run_id)
                job = self.fake_job()
                with patch.object(LinuxL2Job, 'restore', return_value=job):
                    result = orchestrator.attach_run(self.state, run_id, sleep=lambda s: None, progress=lambda s: None)
                self.assertEqual([], result['errors'], phase)
                self.assertEqual((True, 1, True, 0),
                                 (result['attached'], result['attachments'], result['completion'],
                                  result['exit_code']))
                # Killed while closing, the collection is already saved: it is read back, never asked again.
                self.assertEqual((0, 1) if phase == 'close' else (1, 0), (job.collects, job.loads))
                after = self.record(run_id)
                self.assertEqual('completed', after['phase'])
                for name, value in before['budgets'].items():
                    self.assertGreaterEqual(after['budgets'][name], value, name)
                self.assertGreater(after['budgets']['qmp_calls'], before['budgets']['qmp_calls'])
                self.assertEqual(0 if phase == 'close' else 1, after['budgets']['qga_recoveries'])
                self.assertTrue(completion_verified(self.directory(run_id), read_manifest(self.directory(run_id))))
                self.assert_stand_free()

    def test_a_second_attach_is_refused_while_the_first_holds_the_run(self):
        run_id = self.killed('wait')
        lease = StandLease(self.state, 'stand').acquire(recovery=True)
        run = bind_run(lease, run_id)
        from tools.vm.matrix.run_state import RunState
        RunState.load(run)
        vm = lifecycle.attach(run)
        try:
            self.assertEqual('stand-locked', orchestrator.attach_run(self.state, run_id)['refused'])
            with self.assertRaisesRegex(lifecycle.LifecycleError, 'run-control-locked'):
                lifecycle.attach(bind_run(lease, run_id))
        finally:
            vm.close()
            lease.release()
        self.assert_stand_free()

    def test_a_process_that_is_not_the_recorded_one_is_refused_and_left_alone(self):
        run_id = self.killed('wait')
        manifest_path = self.directory(run_id) / 'manifest.json'
        original = manifest_path.read_bytes()
        manifest = json.loads(original)
        for resource in manifest['resources']:
            if resource['kind'] == 'process':
                # Same pid, another start time: what a reused pid looks like.
                resource['start_id'] = str(int(resource['start_id']) + 1)
        manifest_path.write_text(json.dumps(manifest))
        journal, record = self.journal(run_id), self.record(run_id)
        result = orchestrator.attach_run(self.state, run_id, sleep=lambda s: None, progress=lambda s: None)
        self.assertEqual('vm-process-not-alive', result['refused'])
        self.assertEqual(('vm-process-not-alive', 1),
                         (lambda a: (a[0]['refused'], a[1]))(orchestrator.close_run(self.state, run_id)))
        self.assertEqual(journal, self.journal(run_id))
        self.assertEqual(record['budgets'], self.record(run_id)['budgets'])
        manifest_path.write_bytes(original)
        self.assertTrue(self.process_alive(run_id))
        self.assertEqual(0, orchestrator.close_run(self.state, run_id)[1])


if __name__ == '__main__':
    unittest.main()
