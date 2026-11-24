"""Stage 9c: `run windows-reboot-smoke` on the stand-in QEMU, swtpm and guest agent, offline.

The processes are real (`lifecycle.start` spawns `fake_qemu` and `fake_swtpm`, the controller talks to their named
sockets), the agent's programs are real requests, and the guest is the fake's: a PowerShell command is answered from
its encoded script, and `shutdown.exe /r /t 0` makes it restart the way a Windows guest looks from outside (the agent
goes away, QEMU reports the RESET events, the agent comes back with the next boot count). What the real guest does
with the script is checked on the stand.
"""

from copy import deepcopy
from dataclasses import asdict
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from tools.vm.matrix import config as matrix_config, lifecycle, orchestrator, qga, windows_reboot, windows_smoke
from tools.vm.matrix.qemu import prepare
from tools.vm.matrix.resources import _process_status, read_manifest
from tools.vm.matrix.tests import fake_controller, test_windows_run as base
from tools.vm.matrix.tests.posix_only import controller_only, linux_stand_paths

REPOSITORY = base.REPOSITORY
EXAMPLE = Path(__file__).resolve().parents[1] / 'execution-windows-reboot-smoke.example.toml'
STEPS = ['preflight', 'lease', 'create-run', 'save-identities', 'prepare', 'start', 'resume', 'boot', 'evidence',
         'reboot', 'reset', 'new-boot', 'evidence-after', 'shutdown', 'close', 'image-unchanged']


def fast_sleep(seconds):
    time.sleep(min(seconds, 0.05))


class Guest(unittest.TestCase):
    """The stand-in guest for the whole class: short tries and polls, and the environment a case asks for."""

    environment = {}

    def setUp(self):
        for item in [patch.object(windows_reboot, 'TRY_SECONDS', 2), patch.object(windows_reboot, 'RETRY_SECONDS', 0.2),
                     patch.object(qga, 'EXEC_POLL_SECONDS', (0.01,)),
                     patch.dict(os.environ, self.environment)]:
            item.start()
            self.addCleanup(item.stop)


@controller_only
class RebootSmokeTests(Guest, base.Base):
    def setUp(self):
        Guest.setUp(self)
        base.Base.setUp(self)
        fixture = self.fixture
        for item in [*fake_controller.patches(),
                     patch.object(windows_smoke.os, 'access', return_value=True),
                     patch('importlib.metadata.version', return_value='0.0.6'),
                     patch('tools.vm.matrix.linux_l2.source_identity',
                           return_value=dict(source_sha='0' * 40, source_dirty=False,
                                             source_dirty_digest='0' * 64))]:
            item.start()
            self.addCleanup(item.stop)
        self.addCleanup(self.stop_leftovers)
        self.state = fixture.root / 'smoke-state'
        self.config = dict(schema=windows_smoke.SCHEMA, suite='windows-reboot-smoke', mode='exploratory',
                           platform='linux-x86_64-kvm', state_directory=str(self.state), stand_id='smoke',
                           image_descriptor=str(fixture.descriptor_file), qemu=asdict(fixture.config),
                           smoke=dict(agent_wait_seconds=20, reset_wait_seconds=10, reboot_wait_seconds=20,
                                      shutdown_wait_seconds=20),
                           deadlines=dict(preparation=600))

        def prepare_run(run, image, config, *, executor):
            fixture.run = run
            return prepare(run, image, config, executor=fixture.fake)

        def start(run, *, timeout):
            fixture.calls = fixture.calls[:2]
            return lifecycle.start(run, timeout=timeout, executor=lambda argv, *, timeout, output_limit:
                                   fixture.fake(argv, timeout=30, output_limit=output_limit))
        self.adapters = SimpleNamespace(prepare=prepare_run, execute=fixture.fake, start=start)

    def stop_leftovers(self):
        for directory in (self.state / 'runs').glob('*'):
            try:
                for resource in read_manifest(directory)['resources']:
                    if resource['kind'] == 'process' and _process_status(resource) == 'alive':
                        os.kill(resource['pid'], signal.SIGKILL)
            except (OSError, ValueError):
                pass

    def smoke(self):
        return windows_smoke.run_windows_reboot_smoke(self.config, adapters=self.adapters, sleep=fast_sleep,
                                                      progress=lambda stage: None)

    def directory(self, result):
        return self.state / 'runs' / result['identities']['host_run_id']

    def journal(self, result):
        raw = (self.directory(result) / 'lifecycle.jsonl').read_text().splitlines()
        return [(row['action'], row['result']) for row in map(json.loads, raw)]

    def evidence(self, result):
        raw = (self.directory(result) / 'job-evidence.jsonl').read_text().splitlines()
        return [json.loads(line) for line in raw]

    def reasons(self, result):
        return [(error['stage'], error['reason']) for error in result['errors']]


@controller_only
class CleanRunTests(RebootSmokeTests):
    def test_a_run_boots_records_the_guest_restarts_it_once_and_takes_the_new_boot(self):
        result = self.smoke()
        self.assertEqual([], result['errors'])
        self.assertEqual((0, True), (result['exit_code'], result['completion']))
        self.assertEqual(STEPS, [row['stage'] for row in result['stages']])
        execution = result['execution']
        self.assertTrue(execution['accepted'])
        chain = execution['boot_chain']
        self.assertEqual(2, len(chain))
        self.assertNotEqual(chain[0], chain[1])
        self.assertTrue(all(boot.startswith('win-') for boot in chain), chain)
        self.assertEqual((1, 0, 1), (execution['guest_resets'], execution['resets_merged'],
                                     execution['planned_reboots']))
        self.assertEqual(('acpi', True), (execution['shutdown'], execution['image_unchanged']))
        self.assertFalse(execution['kvm_qualified'])
        self.assertEqual((False, True, False), (result['qualified'], result['diagnostic'], result['release_gate']))
        for name in ('agent_ready_seconds', 'reset_seconds', 'reboot_seconds'):
            self.assertIsNotNone(execution[name], name)

    def test_the_budgets_and_the_journal_are_those_of_one_planned_reboot(self):
        result = self.smoke()
        execution = result['execution']
        # One recovery earned by the reset; the first boot's sessions are no recoveries. The limit is 4 + 1.
        self.assertEqual(1, execution['qga_recoveries'])
        self.assertLessEqual(execution['qga_observations'], 32)
        rows = self.journal(result)
        self.assertEqual([('guest-reboot', 'intent'), ('guest-reboot', 'requested')],
                         [row for row in rows if row[0] == 'guest-reboot'])
        self.assertEqual(1, len([row for row in rows if row[0] == 'guest-reset-observed']))
        self.assertTrue([row for row in rows if row[0] == 'guest-reset-observed'][0][1].startswith('1-of-1'))
        self.assertEqual(('boot-chain-extended', '2'), [row for row in rows if row[0] == 'boot-chain-extended'][0])
        self.assertNotIn('guest-reset-coalesced', [action for action, _ in rows])
        document = json.loads((self.directory(result) / 'run-state.json').read_text())
        self.assertEqual(execution['boot_chain'], document['boot_chain'])
        self.assertEqual(execution['boot_chain'][-1], document['identities']['boot_id'])
        self.assertEqual(1, document['budgets']['qga_recoveries'])
        steps = [(row['step'], row['status']) for row in document['transitions']]
        self.assertIn(('guest-reset-1', 'intent'), steps)
        self.assertIn(('guest-reset-1', 'done'), steps)
        self.assertEqual('completed', document['phase'])

    def test_the_observations_name_the_reset_and_the_new_boot(self):
        result = self.smoke()
        rows = [json.loads(line) for line in
                (self.directory(result) / 'qga-observations.jsonl').read_text().splitlines()]
        recovery = [row for row in rows if row['operation'] == 'recovery' and row['reason'] == 'guest-reset']
        self.assertEqual(1, len(recovery))
        self.assertEqual(('changed', True, 'observed'), (recovery[0]['boot_comparison'],
                                                           recovery[0]['new_boot_confirmed'], recovery[0]['result']))
        self.assertEqual(result['execution']['boot_chain'][1], recovery[0]['boot_id'])

    def test_the_guest_is_recorded_before_and_after_with_secure_boot_the_tpm_and_utf8(self):
        result = self.smoke()
        rows = self.evidence(result)
        self.assertEqual(['before', 'after'], [row['when'] for row in rows])
        for row, boot in zip(rows, result['execution']['boot_chain']):
            self.assertEqual(('guest-evidence', boot), (row['operation'], row['boot_id']))
            guest = row['guest']
            self.assertEqual((True, {'present': True, 'ready': True}, True),
                             (guest['secure_boot'], guest['tpm'], guest['utf8_ok']))
            self.assertEqual('Microsoft Windows 11 Pro', guest['caption'])
        execution = result['execution']
        self.assertEqual({'caption', 'version', 'build', 'architecture', 'secure_boot', 'tpm', 'utf8_ok',
                          'boot_counter', 'last_boot'}, set(execution['guest']))
        # The count of boots that names a boot is the one the guest's PowerShell reads, and the kernel's start differs.
        self.assertEqual(['win-%d' % execution['guest']['boot_counter'], 'win-%d' % execution['guest_after']['boot_counter']],
                         execution['boot_chain'])
        self.assertNotEqual(execution['guest']['last_boot'], execution['guest_after']['last_boot'])
        # The owner's token is in no row of the run's evidence, and the summary has no guest text it did not name.
        token = json.loads((self.directory(result) / 'run.json').read_text())['owner_token'] \
            if (self.directory(result) / 'run.json').exists() else None
        if token:
            self.assertNotIn(token, json.dumps(rows))

    def test_the_image_is_not_hashed_again_when_its_identity_is_the_one_the_stand_recorded(self):
        # The disk is hashed in full once by the preparation; the check after the run finds the stand's record.
        with patch.object(base.ImageDescriptor, 'verify_bytes', autospec=True,
                          side_effect=base.ImageDescriptor.verify_bytes) as hashed:
            result = self.smoke()
        self.assertEqual(0, result['exit_code'])
        self.assertEqual(1, hashed.call_count)


@controller_only
class ManyResetsTests(RebootSmokeTests):
    environment = {'FAKE_QEMU_RESETS': '2'}

    def test_two_resets_of_one_restart_are_one_reboot_that_costs_one_of_the_plan(self):
        result = self.smoke()
        self.assertEqual(0, result['exit_code'], result['errors'])
        execution = result['execution']
        self.assertEqual((1, 1), (execution['guest_resets'], execution['resets_merged']))
        merged = [row for row in self.journal(result) if row[0] == 'guest-reset-coalesced']
        self.assertEqual(1, len(merged))
        self.assertTrue(merged[0][1].startswith('1-of-1 merged=1 +67ms'), merged)
        self.assertEqual(1, execution['qga_recoveries'])


@controller_only
class UnobservedBootTests(RebootSmokeTests):
    environment = {'FAKE_QEMU_RESETS': '2', 'FAKE_QEMU_RESET_GAP_US': '2500000'}

    def test_a_second_reset_after_the_window_before_the_boot_is_taken_ends_the_run(self):
        result = self.smoke()
        self.assertEqual(2, result['exit_code'])
        self.assertEqual([('reset', 'guest-reboot-unobserved')], self.reasons(result))
        self.assertFalse(result['execution']['accepted'])
        self.assertEqual(1, len(result['execution']['boot_chain']))
        self.assertTrue(result['completion'])
        self.assertEqual('forced', result['execution']['shutdown'])


@controller_only
class LimitTests(RebootSmokeTests):
    def test_a_guest_that_does_not_restart_is_an_error_at_the_wait_for_its_reset(self):
        self.config['smoke']['reset_wait_seconds'] = 1
        with patch.dict(os.environ, FAKE_QEMU_NO_RESTART='1'):
            result = self.smoke()
        self.assertEqual(2, result['exit_code'])
        self.assertEqual([('reset', 'guest-reset-deadline')], self.reasons(result))
        self.assertEqual(0, result['execution']['guest_resets'])
        self.assertTrue(result['completion'])

    def test_a_new_boot_that_does_not_answer_within_the_time_is_an_error_and_the_run_is_closed_hard(self):
        self.config['smoke']['reboot_wait_seconds'] = 3
        with patch.dict(os.environ, FAKE_QEMU_BOOT_SECONDS='60'):
            result = self.smoke()
        self.assertEqual(2, result['exit_code'])
        self.assertEqual([('new-boot', 'rebooted-guest-deadline')], self.reasons(result))
        self.assertEqual(1, result['execution']['guest_resets'])
        self.assertEqual(1, len(result['execution']['boot_chain']))
        self.assertTrue(result['completion'])
        self.assertEqual('forced', result['execution']['shutdown'])

    def test_a_slow_boot_is_waited_for_with_new_sessions_that_earn_no_second_recovery(self):
        with patch.dict(os.environ, FAKE_QEMU_BOOT_SECONDS='3'):
            result = self.smoke()
        self.assertEqual(0, result['exit_code'], result['errors'])
        execution = result['execution']
        self.assertEqual(1, execution['qga_recoveries'])
        self.assertGreater(execution['qga_observations'], 3)
        self.assertGreater(execution['reboot_seconds'], 3)

    def test_a_guest_whose_boot_id_cannot_be_read_is_an_error_of_the_first_boot(self):
        self.config['smoke']['agent_wait_seconds'] = 3
        with patch.dict(os.environ, FAKE_QEMU_REG_FAIL='1'):
            result = self.smoke()
        self.assertEqual(2, result['exit_code'])
        self.assertEqual([('boot', 'initial-guest-deadline')], self.reasons(result))
        # What the guest wrote on its error stream is evidence of the session at most, never the name of an error.
        self.assertNotIn('unable to find', json.dumps(result))
        self.assertTrue(result['completion'])

    def test_a_powershell_that_fails_is_an_error_of_the_evidence_and_names_nothing_the_guest_said(self):
        with patch.dict(os.environ, FAKE_QEMU_PS_FAIL='1'):
            result = self.smoke()
        self.assertEqual(2, result['exit_code'])
        self.assertEqual([('evidence', 'qga-powershell-failed')], self.reasons(result))
        self.assertNotIn('System.Exception', json.dumps(result))
        self.assertEqual(1, len(result['execution']['boot_chain']))

    def test_two_readings_of_the_boot_that_disagree_are_an_error(self):
        with patch.dict(os.environ, FAKE_QEMU_COUNTER_LIE='1'):
            result = self.smoke()
        self.assertEqual([('evidence', 'guest-boot-readings-disagree')], self.reasons(result))
        self.assertEqual(2, result['exit_code'])


@controller_only
class SlowEvidenceTests(RebootSmokeTests):
    def setUp(self):
        super().setUp()
        patcher = patch.object(windows_reboot, 'EVIDENCE_SECONDS', 1)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_first_powershell_that_does_not_finish_is_asked_again_once_on_a_new_session_and_the_run_is_accepted(self):
        with patch.dict(os.environ, FAKE_QEMU_PS_HANGS='1'):
            result = self.smoke()
        self.assertEqual([], result['errors'])
        self.assertEqual(0, result['exit_code'], result['errors'])
        execution = result['execution']
        self.assertTrue(execution['accepted'])
        rows = self.evidence(result)
        self.assertEqual([('guest-evidence-timeout', 'before'), ('guest-evidence', 'before'),
                          ('guest-evidence', 'after')], [(row['operation'], row['when']) for row in rows])
        self.assertEqual((1, 1, 'qga-exec-timeout'), (rows[0]['attempt'], rows[0]['seconds'], rows[0]['reason']))
        # The repeat is one more recovery, within the plan's 4 + 1: the reset's own and this one.
        self.assertEqual(2, execution['qga_recoveries'])
        self.assertLessEqual(execution['qga_recoveries'], 5)

    def test_two_tries_in_a_row_that_do_not_finish_are_an_honest_refusal(self):
        with patch.dict(os.environ, FAKE_QEMU_PS_HANGS='2'):
            result = self.smoke()
        self.assertEqual(2, result['exit_code'])
        self.assertEqual([('evidence', 'qga-exec-timeout')], self.reasons(result))
        self.assertEqual(['guest-evidence-timeout'], [row['operation'] for row in self.evidence(result)])
        self.assertFalse(result['execution']['accepted'])
        self.assertTrue(result['completion'])

    def test_a_powershell_that_fails_is_not_asked_again(self):
        with patch.dict(os.environ, FAKE_QEMU_PS_FAIL='1'):
            result = self.smoke()
        self.assertEqual([('evidence', 'qga-powershell-failed')], self.reasons(result))
        self.assertEqual([], self.evidence(result))


@controller_only
class ReadingTests(RebootSmokeTests):
    def test_a_guest_whose_secure_boot_is_off_is_recorded_and_the_run_is_not_accepted(self):
        with patch.dict(os.environ, FAKE_QEMU_SECURE_BOOT='0'):
            result = self.smoke()
        self.assertEqual([], result['errors'])
        self.assertEqual(1, result['exit_code'])
        self.assertFalse(result['execution']['accepted'])
        self.assertIs(False, result['execution']['guest']['secure_boot'])
        self.assertIs(False, self.evidence(result)[0]['guest']['secure_boot'])
        self.assertEqual(2, len(result['execution']['boot_chain']))

    def test_an_answer_that_did_not_cross_as_utf8_is_not_accepted(self):
        with patch.dict(os.environ, FAKE_QEMU_LATIN1='1'):
            result = self.smoke()
        self.assertEqual(1, result['exit_code'])
        self.assertIs(False, result['execution']['guest']['utf8_ok'])
        self.assertFalse(result['execution']['accepted'])


@controller_only
class AttachRebootTests(unittest.TestCase):
    """A controller killed at a step of the run; another one takes over (`attach`) or closes it."""

    environment = {}

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='windows 9c ')
        self.addCleanup(temp.cleanup)
        self.state = Path(temp.name) / 'state'
        for item in [*fake_controller.patches(), patch.object(orchestrator, '_current_commit', return_value=None),
                     patch.object(windows_reboot, 'TRY_SECONDS', 2), patch.object(qga, 'EXEC_POLL_SECONDS', (0.01,)),
                     patch.dict(os.environ, dict(FAKE_QEMU_RESTART_DELAY='3', FAKE_QEMU_BOOT_SECONDS='0.5'))]:
            item.start()
            self.addCleanup(item.stop)
        self.addCleanup(self.stop_leftovers)

    def stop_leftovers(self):
        for directory in (self.state / 'runs').glob('*'):
            try:
                for resource in read_manifest(directory)['resources']:
                    if resource['kind'] == 'process' and _process_status(resource) == 'alive':
                        os.kill(resource['pid'], signal.SIGKILL)
            except (OSError, ValueError):
                pass

    def killed(self, phase):
        process = fake_controller.REAL_POPEN(
            [sys.executable, '-B', '-m', 'tools.vm.matrix.tests.fake_controller', str(self.state), phase, 'windows',
             'reboot'], cwd=REPOSITORY, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True)
        self.addCleanup(lambda: process.poll() is None and process.kill())
        self.addCleanup(process.wait)
        self.addCleanup(process.stdout.close)
        if not select.select([process.stdout], [], [], 90)[0]:
            self.fail('the controller did not reach ' + phase)
        word, run_id = process.stdout.readline().decode().split()
        self.assertEqual('READY', word)
        os.kill(process.pid, signal.SIGKILL)
        process.wait()
        return run_id

    def attach(self, run_id):
        return orchestrator.attach_run(self.state, run_id, sleep=fast_sleep, progress=lambda stage: None)

    def directory(self, run_id):
        return self.state / 'runs' / run_id

    def journal(self, run_id):
        raw = (self.directory(run_id) / 'lifecycle.jsonl').read_text().splitlines()
        return [(row['action'], row['result']) for row in map(json.loads, raw)]

    def test_a_controller_killed_after_the_request_and_before_the_reset_is_replaced_and_the_run_ends_whole(self):
        run_id = self.killed('reset')
        result = self.attach(run_id)
        self.assertEqual([], result['errors'])
        self.assertEqual((True, 1, 0), (result['attached'], result['attachments'], result['exit_code']))
        execution = result['execution']
        self.assertTrue(execution['accepted'], execution)
        self.assertEqual(2, len(execution['boot_chain']))
        self.assertEqual(1, execution['guest_resets'])
        # The attach took one recovery and the reset the other: neither the dead controller's count nor the limit.
        self.assertEqual(2, execution['qga_recoveries'])
        self.assertLessEqual(execution['qga_recoveries'], 4 + 1)
        document = json.loads((self.directory(run_id) / 'run-state.json').read_text())
        self.assertEqual(2, document['budgets']['qga_recoveries'])
        self.assertEqual('completed', document['phase'])
        self.assertEqual(['before', 'after'], [
            json.loads(line)['when'] for line in (self.directory(run_id) / 'job-evidence.jsonl').read_text().splitlines()
            if json.loads(line)['operation'] == 'guest-evidence'])

    def test_a_controller_killed_after_it_read_the_reset_is_replaced_and_takes_the_boot(self):
        run_id = self.killed('new-boot')
        document = json.loads((self.directory(run_id) / 'run-state.json').read_text())
        self.assertIn(('guest-reset-1', 'intent'), [(row['step'], row['status']) for row in document['transitions']])
        result = self.attach(run_id)
        self.assertEqual([], result['errors'])
        self.assertEqual(0, result['exit_code'])
        self.assertEqual(2, len(result['execution']['boot_chain']))
        self.assertEqual(1, result['execution']['guest_resets'])
        self.assertEqual(1, result['execution']['qga_recoveries'])
        self.assertEqual(1, len([row for row in self.journal(run_id) if row[0] == 'boot-chain-extended']))

    def test_a_controller_killed_after_the_new_boot_was_taken_is_replaced_and_finishes_the_run(self):
        run_id = self.killed('evidence-after')
        result = self.attach(run_id)
        self.assertEqual([], result['errors'])
        self.assertEqual(0, result['exit_code'])
        self.assertEqual(2, len(result['execution']['boot_chain']))
        self.assertTrue(result['completion'])

    def test_a_reset_that_came_while_nobody_was_connected_is_an_honest_end_and_not_a_chain_with_a_hole(self):
        with patch.dict(os.environ, FAKE_QEMU_RESTART_DELAY='0.2', FAKE_QEMU_BOOT_SECONDS='0.2'):
            run_id = self.killed('reset')
            # The guest restarts with no monitor connected: its RESET goes nowhere, and the agent answers on a new boot.
            time.sleep(2)
            result = self.attach(run_id)
        self.assertEqual(2, result['exit_code'])
        self.assertEqual([('attach-guest', 'boot-id-changed-without-reset')],
                         [(error['stage'], error['reason']) for error in result['errors']])
        self.assertEqual(1, len(result['execution']['boot_chain']))
        self.assertTrue(result['completion'])
        self.assertFalse(result['execution']['accepted'])

    def test_a_controller_killed_before_the_request_is_not_replaced_but_closed(self):
        run_id = self.killed('evidence')
        result = self.attach(run_id)
        self.assertEqual('attach-phase-not-resumable', result['refused'])
        answer, code = orchestrator.close_run(self.state, run_id)
        self.assertEqual((0, True), (code, answer['completion_verified']))
        self.assertEqual(['absent', 'absent'], [_process_status(r) for r in read_manifest(self.directory(run_id))['resources']
                                                if r['kind'] == 'process'])


class CommandTests(base.Base):
    def toml(self, config):
        return base.CommandTests.toml(self, config)

    def config(self):
        fixture = self.fixture
        config = dict(schema=windows_smoke.SCHEMA, suite='windows-reboot-smoke', mode='exploratory',
                      platform='linux-x86_64-kvm', state_directory=str(fixture.root / 'cli-state'),
                      stand_id='smoke', image_descriptor=str(fixture.descriptor_file), qemu=asdict(fixture.config),
                      smoke=dict(agent_wait_seconds=300, reset_wait_seconds=180, reboot_wait_seconds=300,
                                 shutdown_wait_seconds=240), deadlines=dict(preparation=900))
        path = fixture.root / 'reboot-smoke.toml'
        path.write_text(self.toml(config), encoding='utf-8')
        return config, path

    def command(self, *arguments):
        return base.CommandTests.command(self, *arguments)

    def test_the_dry_run_says_that_the_guest_restarts_once_and_creates_nothing(self):
        config, path = self.config()
        code, plan = self.command('run', 'windows-reboot-smoke', '--config', str(path), '--dry-run')
        self.assertEqual(0, code)
        self.assertEqual('windows-reboot-smoke', plan['suite'])
        self.assertTrue(plan['dry_run'])
        self.assertFalse(plan['image']['qualified'])
        self.assertFalse(plan['release_gate'])
        self.assertTrue(any('restart itself' in action for action in plan['actions']))
        self.assertFalse(Path(config['state_directory']).exists())

    def test_the_suite_on_the_command_line_must_match_the_configuration(self):
        _, path = self.config()
        code, answer = self.command('run', 'windows-boot-smoke', '--config', str(path), '--dry-run')
        self.assertEqual(2, code)
        code, answer = self.command('run', 'windows-reboot-smoke', '--config', str(self.config_of_boot_smoke()),
                                    '--dry-run')
        self.assertEqual(2, code)

    def config_of_boot_smoke(self):
        config, _ = base.CommandTests.config(self)
        path = self.fixture.root / 'boot-smoke.toml'
        path.write_text(self.toml(config), encoding='utf-8')
        return path

    def test_the_options_of_the_lab_are_refused(self):
        _, path = self.config()
        for option in (['--lab'], ['--diagnostic'], ['--control', 'stop-helper']):
            with self.subTest(option=option):
                code, answer = self.command('run', 'windows-reboot-smoke', '--config', str(path), *option)
                self.assertEqual(2, code)

    def test_a_configuration_with_other_fields_or_times_is_refused(self):
        config, _ = self.config()
        for change in (lambda c: c['smoke'].update(boot_wait_seconds=90), lambda c: c['smoke'].pop('reset_wait_seconds'),
                       lambda c: c['smoke'].update(agent_wait_seconds=301), lambda c: c['smoke'].update(agent_wait_seconds=0),
                       lambda c: c['smoke'].update(reboot_wait_seconds=901),
                       lambda c: c['smoke'].update(reset_wait_seconds=601),
                       lambda c: c['smoke'].update(shutdown_wait_seconds=601),
                       lambda c: c['smoke'].update(reboot_wait_seconds='300'), lambda c: c.update(mode='release'),
                       lambda c: c.update(suite='linux-reboot-smoke')):
            changed = deepcopy(config)
            change(changed)
            with self.subTest(), self.assertRaises(ValueError):
                windows_smoke.preflight(changed, dry_run=True)

    @linux_stand_paths
    def test_the_example_configuration_validates(self):
        with EXAMPLE.open('rb') as stream:
            import tomllib
            config = windows_smoke.validate(tomllib.load(stream))
        self.assertEqual('windows-reboot-smoke', config['suite'])
        self.assertEqual(1, matrix_config.planned_reboots_of('windows-reboot-smoke'))
        self.assertEqual(windows_reboot.PLANNED_REBOOTS, matrix_config.planned_reboots_of('windows-reboot-smoke'))


class LimitsTests(unittest.TestCase):
    def test_one_try_of_the_evidence_gets_five_minutes_and_its_polls_fit_in_the_calls_of_a_session(self):
        self.assertEqual(300, windows_reboot.EVIDENCE_SECONDS)
        # The first looks are soon and the later ones every 5 seconds: 300 seconds take about 60 of the 128 calls.
        polls = len(qga.EXEC_POLL_SECONDS) - 1 + (300 - sum(qga.EXEC_POLL_SECONDS[:-1])) / qga.EXEC_POLL_SECONDS[-1]
        self.assertLess(polls + 10, 128)

    def test_the_limits_leave_room_for_the_observations_of_the_run(self):
        # The first boot may take 7 tries (30 seconds and a pause of 15), the new boot 12; the run has 32.
        first = 300 // (windows_reboot.TRY_SECONDS + windows_reboot.INITIAL_PAUSE_SECONDS) + 1
        again = windows_reboot.REBOOT_ATTEMPTS
        self.assertLessEqual(first + again + 2, 32)
        self.assertEqual(1, windows_reboot.PLANNED_REBOOTS)

    def test_the_time_for_the_agent_is_several_times_the_slowest_start_seen(self):
        # 28 to 78 seconds in stages 9a and 9b.
        self.assertGreaterEqual(300, 3 * 78)


if __name__ == '__main__':
    unittest.main()
