"""Planned guest resets: the controller takes them from QMP, keeps a chain of boots and waits by polling.

The VM is the lifecycle fixture with a scripted QMP (`Control.resets` holds what the monitor reported) and a scripted
agent per session; no guest, no QEMU process. The named-socket cases are in `test_attach`.
"""

from dataclasses import asdict
import hashlib
import io
import json
from pathlib import Path
import tempfile
import tomllib
import unittest
from unittest.mock import patch

from tools.vm.matrix import cli, execution, lifecycle, linux_l2 as l2, l2_media as media, orchestrator, run_state
from tools.vm.matrix.jobs import JobError
from tools.vm.matrix.qmp_adapter import ResetEvent
from tools.vm.matrix.qga import QgaError
from tools.vm.matrix.tests import test_jobs, test_orchestrator, test_qemu
from tools.vm.matrix.tests.test_l2_media import helper
from tools.vm.matrix.tests.test_jobs import GUEST
from tools.vm.matrix.tests.test_linux_l2 import CHECKOUT, SOURCE
from tools.vm.matrix.tests.test_matrix import summarize, synthetic_inputs
from tools.vm.matrix.tests.test_qga import BOOT, read
from tools.vm.matrix.tests.test_stage_profiles import lines_of, register_evidence

NEW = '22345678-1234-4234-8234-123456789abc'
THIRD = '32345678-1234-4234-8234-123456789abc'
SMOKE = l2.PROFILES['reboot-smoke']


def package_smoke(root, vm_uuid, stand):
    """The package of the reboot smoke: the real guest scripts and a provenance record, no program."""
    for name in SMOKE.sources:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((CHECKOUT / 'tools/vm/linux' / name).read_bytes().replace(b'\r\n', b'\n').rstrip(b'\n') + b'\n')
    (root / 'artifacts').mkdir()
    provenance = dict(schema=1, stage='reboot-smoke', target='x86_64-unknown-linux-gnu', **SOURCE, artifacts={})
    (root / 'artifacts/provenance.json').write_text(json.dumps(provenance), encoding='ascii')
    env = dict(RUN_ID=GUEST, STAND_ID=stand, EXPECTED_BOOT_ID=BOOT, USER_A='l2a', USER_B='l2b', BIOS_GUID=vm_uuid,
               SCENARIO_TIMEOUT_SECONDS='30', UNIT_TIMEOUT_SECONDS='180', JOB_TIMEOUT_SECONDS='300')
    (root / 'job.env').write_bytes(''.join(f'{k}={v}\n' for k, v in env.items()).encode())
    (root / 'manifest.sha256').write_bytes(''.join(
        hashlib.sha256((root / n).read_bytes()).hexdigest() + '  ' + n + '\n' for n in SMOKE.payload).encode())


class Clock:
    now = 0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class RebootCase(unittest.TestCase):
    """A VM that plans `planned` guest resets, its job of the reboot smoke profile and an agent that answers."""

    planned = 1

    def setUp(self):
        self.fixture = test_jobs.JobsTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.vm, self.agent = self.fixture.vm, self.fixture.agent
        del self.vm._smoke_job
        self.vm.planned_reboots = self.planned
        self.control = self.vm.qmp
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        package_smoke(self.root, self.vm.vm_uuid, self.vm.run._identity[1])
        register_evidence(self.vm.run, 'reboot-smoke')
        with patch.object(l2, 'source_identity', return_value=SOURCE):
            self.job = l2.LinuxL2Job(self.vm, enabled=True, package_directory=self.root, checkout=CHECKOUT,
                                     profile='reboot-smoke')
        self.files = {}
        self.clock = Clock()
        self.serve(self.agent, BOOT)

    def serve(self, agent, boot):
        """The guest behind `agent`: the boot ID it reports and the files of the job's report directory."""
        current = {}

        def opened():
            path = agent.client.commands[-1][1]['path']
            if path == '/proc/sys/kernel/random/boot_id':
                current['data'] = (boot + '\n').encode()
            else:
                name = path.rsplit('/', 1)[1]
                if name not in self.files:
                    raise QgaError('qga-rpc-rejected')
                current['data'] = self.files[name]
            return 7
        agent.client.responses.update({'guest-file-open': opened, 'guest-file-read': lambda: read(current['data'])})

    def publish(self, state='finished', boot=BOOT, boots=None, at_end=None):
        """What the guest's job wrote: its status, and a report whose chain of boots is `boots`."""
        _, report, status = synthetic_inputs('linux-reboot-smoke')
        boots = [BOOT] if boots is None else boots
        report['run_id'] = GUEST
        report['guest'] = dict(boot_id=BOOT, boot_id_at_end=at_end or boots[-1], boot_ids=boots)
        summarize(report)
        status.update(run_id=GUEST, state=state, boot_id=boot)
        self.files.update({'report.json': json.dumps(report).encode(), 'status.json': json.dumps(status).encode()})

    def reset(self, boot=NEW, *, host=False):
        """A RESET read from QMP, then the guest's new agent answering with `boot`."""
        self.control.resets.append(not host)
        self.vm.watch_resets()
        return self.reboot(boot)

    def reboot(self, boot):
        agent = self.fixture.agent_new()
        self.serve(agent, boot)
        with patch.object(lifecycle, 'Qga', return_value=agent):
            return self.vm.await_rebooted_guest(timeout=60, clock=self.clock, sleep=self.clock.sleep)

    def rows(self):
        raw = (self.vm.run.directory / 'lifecycle.jsonl').read_text()
        return [(row['action'], row['result']) for row in map(json.loads, raw.splitlines())]


class ChainTests(RebootCase):
    def test_a_planned_guest_reset_and_a_new_boot_id_make_a_chain_of_two_and_the_job_collects(self):
        self.job.submit()
        self.publish('running')
        self.assertEqual([BOOT], self.vm.boot_chain)
        row = self.reset()
        self.assertEqual(([BOOT, NEW], NEW, False), (self.vm.boot_chain, self.vm.last_boot_id, self.vm.reset_pending))
        self.assertEqual(('changed', True, 'guest-reset'), (row['boot_comparison'], row['new_boot_confirmed'],
                                                            row['reason']))
        self.publish(boot=NEW, boots=[BOOT, NEW])
        result = self.job.collect()
        self.assertTrue(result['assessment']['acceptance']['accepted'], result['assessment']['validation'])
        self.assertEqual([BOOT, NEW], result['boot_chain'])
        self.assertEqual(BOOT, result['identity']['boot_id'])

    def test_the_reset_costs_two_rows_of_the_journal_one_recovery_and_one_new_agent_session(self):
        self.job.submit()
        before = self.vm.events
        recoveries = self.vm.qga_recoveries
        self.reset()
        self.assertEqual([('guest-reset-observed', '1-of-1'), ('boot-chain-extended', '2')], self.rows()[-2:])
        self.assertEqual((lifecycle.RESET_ROWS, 1), (self.vm.events - before, self.vm.qga_recoveries - recoveries))

    def test_an_unplanned_second_reset_is_an_error_and_no_later_boot_is_taken(self):
        self.reset()
        self.control.resets.append(True)
        with self.assertRaisesRegex(lifecycle.LifecycleError, 'unplanned-guest-reset'):
            self.vm.watch_resets()
        self.assertEqual(('guest-reset-observed', 'unplanned-guest-reset'), self.rows()[-1])
        self.assertTrue(self.vm.reset_pending)
        # The refusal is sticky: neither an observation nor a recovery takes the third boot.
        with self.assertRaisesRegex(lifecycle.LifecycleError, 'unplanned-guest-reset'):
            self.vm.observe_guest()
        self.assertEqual([BOOT, NEW], self.vm.boot_chain)

    def test_a_run_that_plans_no_reboot_refuses_the_first_reset(self):
        self.vm.planned_reboots = 0
        self.control.resets.append(True)
        with self.assertRaisesRegex(lifecycle.LifecycleError, 'unplanned-guest-reset'):
            self.vm.watch_resets()
        self.assertEqual(([BOOT], 0), (self.vm.boot_chain, self.vm.guest_resets))

    def test_a_reset_that_is_not_the_guests_outside_reset_is_an_error(self):
        self.control.resets.append(False)
        with self.assertRaisesRegex(lifecycle.LifecycleError, 'host-reset-outside-reset'):
            self.vm.watch_resets()
        self.assertEqual(('guest-reset-observed', 'host-reset-outside-reset'), self.rows()[-1])

    def test_a_monitor_that_cannot_be_read_stops_a_run_that_plans_a_reset_and_no_other(self):
        self.control.pump = lambda seconds: (_ for _ in ()).throw(ValueError('qmp-unavailable'))
        with self.assertRaisesRegex(lifecycle.LifecycleError, 'qmp-events-unavailable'):
            self.vm.watch_resets()
        self.vm.planned_reboots = 0
        self.vm.watch_resets()

    def test_the_controllers_own_reset_is_expected_inside_reset_only(self):
        self.vm.reset()
        self.assertFalse(self.vm.unplanned_reset)
        self.assertEqual((0, 'controller'), (self.vm.guest_resets, self.vm.reset_kind))

    def test_a_new_boot_id_without_a_reset_is_refused_and_the_chain_stays(self):
        self.job.submit()
        agent = self.fixture.agent_new()
        self.serve(agent, NEW)
        with patch.object(lifecycle, 'Qga', return_value=agent):
            with self.assertRaisesRegex(lifecycle.LifecycleError, 'boot-id-changed-without-reset'):
                self.vm.recover_guest()
        self.assertEqual(([BOOT], BOOT), (self.vm.boot_chain, self.vm.last_boot_id))
        last = json.loads((self.vm.run.directory / 'qga-observations.jsonl').read_text().splitlines()[-1])
        self.assertEqual(('boot-id-changed-without-reset', 'changed', False),
                         (last['result'], last['boot_comparison'], last['new_boot_confirmed']))
        self.assertIn('boot-id-changed-without-reset', self.vm.operation_errors)

    def test_a_reset_with_the_same_boot_id_is_refused_and_the_job_does_not_go_on(self):
        self.job.submit()
        with self.assertRaisesRegex(lifecycle.LifecycleError, 'guest-reset-boot-id-unchanged'):
            self.reset(BOOT)
        self.assertEqual(([BOOT], True), (self.vm.boot_chain, self.vm.reset_pending))
        self.publish()
        with self.assertRaises(JobError):
            self.job.collect()

    def test_a_repeated_boot_id_is_refused(self):
        self.vm.planned_reboots = 2
        self.reset(NEW)
        with self.assertRaisesRegex(lifecycle.LifecycleError, 'boot-id-repeated'):
            self.reset(BOOT)
        self.assertEqual([BOOT, NEW], self.vm.boot_chain)

    def test_the_guests_report_with_another_chain_than_the_controllers_is_refused(self):
        self.job.submit()
        self.reset()
        for boots in ([BOOT, THIRD], [BOOT], [NEW, BOOT], [BOOT, NEW, THIRD]):
            with self.subTest(boots=boots):
                self.publish(boot=NEW, boots=boots, at_end=NEW)
                self.job.polls = self.job.calls = self.vm.qga.calls = 0
                with self.assertRaisesRegex(JobError, 'UNVERIFIED'):
                    self.job.collect()
                self.assertIsNone(self.job.assessment)
        evidence = [json.loads(line) for line in
                    (self.vm.run.directory / 'job-evidence.jsonl').read_text().splitlines()]
        refusals = [row for row in evidence if row['operation'] == 'l2-boot-chain-mismatch']
        self.assertEqual(4, len(refusals))
        self.assertEqual(([BOOT, NEW], [BOOT, THIRD]), (refusals[0]['controller'], refusals[0]['guest']))

    def test_a_job_cannot_be_submitted_after_a_reset(self):
        self.reset()
        with self.assertRaisesRegex(JobError, 'boot-chain-before-submit'):
            self.job.submit()

    def test_the_status_of_the_old_boot_is_no_final_status_of_the_new_one(self):
        self.job.submit()
        self.reset()
        self.publish(boot=BOOT, boots=[BOOT, NEW], at_end=NEW)
        with self.assertRaises(JobError):
            self.job.collect()


class BudgetTests(RebootCase):
    planned = 2

    def test_two_planned_resets_fit_in_the_ordinary_rows_with_a_whole_run_and_its_teardown(self):
        self.vm.resume()
        self.job.submit()
        self.rows_before = self.vm.events
        for boot in (NEW, THIRD):
            self.reset(boot)
        self.assertEqual([BOOT, NEW, THIRD], self.vm.boot_chain)
        self.assertLessEqual(self.vm.events, lifecycle.ORDINARY_ROWS)
        self.assertLessEqual(self.vm.events + lifecycle.TEARDOWN_ROWS, lifecycle.JOURNAL_LIMIT)
        # Start and resume take the rows below; each of the two resets takes RESET_ROWS of what is left.
        self.assertEqual(self.rows_before + 2 * lifecycle.RESET_ROWS, self.vm.events)

    def test_each_reset_earns_one_recovery_and_no_more(self):
        self.assertEqual(4 + 2, self.vm.qga_recovery_limit)
        self.vm.planned_reboots = 0
        self.assertEqual(4, self.vm.qga_recovery_limit)
        with self.assertRaises(ValueError):
            self.vm.planned_reboots = run_state.MAX_PLANNED_REBOOTS + 1

    def test_a_reset_refused_for_lack_of_rows_leaves_no_trace(self):
        self.vm.events = lifecycle.ORDINARY_ROWS - 1
        self.control.resets.append(True)
        with self.assertRaisesRegex(lifecycle.LifecycleError, 'journal-limit'):
            self.vm.watch_resets()
        self.assertEqual((0, False), (self.vm.guest_resets, self.vm.reset_pending))


T0 = 1_700_000_000_000_000


def at(milliseconds, *, reason='guest-reset', guest=True, micro=0):
    """A RESET that QEMU stamped `milliseconds` after the first of the tests (QEMU's own clock, microseconds)."""
    return ResetEvent(guest, reason, T0 + milliseconds * 1000 + micro)


class CoalescedResetTests(RebootCase):
    """Linux resets a machine by several ways in a row and QEMU reports each: those are one reboot."""

    def seen(self, *events):
        self.control.resets.extend(events)
        self.vm.watch_resets()

    def collects(self):
        self.publish(boot=NEW, boots=[BOOT, NEW])
        result = self.job.collect()
        self.assertTrue(result['assessment']['acceptance']['accepted'], result['assessment']['validation'])
        return result

    def test_two_guest_resets_67_ms_apart_are_one_reboot_that_the_job_goes_through(self):
        self.job.submit()
        self.publish('running')
        before, recoveries = self.vm.events, self.vm.qga_recoveries
        self.seen(at(0), at(67))
        self.assertEqual((1, 1, True), (self.vm.guest_resets, self.vm.reset_merged, self.vm.reset_pending))
        self.assertEqual([('guest-reset-observed', '1-of-1 reason=guest-reset qemu=1700000000.000000'),
                          ('guest-reset-coalesced', '1-of-1 merged=1 +67ms reason=guest-reset qemu=1700000000.067000')],
                         self.rows()[-2:])
        row = self.reboot(NEW)
        self.assertEqual(('changed', True), (row['boot_comparison'], row['new_boot_confirmed']))
        self.assertEqual(([BOOT, NEW], NEW, False), (self.vm.boot_chain, self.vm.last_boot_id, self.vm.reset_pending))
        # The merged reset cost a row and nothing of the plan: one recovery, the same as a reboot of one reset.
        self.assertEqual((lifecycle.RESET_ROWS + 1, 1), (self.vm.events - before, self.vm.qga_recoveries - recoveries))
        self.assertEqual('boot-chain-extended', self.rows()[-1][0])
        self.assertEqual([BOOT, NEW], self.collects()['boot_chain'])

    def test_three_resets_in_the_window_are_the_same_reboot(self):
        self.seen(at(0), at(67), at(130))
        self.assertEqual((1, 2), (self.vm.guest_resets, self.vm.reset_merged))
        self.assertEqual(['guest-reset-observed', 'guest-reset-coalesced', 'guest-reset-coalesced'],
                         [action for action, _ in self.rows()[-3:]])
        self.assertTrue(self.rows()[-1][1].startswith('1-of-1 merged=2 +130ms'))
        self.reboot(NEW)
        self.assertEqual([BOOT, NEW], self.vm.boot_chain)

    def test_a_reset_that_arrives_in_a_later_look_is_merged_by_its_own_time_not_by_when_it_was_read(self):
        self.seen(at(0))
        self.seen(at(300))
        self.assertEqual((1, 1), (self.vm.guest_resets, self.vm.reset_merged))

    def test_the_window_closes_after_one_second_of_qemus_time_to_the_microsecond(self):
        self.seen(at(0), at(1000))
        self.assertEqual(1, self.vm.reset_merged)
        with self.assertRaisesRegex(lifecycle.LifecycleError, 'unplanned-guest-reset'):
            self.seen(at(1000, micro=1))
        self.assertEqual('unplanned-guest-reset reason=guest-reset qemu=1700000001.000001', self.rows()[-1][1])

    def test_a_second_reset_after_the_window_before_the_boot_is_confirmed_counts_against_the_plan(self):
        self.seen(at(0))
        with self.assertRaisesRegex(lifecycle.LifecycleError, 'unplanned-guest-reset'):
            self.seen(at(2500))
        self.assertEqual(('guest-reset-observed', 'unplanned-guest-reset reason=guest-reset qemu=1700000002.500000'),
                         self.rows()[-1])
        self.assertEqual((1, 0), (self.vm.guest_resets, self.vm.reset_merged))

    def test_a_plan_of_two_takes_a_reset_after_the_window_as_the_second_reboot(self):
        self.vm.planned_reboots = 2
        self.seen(at(0), at(60), at(2500), at(2560))
        self.assertEqual((2, 1), (self.vm.guest_resets, self.vm.reset_merged))
        self.assertEqual(['guest-reset-observed', 'guest-reset-coalesced', 'guest-reset-observed',
                          'guest-reset-coalesced'], [action for action, _ in self.rows()[-4:]])

    def test_a_reset_within_the_window_of_a_boot_already_confirmed_is_a_new_reboot(self):
        self.seen(at(0))
        self.reboot(NEW)
        with self.assertRaisesRegex(lifecycle.LifecycleError, 'unplanned-guest-reset'):
            self.seen(at(67))
        self.assertEqual([BOOT, NEW], self.vm.boot_chain)

    def test_more_merged_resets_than_the_limit_end_the_run(self):
        self.seen(at(0), *[at(50 * n) for n in range(1, lifecycle.RESET_MERGE_LIMIT + 1)])
        self.assertEqual((1, lifecycle.RESET_MERGE_LIMIT), (self.vm.guest_resets, self.vm.reset_merged))
        with self.assertRaisesRegex(lifecycle.LifecycleError, 'guest-reset-merge-limit'):
            self.seen(at(300))
        self.assertTrue(self.rows()[-1][1].startswith('guest-reset-merge-limit reason=guest-reset'))
        # The refusal is sticky, as every other refusal of a reset.
        with self.assertRaisesRegex(lifecycle.LifecycleError, 'guest-reset-merge-limit'):
            self.vm.observe_guest()
        self.assertEqual([BOOT], self.vm.boot_chain)

    def test_events_with_a_reason_without_one_and_with_neither_are_told_as_they_came(self):
        self.vm.planned_reboots = 2
        self.seen(ResetEvent(True, None, T0), ResetEvent(True, 'guest-shutdown', T0 + 5000))
        self.assertEqual([('guest-reset-observed', '1-of-2 qemu=1700000000.000000'),
                          ('guest-reset-coalesced', '1-of-2 merged=1 +5ms reason=guest-shutdown qemu=1700000000.005000')],
                         self.rows()[-2:])

    def test_a_reset_with_no_time_is_never_merged_and_costs_the_plan_as_before(self):
        self.seen(at(0))
        for event in (ResetEvent(True), ResetEvent(True, 'guest-reset', None)):
            with self.assertRaisesRegex(lifecycle.LifecycleError, 'unplanned-guest-reset'):
                self.seen(event)
            self.vm.unplanned_reset = None
        self.assertEqual('unplanned-guest-reset reason=guest-reset', self.rows()[-1][1])

    def test_a_reset_of_the_host_inside_the_window_is_still_an_error(self):
        self.seen(at(0))
        with self.assertRaisesRegex(lifecycle.LifecycleError, 'host-reset-outside-reset'):
            self.seen(at(10, guest=False, reason='host-qmp-system-reset'))
        self.assertEqual(0, self.vm.reset_merged)

    def test_a_merge_that_would_take_the_rows_of_the_boot_is_refused_and_leaves_no_trace(self):
        self.seen(at(0))
        self.vm.events = lifecycle.ORDINARY_ROWS - 1
        with self.assertRaisesRegex(lifecycle.LifecycleError, 'journal-limit'):
            self.seen(at(67))
        self.assertEqual((0, lifecycle.ORDINARY_ROWS - 1), (self.vm.reset_merged, self.vm.events))

    def test_the_time_of_the_first_reset_and_the_merged_count_are_kept_in_the_run_state(self):
        from tools.vm.matrix.resources import StandLease, create_run
        stand = tempfile.TemporaryDirectory()
        self.addCleanup(stand.cleanup)
        lease = StandLease(stand.name, 'synthetic').acquire()
        self.addCleanup(lease.release)
        # The state of a run of its own: the run of the fixture takes no more resources.
        run = create_run(lease)
        run.register(dict(run_state.RESOURCE))
        state = run_state.RunState.create(run, phase='running', boot_id=BOOT)
        self.vm.state = state
        self.seen(at(0), at(67), at(90))
        collected = run_state.RunState.load(run).document['collected']
        self.assertEqual((T0, 2), (collected['guest_reset_1_us'], collected['guest_reset_1_merged']))
        self.reboot(NEW)
        steps = [(row['step'], row['status']) for row in state.document['transitions']]
        self.assertEqual([('guest-reset-1', 'intent'), ('guest-reset-1', 'done')], steps)
        self.assertEqual((None, 0), (self.vm.reset_first_us, self.vm.reset_merged))


class CoalescedBudgetTests(RebootCase):
    planned = 2

    def test_two_planned_reboots_of_the_most_merged_resets_fit_in_the_ordinary_rows_with_the_teardown(self):
        self.vm.resume()
        self.job.submit()
        before = self.vm.events
        for index, boot in enumerate((NEW, THIRD)):
            base = index * 60_000
            self.control.resets.extend(at(base + 50 * n) for n in range(lifecycle.RESET_MERGE_LIMIT + 1))
            self.vm.watch_resets()
            self.assertEqual(lifecycle.RESET_MERGE_LIMIT, self.vm.reset_merged)
            self.reboot(boot)
        self.assertEqual([BOOT, NEW, THIRD], self.vm.boot_chain)
        # Per reboot: observed, the merged ones, and the extension of the chain.
        rows_per_reboot = lifecycle.RESET_ROWS + lifecycle.RESET_MERGE_LIMIT
        self.assertEqual((6, before + 2 * rows_per_reboot), (rows_per_reboot, self.vm.events))
        self.assertLessEqual(self.vm.events, lifecycle.ORDINARY_ROWS)
        self.assertLessEqual(self.vm.events + lifecycle.TEARDOWN_ROWS, lifecycle.JOURNAL_LIMIT)
        self.assertEqual(2, self.vm.guest_resets)


class WaitTests(RebootCase):
    def waiting(self, seconds, *, hook=None):
        sleeps = []

        def sleep(value):
            sleeps.append(value)
            self.clock.sleep(value)
            if hook:
                hook(len(sleeps))
        return sleeps, self.job.wait(seconds, sleep=sleep, clock=self.clock)

    def test_a_final_status_on_the_second_look_ends_the_wait_with_no_collection_spent(self):
        self.job.submit()
        self.publish('running')
        calls = self.job.calls
        sleeps, finished = self.waiting(725, hook=lambda n: self.publish('finished') if n == 2 else None)
        self.assertTrue(finished)
        # One look every 46 seconds (a sixteenth of the wait), and each look is open, read and close.
        self.assertEqual(([46, 46], 6, 0), (sleeps, self.job.calls - calls, self.job.polls))

    def test_a_status_that_never_ends_is_waited_out_in_full_and_collection_goes_the_old_way(self):
        self.job.submit()
        self.publish('running')
        sleeps, finished = self.waiting(725)
        self.assertFalse(finished)
        self.assertEqual(725, sum(sleeps))
        # Sixteen looks after the submission, and room left for two collections of the largest report.
        self.assertEqual(6 + 16 * 3, self.job.calls)
        self.assertLessEqual(self.job.calls + 2 * 28, 112)
        self.assertEqual(0, self.job.polls)
        with self.assertRaises(JobError):
            self.job.collect()
        self.assertEqual(1, self.job.polls)

    def test_a_short_wait_looks_every_thirty_seconds(self):
        self.job.submit()
        self.publish('running')
        sleeps, finished = self.waiting(100)
        self.assertEqual(([30, 30, 30, 10], False), (sleeps, finished))

    def test_no_status_yet_is_no_failure_of_the_channel(self):
        self.job.submit()
        sleeps, finished = self.waiting(100, hook=lambda n: self.publish('finished') if n == 2 else None)
        self.assertEqual(([30, 30], True), (sleeps, finished))

    def test_the_looks_stop_when_the_job_calls_run_short_and_the_time_is_still_waited_out(self):
        self.job.submit()
        self.publish('running')
        self.job.calls = l2.POLL_CALLS_LIMIT
        before = len(self.agent.client.commands)
        sleeps, finished = self.waiting(100)
        self.assertEqual((False, 100), (finished, sum(sleeps)))
        self.assertEqual(before, len(self.agent.client.commands))

    def test_a_failed_look_without_a_reset_ends_the_looking_and_not_the_wait(self):
        self.job.submit()
        self.agent.client.responses['guest-file-open'] = TimeoutError()
        sleeps, finished = self.waiting(100)
        self.assertEqual((False, 100), (finished, sum(sleeps)))
        self.assertEqual(0, self.job.polls)
        self.assertEqual(0, self.vm.guest_resets)

    def test_a_planned_reset_during_the_wait_is_recovered_inside_it_and_the_job_is_collected_after(self):
        self.job.submit()
        self.publish('running')
        agent = self.fixture.agent_new()
        self.serve(agent, NEW)

        def hook(n):
            if n == 1:
                self.control.resets.append(True)
            if n == 2:
                self.publish('finished', boot=NEW, boots=[BOOT, NEW])
        with patch.object(lifecycle, 'Qga', return_value=agent):
            sleeps, finished = self.waiting(725, hook=hook)
        self.assertTrue(finished)
        self.assertEqual(([BOOT, NEW], 1, 0), (self.vm.boot_chain, self.vm.qga_recoveries, self.job.polls))
        result = self.job.collect()
        self.assertTrue(result['assessment']['acceptance']['accepted'], result['assessment']['validation'])

    def test_a_look_that_fails_because_the_guest_is_going_down_waits_for_the_reset_that_explains_it(self):
        self.job.submit()
        self.publish('running')
        agent = self.fixture.agent_new()
        self.serve(agent, NEW)
        self.agent.client.responses['guest-file-open'] = TimeoutError()
        sleeps = []

        def sleep(value):
            sleeps.append(value)
            self.clock.sleep(value)
            # The agent stops first; the machine's reset follows within the grace.
            if len(sleeps) == 3:
                self.control.resets.append(True)
                self.publish('finished', boot=NEW, boots=[BOOT, NEW])
        with patch.object(lifecycle, 'Qga', return_value=agent):
            finished = self.job.wait(725, sleep=sleep, clock=self.clock)
        self.assertTrue(finished)
        self.assertEqual(([BOOT, NEW], 1), (self.vm.boot_chain, self.vm.qga_recoveries))

    def test_an_unplanned_reset_during_the_wait_ends_it_with_an_error(self):
        self.vm.planned_reboots = 0
        self.job.submit()
        self.publish('running')
        with self.assertRaisesRegex(lifecycle.LifecycleError, 'unplanned-guest-reset'):
            self.waiting(725, hook=lambda n: self.control.resets.append(True))

    def test_no_reset_and_no_look_writes_nothing_to_the_journal(self):
        self.job.submit()
        self.publish('running')
        rows = self.rows()
        self.waiting(100)
        self.assertEqual(rows, self.rows())


class ProfileTests(unittest.TestCase):
    def test_the_smoke_suite_plans_one_reset_and_the_others_none_but_l4(self):
        from tools.vm.matrix import config
        self.assertEqual({'linux-l4': 2, 'linux-reboot-smoke': 1}, config.PLANNED_REBOOTS)
        for suite in ('linux-l2', 'linux-l3', 'linux-proxy', 'linux-l5'):
            self.assertEqual(0, config.planned_reboots_of(suite))
        plan = config.make_plan('linux-reboot-smoke', 'x', dict(mode='exploratory'))
        self.assertEqual((1, 3), (plan['planned_reboots'], len(plan['catalog'])))
        config.validate_plan(plan)
        with self.assertRaises(ValueError):
            config.validate_plan(dict(plan, planned_reboots=0))


class OrchestratorTests(unittest.TestCase):
    """The shared controller on fake adapters: how it waits, and what a refused reset does to the run."""

    def setUp(self):
        self.flow = test_orchestrator.FlowTests()
        self.addCleanup(self.flow.doCleanups)
        self.flow.setUp()

    def test_the_wait_is_asked_for_the_old_bound_and_a_job_that_ends_early_is_collected_at_once(self):
        asked = []

        def wait(seconds, **options):
            asked.append((seconds, sorted(options)))
            self.flow.clock.sleep(100)
            return True
        self.flow.job.wait = wait
        result = self.flow.execute()
        self.assertEqual(0, result['exit_code'])
        self.assertEqual([(900 + 125, ['clock', 'sleep'])], asked)
        times = dict(self.flow.events)
        # The old wait took all 1025 seconds; the job was done after 100.
        self.assertEqual(100, times['collect'] - times['submit'])
        self.assertEqual(0, self.flow.vm.planned_reboots)

    def test_a_wait_that_runs_out_leaves_collection_as_it_always_was(self):
        self.flow.job.wait = lambda seconds, **options: self.flow.clock.sleep(seconds) or False
        result = self.flow.execute()
        self.assertEqual(0, result['exit_code'])
        times = dict(self.flow.events)
        self.assertEqual(1025, times['collect'] - times['submit'])
        self.assertEqual((1, 1), (self.flow.submits, self.flow.collects))

    def test_an_unplanned_reset_in_the_wait_ends_the_run_with_an_error_and_exit_2_and_never_collects(self):
        def wait(seconds, **options):
            raise lifecycle.LifecycleError('unplanned-guest-reset')
        self.flow.job.wait = wait
        result = self.flow.execute()
        self.assertEqual(2, result['exit_code'])
        self.assertEqual(('wait', 'unplanned-guest-reset'), (result['errors'][0]['stage'], result['errors'][0]['reason']))
        names = [e[0] for e in self.flow.events]
        self.assertNotIn('collect', names)
        self.assertEqual('close', names[-1])
        self.assertEqual(0, self.flow.collects)

    def test_the_smoke_suite_plans_one_reset_and_takes_the_media_of_its_profile(self):
        self.flow.config['suite'] = 'linux-reboot-smoke'
        options = {}
        self.flow.adapters.attach = lambda *a, **k: options.update(k) or self.flow.call('media')
        result = orchestrator.run_linux_reboot_smoke(self.flow.config, adapters=self.flow.adapters,
                                                     clock=self.flow.clock, sleep=self.flow.clock.sleep,
                                                     progress=lambda stage: None)
        self.assertEqual(0, result['exit_code'])
        self.assertEqual(1, self.flow.vm.planned_reboots)
        self.assertEqual('reboot-smoke', options['profile'])
        with self.assertRaisesRegex(ValueError, 'another suite'):
            orchestrator.run_linux_reboot_smoke(dict(self.flow.config, suite='linux-l2'))
        with self.assertRaisesRegex(ValueError, 'another suite'):
            orchestrator.run_linux_l2(self.flow.config)


class SmokeProfileTests(unittest.TestCase):
    def test_the_profile_is_exactly_what_start_sh_requires_and_names_no_program(self):
        self.assertEqual(sorted(lines_of('tools/vm/linux/guest/start.sh', 'REBOOT_SMOKE_START_REQUIRED')),
                         sorted(SMOKE.payload))
        self.assertEqual(((), (), (), (), 'reboot-smoke', 'reboot-smoke', l2.ENV_L2),
                         (SMOKE.binaries, SMOKE.packages, SMOKE.packaged, SMOKE.requests, SMOKE.name, SMOKE.stage,
                          SMOKE.env))
        self.assertEqual(('artifacts/provenance.json',), SMOKE.artifacts)
        self.assertNotIn('reboot-smoke', l2.SERVICE_PROFILES)
        self.assertEqual(l2.evidence_files('l2'), l2.evidence_files('reboot-smoke'))

    def test_the_guest_importer_names_the_same_content_and_no_marker_service(self):
        entry = helper.PROFILES['reboot-smoke']
        self.assertEqual(media.content('reboot-smoke'), tuple(entry['content']))
        self.assertEqual(((), l2.ENV_L2), (tuple(entry['binaries']), tuple(entry['env'])))
        self.assertNotIn('reboot-smoke', helper.SERVICE)

    def test_the_build_makes_a_record_of_the_build_and_nothing_else(self):
        script = (CHECKOUT / 'tools/vm/linux/build-artifacts.sh').read_text(encoding='utf-8')
        self.assertIn('--reboot-smoke', script)
        self.assertIn('provenance >"$out/provenance.json"', script)

    def test_the_package_validates_and_its_catalog_is_the_smokes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            package_smoke(root, BOOT, 'synthetic')
            with patch.object(l2, 'source_identity', return_value=SOURCE):
                package = l2.validate_package(root, checkout=CHECKOUT, profile='reboot-smoke')
            self.assertEqual(('reboot-smoke', 3), (package['profile'], len(package['catalog'])))
            self.assertEqual(set(SMOKE.files), set(package['hashes']))
            self.assertEqual(list(l2.ENV_L2), list(package['env']))
            # A program in the package is no part of this profile.
            (root / 'artifacts/extra').write_bytes(b'x')
            with patch.object(l2, 'source_identity', return_value=SOURCE), self.assertRaises(JobError):
                l2.validate_package(root, checkout=CHECKOUT, profile='reboot-smoke')

    def test_the_catalog_names_one_planned_reset_and_requires_all_three_scenarios(self):
        rows = [line.split('\t') for line in
                (CHECKOUT / 'tools/vm/linux/scenarios-reboot-smoke.tsv').read_text().splitlines()[1:]]
        self.assertEqual(['preflight.identity', 'reboot.planned', 'reboot.continued'], [r[0] for r in rows])
        self.assertEqual({'yes'}, {r[1] for r in rows})

    def test_the_guest_script_keeps_the_pattern_of_the_reboot_it_is_modelled_on(self):
        script = (CHECKOUT / 'tools/vm/linux/guest/run-reboot-smoke.sh').read_text(encoding='utf-8')
        for text in ('RESUME_UNIT=rosetun-l2-resume.service', 'systemctl --no-block reboot', ': >"$STATE/rebooting"',
                     '[ -f "$STATE/rebooting" ] && return 0', '"boot_ids":%s', 'WantedBy=multi-user.target'):
            self.assertIn(text, script)
        self.assertNotIn('rosetun-helper', script)

    def test_the_example_configuration_validates_for_the_smoke_suite(self):
        with (Path(execution.__file__).parent / 'execution-reboot-smoke.example.toml').open('rb') as stream:
            config = execution.validate(tomllib.load(stream))
        self.assertEqual('linux-reboot-smoke', execution.suite_of(config))
        self.assertNotIn('l3', config)
        self.assertEqual(config['timeouts']['job'] + 180, config['deadlines']['execution'])


class SmokeDryRunTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_qemu.PreparationTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        package_smoke(self.root, BOOT, 'synthetic')
        for name in ('job.env', 'manifest.sha256'):
            (self.root / name).unlink()
        self.config = dict(schema=execution.SCHEMA_V2, suite='linux-reboot-smoke', mode='exploratory',
            platform='linux-x86_64-kvm', state_directory=str(self.root / 'absent-state'), stand_id='synthetic',
            image=self.fixture.image.record(), qemu=asdict(self.fixture.config),
            xorriso=self.fixture.config.executable, content_directory=str(self.root),
            source_checkout=str(CHECKOUT), accounts=dict(user_a='l2a', user_b='l2b'),
            timeouts=dict(scenario=30, unit=180, job=300),
            deadlines=dict(preparation=600, boot=300, **{'import': 900}, execution=480))
        self.config['qemu'].update(machine='pc-i440fx-10.0', qga=True)

    def dry_run(self, suite='linux-reboot-smoke'):
        with patch.object(execution, 'load_execution', return_value=self.config), \
                patch('subprocess.Popen', side_effect=AssertionError('external program forbidden')), \
                patch('sys.stdout', new_callable=io.StringIO) as output:
            code = cli.main(['run', suite, '--config', 'synthetic', '--dry-run'])
        return code, output.getvalue()

    def test_the_dry_run_checks_the_package_and_says_that_the_guest_reboots_once(self):
        code, text = self.dry_run()
        self.assertEqual(0, code)
        plan = json.loads(text)
        self.assertEqual(('linux-reboot-smoke', True), (plan['suite'], plan['dry_run']))
        self.assertTrue(any('reboots the guest once' in action for action in plan['actions']))
        self.assertTrue(any('planned guest reset' in action for action in plan['actions']))
        self.assertTrue(any('wait for the job by reading its status' in action for action in plan['actions']))
        self.assertEqual(['artifacts/provenance.json'], [n for n in plan['content_hashes'] if n.startswith('artifacts/')])
        self.assertFalse(Path(self.config['state_directory']).exists())

    def test_the_suite_on_the_command_line_must_match_the_configuration(self):
        self.assertEqual(2, self.dry_run('linux-l2')[0])

    def test_a_package_of_another_profile_is_refused(self):
        (self.root / 'artifacts/provenance.json').write_text(json.dumps(dict(
            schema=1, stage='l2', target='x86_64-unknown-linux-gnu', **SOURCE, artifacts={})), encoding='ascii')
        self.assertEqual(2, self.dry_run()[0])


if __name__ == '__main__':
    unittest.main()
