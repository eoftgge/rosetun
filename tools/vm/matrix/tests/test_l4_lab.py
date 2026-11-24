"""Linux L4 in the lab (stage 8d): the tables of the suite, the run with its three boots and its poller, the exit codes.

The numbers come from run-l4.sh alone: no L4 run has been through the lab yet.
"""

import json
from pathlib import Path
import unittest
from unittest.mock import patch

from tools.vm.matrix import cli, config as matrix_config, execution, l3_lab, l3_summary as summary, l4_tables as tables
from tools.vm.matrix import lab_protocol as wire
from tools.vm.matrix.tests.test_l3_lab import (Flow, HEX, Machines, direct_flow, example as l3_example, wire_frame)
from tools.vm.matrix.tests.test_l3_summary import LEAK
from tools.vm.matrix.tests.test_l4_script import SCRIPT
from tools.vm.matrix.tests.test_lab import ip_frame, tcp
from tools.vm.matrix.tests.test_proxy_script import callers
from tools.vm.matrix.tests.test_lab_flows import SYN, SYN_ACK, PUSH

CATALOG = Path(__file__).resolve().parents[2] / 'linux' / 'scenarios-l4.tsv'
PACKAGE = Path(__file__).resolve().parents[1]
CLIENT, GATEWAY = wire.CLIENTS[4], wire.GATEWAYS[4]
# What the guest says in `cleanup.actions` when its local network went on: 13 digits of epoch milliseconds. The fake
# capture stamps every frame with the second 0, so two seconds, less the slack of the tables, is the second 0.
LAN_ON = '0000000002000'
BOOTS = ['11111111-1111-4111-8111-111111111111', '22222222-2222-4222-8222-222222222222',
         '33333333-3333-4333-8333-333333333333']


def catalog():
    rows = [line.split('\t') for line in CATALOG.read_text(encoding='utf-8').splitlines()]
    return [row for row in rows[1:] if row and row[0]]


def passing_rows(**changes):
    rows = {row[0]: ('PASS', 'ok') for row in catalog()}
    for key, value in changes.items():
        rows[key.replace('__', '.').replace('_', '-')] = value
    return rows


def by_design():
    """The direct flows of a clean run in `lockdown`: four probes of a permitted scope, a connection and an exchange each."""
    frames = ()
    for number in range(4):
        frames += direct_flow('target', 44000 + number) + direct_flow('resolver', 45000 + number)
    return frames


def poll(port, answered=True):
    syn = ip_frame(GATEWAY, CLIENT, 6, tcp(port, 22, b'', SYN), src=wire.MACS['lab'], dst=wire.MACS['test'])
    reply = ip_frame(CLIENT, GATEWAY, 6, tcp(22, port, b'', SYN_ACK))
    return (syn, reply) if answered else (syn,)


def windows(extra=(), polled=True, answered=True):
    """The one window of a clean run: its flows by design, the poller's attempts, then what the test adds."""
    frames = by_design() + (poll(40001, answered) + poll(40002, answered) if polled else ()) + tuple(extra)
    return [('lockdown', frames)]


class TableTests(unittest.TestCase):
    def test_every_scenario_is_in_the_group_and_has_a_window_entry(self):
        ids = [row[0] for row in catalog()]
        self.assertEqual(27, len(ids))
        self.assertEqual(sorted(ids), sorted(tables.GROUP))
        self.assertEqual(sorted(ids), sorted(tables.WINDOW_OF))
        in_window = [i for i in ids if tables.WINDOW_OF[i] == ('lockdown', 0)]
        self.assertEqual(19, len(in_window))
        self.assertEqual(['preflight.identity', 'preflight.accounts', 'preflight.no-foreign-service', 'preflight.tools',
                          'preflight.baseline', 'install.service', 'lockdown.denied', 'reboot.without-record'],
                         [i for i in ids if tables.WINDOW_OF[i] is None])
        self.assertEqual(('lockdown',), tables.GROUP_LABELS)
        self.assertEqual({'lockdown': 1}, tables.WINDOWS_PER_LABEL)

    def test_the_window_opens_before_the_first_scenario_in_it_and_closes_with_the_last_one(self):
        order = [row[0] for row in catalog()]
        first, last = order.index('lockdown.direct-blocked'), order.index('exit.reset-firewall')
        self.assertEqual(['lockdown.direct-blocked', 'exit.reset-firewall'], [order[first], order[last]])
        for identifier in order[first:last + 1]:
            self.assertEqual(('lockdown', 0), tables.WINDOW_OF[identifier], identifier)
        for identifier in order[:first] + order[last + 1:]:
            self.assertIsNone(tables.WINDOW_OF[identifier], identifier)
        text = SCRIPT.read_text(encoding='utf-8')
        self.assertEqual(['lockdown'], callers(text, 'lab_mark open'))
        self.assertEqual(['reset'], callers(text, 'lab_mark close'))

    def test_the_expectation_is_four_connections_to_the_target_and_four_exchanges_with_the_resolver(self):
        self.assertEqual({('lockdown', 0): {summary.TARGET_FLOW: 4, summary.RESOLVER_FLOW: 4}}, tables.EXPECTED_FLOWS)
        self.assertEqual(('tcp', 'target', '203.0.113.2:443'), summary.TARGET_FLOW)
        self.assertEqual(('udp', 'resolver', '203.0.113.53:53'), summary.RESOLVER_FLOW)
        # Counted from the script: the same four probes tests/test_l4_script.py reads out of it.
        text = SCRIPT.read_text(encoding='utf-8')
        self.assertEqual(6, text.count('scope_probe rosetun-') - text.count('scope_probe rosetun-\n'))

    def test_the_boot_of_the_first_reboot_is_in_the_window_and_only_its_address_check_is_allowed(self):
        self.assertEqual({'lockdown': ('ipv6-dad',)}, tables.WINDOW_ALLOWANCES)
        names = {name for name, _, _ in wire.ALLOWANCES}
        self.assertLessEqual(set(tables.WINDOW_ALLOWANCES['lockdown']), names)

    def test_the_tables_name_the_rest_of_what_makes_a_suite(self):
        l4 = summary.tables_for('linux-l4')
        for name in summary.TABLES:
            self.assertIs(getattr(tables, name), getattr(l4, name), name)
        self.assertEqual(('stop-helper',), l4.CONTROLS)
        self.assertEqual(('lockdown', 'exit.denied-without-root'), (l4.CONTROL_WINDOW, l4.CONTROL_SCENARIO))
        self.assertEqual(('lockdown', 0), tables.WINDOW_OF[l4.CONTROL_SCENARIO])
        self.assertEqual((3, True, 2.0), (l4.BOOT_CHAIN, l4.INBOUND_POLL, l4.LAN_ON_SLACK_SECONDS))
        self.assertEqual(('node', 'https', 'doh'), l4.REQUIRED_FIXTURES)
        self.assertTrue(l4.LEAK_OUTSIDE_THE_GROUP_FAILS)
        self.assertEqual(matrix_config.planned_reboots_of('linux-l4') + 1, l4.BOOT_CHAIN)
        self.assertIn('linux-l4', summary.LAB_SUITES)

    def test_the_tables_of_the_other_suites_have_none_of_the_new_things(self):
        for suite in ('linux-l3', 'linux-proxy', 'linux-l5'):
            other = summary.tables_for(suite)
            self.assertEqual((None, None, None), (other.BOOT_CHAIN, other.INBOUND_POLL, other.LAN_ON_SLACK_SECONDS))

    def test_the_example_is_a_valid_lab_configuration_of_the_suite(self):
        import tomllib
        with (PACKAGE / 'execution-l4-lab.example.toml').open('rb') as stream:
            config = tomllib.load(stream)
        for name in ('state_directory', 'content_directory', 'source_checkout'):
            config[name] = l3_example()[name]
        config = execution.validate(config)
        self.assertEqual(('linux-l4', 600, 2460), (execution.suite_of(config), config['timeouts']['job'],
                                                   config['deadlines']['execution']))
        self.assertEqual(2580, l3_lab.capture_seconds(config))
        config['timeouts']['job'] = 641
        config['deadlines']['execution'] = matrix_config.job_span('linux-l4', 641) + 180
        with self.assertRaisesRegex(ValueError, 'at most 2400 seconds'):
            execution.validate(config)


class RunMachines(Machines):
    """The fake machines of an L4 run: three boots, the report of its script and the log of the poller."""

    def __init__(self, test, *, chain=BOOTS, polled=None, wait_error=None, lan_on=LAN_ON, **options):
        options.setdefault('windows', windows())
        options.setdefault('rows', passing_rows())
        super().__init__(test, **options)
        self.report_directory = 'linux-l4'
        self.chain, self.wait_error, self.lan_on = list(chain), wait_error, lan_on
        self.polled = [dict(attempt=1, at=1.0, result='failed', code=255, elapsed_ms=5003),
                       dict(attempt=2, at=11.0, result='accepted', code=0, elapsed_ms=801)] if polled is None else polled

    def adapters(self):
        namespace = super().adapters()
        machines, importer = self, namespace.importer

        def wrapped(vm, **kwargs):
            attempt = importer(vm, **kwargs)
            create = attempt.linux_l2_job

            def create_job(**options):
                job = create(**options)
                job.snapshot = lambda: dict(accepted=False, polls=job.polls, boot_chain=list(machines.chain))
                if machines.wait_error is not None:
                    def wait(seconds, *, sleep, clock):
                        machines.waited = seconds
                        raise machines.wait_error
                    job.wait = wait
                else:
                    job.wait = lambda seconds, *, sleep, clock: (setattr(machines, 'waited', seconds), sleep(seconds))
                return job
            attempt.linux_l2_job = create_job
            return attempt
        namespace.importer = wrapped
        return namespace

    def artifact(self, name):
        if name == 'poller.json':
            self.note('read-poller')
            return json.dumps(self.polled).encode()
        return super().artifact(name)

    def report(self):
        report = json.loads(super().report())
        report['cleanup']['actions'] = ('removed the peer namespace; ' + ('lan-on-ms=' + self.lan_on + '; '
                                                                           if self.lan_on else '') + 'removed the units')
        return json.dumps(report).encode()


class L4Flow(Flow):
    JOB = 600

    def setUp(self):
        super().setUp()
        self.config['suite'] = 'linux-l4'
        self.config['deadlines']['execution'] = matrix_config.job_span('linux-l4', 600) + 180

    def machines(self, **options):
        return RunMachines(self, **options)

    def go(self, machines, **options):
        self.runs = getattr(self, 'runs', 0) + 1
        self.config['state_directory'] = str(self.fixture.root / ('lab-state-' + str(self.runs)))
        with patch.object(l3_lab, 'run_linux_l3_lab', side_effect=l3_lab.run_linux_l4_lab):
            return super().go(machines, **options)

    def agreements(self, result):
        return {row['id']: row['agreement'] for row in result['crosscheck']}


class RunTests(L4Flow):
    def test_a_clean_run_has_one_window_as_expected_three_boots_and_exits_zero(self):
        result = self.go(self.machines())
        self.assertEqual((0, 'group-clean'), (result['exit_code'], result['outcome']))
        self.assertEqual(('rosetun.matrix.l4-summary.v1', 'linux-l4'), (result['schema'], result['suite']))
        self.assertEqual(27, len(result['crosscheck']))
        agreements = self.agreements(result)
        self.assertEqual({'NOT_APPLICABLE'}, {agreements[i] for i in tables.GROUP if tables.WINDOW_OF[i] is None})
        self.assertEqual({'AGREE'}, {agreements[i] for i in tables.GROUP if tables.WINDOW_OF[i] is not None})
        (window,) = result['lab']['windows']
        self.assertEqual(('lockdown', 'EXPECTED', 0), (window['label'], window['verdict'], window['number']))
        # The frames of the flows by design are `unexpected` frames the expectation accounts for: 4 * 3 + 4 * 4 of them.
        self.assertEqual((4, 28), (window['categories']['inbound-poll'], window['categories']['unexpected']))
        self.assertEqual([dict(protocol='tcp', kind='target', server='203.0.113.2:443', direction='out', count=4),
                          dict(protocol='udp', kind='resolver', server='203.0.113.53:53', direction='out', count=4)],
                         window['expected_flows'])
        self.assertEqual({True}, {row['as_expected'] for row in result['lab']['window_counts']})
        self.assertEqual(dict(expected=3, seen=3), result['group']['boot_chain'])
        self.assertEqual(([], []), (result['group']['findings'], result['group']['unproven']))
        self.assertEqual([], result['out_of_scope'])

    def test_the_run_waits_for_every_phase_and_the_reboots_and_the_capture_covers_them(self):
        machines = self.machines()
        self.go(machines)
        self.assertEqual(3 * 600 + 2 * 240 + 125, machines.waited)
        options = machines.calls[0][4]
        self.assertEqual(3 * 600 + 2 * 240 + 300, options['duration_seconds'])
        self.assertEqual(2, machines.vms['test'].planned_reboots)
        self.assertEqual(0, getattr(machines.vms['lab'], 'planned_reboots', 0))

    def test_the_run_asks_for_the_l4_requests_media_with_the_engine_and_the_marker_and_the_poller(self):
        machines = self.machines()
        self.go(machines)
        self.assertEqual(dict(profile='l4'), machines.request_options)
        self.assertEqual(('l4', HEX), (machines.attach_options['profile'], machines.attach_options['sing_box_sha256']))
        block = machines.imports[0]['l3']
        self.assertEqual(l3_lab.marker_address(), block['lab_marker_address'])
        self.assertRegex(block['lab_poller_key'], '^AAAAC3NzaC1lZDI1NTE5AAAAI[A-P][A-Za-z0-9+/]{42}$')
        self.assertTrue(machines.pair_options['poller'])
        self.assertIn('read-poller', machines.names())
        self.assertIn('lab-poller', {name for name in machines.pair.resources(machines.runs['lab'])})

    def test_the_poller_key_is_new_for_each_run_and_only_the_lab_machine_has_its_private_half(self):
        first, second = self.machines(), self.machines()
        results = [self.go(first), self.go(second)]
        keys = [m.calls[0][4]['poller']['private_key'] for m in (first, second)]
        publics = [m.imports[0]['l3']['lab_poller_key'] for m in (first, second)]
        self.assertNotEqual(keys[0], keys[1])
        self.assertNotEqual(publics[0], publics[1])
        for machines, result, private in zip((first, second), results, keys):
            # The same key reaches the lab machine in the request that sets it up and in the one that finishes it.
            self.assertEqual({private}, {call[4]['poller']['private_key'] for call in machines.calls})
            self.assertTrue(private.startswith('-----BEGIN OPENSSH PRIVATE KEY-----'))
            for text in (json.dumps(result), json.dumps(machines.imports), json.dumps(machines.attach_options, default=str),
                         json.dumps(machines.request_options)):
                self.assertNotIn(private, text)
                self.assertNotIn(json.dumps(private)[1:-1], text)
                self.assertNotIn(private.splitlines()[1], text)
        # Nothing else reaches the test machine's media or the summaries but the public blob.
        self.assertTrue(all('private' not in key for key in first.imports[0]['l3']))

    def test_the_summary_and_the_run_directories_never_hold_the_private_key(self):
        machines = self.machines()
        result = self.go(machines)
        private = machines.calls[0][4]['poller']['private_key']
        for run in machines.runs.values():
            for path in Path(run.directory).rglob('*'):
                if path.is_file() and path.stat().st_size < 4 * 1024 * 1024:
                    self.assertNotIn(private.splitlines()[1].encode(), path.read_bytes(), path.name)
        self.assertNotIn(private.splitlines()[1], json.dumps(result))

    def test_a_private_key_that_got_into_a_summary_is_removed_and_the_run_is_an_error(self):
        machines = self.machines()
        secret = 'sentinel-key-body'
        decide = summary.decide

        def leaking(result, interrupted):
            decide(result, interrupted)
            result['leaked'] = secret

        with patch.object(l3_lab.poller_key, 'new_pair', return_value=(secret, 'A' * 68)), \
                patch.object(summary, 'decide', leaking):
            result = self.go(machines)
        self.assertEqual(2, result['exit_code'])
        self.assertNotIn(secret, json.dumps(result))
        self.assertEqual('[redacted-key]', result['leaked'])
        self.assertIn('poller-key-redacted', [error.get('reason') for error in result['errors']])

    def test_the_log_of_the_poller_is_counted_in_the_summary_and_kept_as_a_file_of_the_lab_run(self):
        machines = self.machines()
        result = self.go(machines)
        self.assertEqual(dict(attempts=2, accepted=1, failed=1, timeouts=0, errors=0, first_accepted_at=11.0,
                              last_attempt_at=11.0), result['lab']['poller'])
        self.assertIn('poller.json', result['lab']['artifacts_sha256'])
        saved = machines.runs['lab'].directory / 'poller.json'
        self.assertEqual(machines.polled, json.loads(saved.read_bytes()))

    def test_a_log_that_cannot_be_read_counts_nothing(self):
        self.assertEqual(dict(attempts=0, accepted=0, failed=0, timeouts=0, errors=0, first_accepted_at=None,
                              last_attempt_at=None), l3_lab.poller_block(None))
        self.assertEqual(0, l3_lab.poller_block([1, 'x'])['attempts'])


class LeakTests(L4Flow):
    def test_one_flow_more_than_the_script_sends_is_a_leak_in_the_window_and_exits_one(self):
        extra = direct_flow('target', 46000)
        result = self.go(self.machines(windows=windows(extra=extra)))
        self.assertEqual((1, 'findings'), (result['exit_code'], result['outcome']))
        (window,) = result['lab']['windows']
        self.assertEqual('DETECTED', window['verdict'])
        self.assertIn('leak-in-group-window', result['group']['findings'])
        self.assertEqual({'DISAGREE'}, {self.agreements(result)[i] for i in tables.GROUP
                                        if tables.WINDOW_OF[i] and result['legacy']['scenarios']
                                        and i == 'lockdown.direct-blocked'})

    def test_a_flow_to_somewhere_else_and_an_unexpected_frame_are_leaks_too(self):
        for extra in (direct_flow('resolver', 46001), (LEAK,)):
            with self.subTest(extra=len(extra)):
                result = self.go(self.machines(windows=windows(extra=extra)))
                self.assertEqual(1, result['exit_code'])

    def test_a_probe_that_did_not_get_out_is_a_mismatch_which_contradicts_the_passes_of_the_window(self):
        frames = by_design()[:-len(direct_flow('resolver', 45003))]
        result = self.go(self.machines(windows=[('lockdown', frames + poll(40001))]))
        self.assertEqual(1, result['exit_code'])
        (window,) = result['lab']['windows']
        self.assertEqual('MISMATCH', window['verdict'])

    def test_a_scenario_of_the_group_that_failed_is_a_finding(self):
        rows = passing_rows(inbound__lan_open=('FAIL', 'sshd accepted no connection'))
        result = self.go(self.machines(rows=rows))
        self.assertEqual((1, ['inbound.lan-open']), (result['exit_code'], result['group']['failed']))

    def test_a_second_window_of_the_label_is_a_session_nobody_expected(self):
        result = self.go(self.machines(windows=windows() + [('lockdown', ())]))
        self.assertEqual(2, result['exit_code'])
        self.assertTrue(any(item.startswith('window-count:lockdown') for item in result['group']['unproven']))


class PollTests(L4Flow):
    def categories(self, result):
        (window,) = result['lab']['windows']
        return window['categories']

    def test_syns_nobody_answers_are_allowed_and_nothing_else_is_seen(self):
        result = self.go(self.machines(windows=windows(answered=False)))
        self.assertEqual((0, 2), (result['exit_code'], self.categories(result)['inbound-poll']))
        self.assertEqual(28, self.categories(result)['unexpected'])

    def test_an_answer_of_the_test_machine_before_the_local_network_went_on_is_a_leak(self):
        # The guest says the local network went on at second 100, and the answers are in the capture at second 0.
        result = self.go(self.machines(lan_on='0000000100000'))
        self.assertEqual((1, 'findings'), (result['exit_code'], result['outcome']))
        self.assertEqual((28 + 2, 2), (self.categories(result)['unexpected'], self.categories(result)['inbound-poll']))
        self.assertEqual('DETECTED', result['lab']['windows'][0]['verdict'])

    def test_a_guest_that_never_says_so_has_no_answer_admitted(self):
        result = self.go(self.machines(lan_on=''))
        self.assertEqual(1, result['exit_code'])
        self.assertEqual(28 + 2, self.categories(result)['unexpected'])

    def test_the_boundary_is_the_guests_note_less_the_slack_of_the_clocks(self):
        note = '{"cleanup": {"actions": "removed the units; lan-on-ms=1763000000000; done"}}'
        self.assertEqual(1762999998.0, l3_lab.lan_on_seconds(note.encode(), 2.0))
        for raw in (None, b'', b'[]', b'{}', b'{"cleanup": {"actions": 5}}',
                    b'{"cleanup": {"actions": "lan-on-ms=17630000"}}', b'{"cleanup": {"actions": "lan-on-ms=17630000000000"}}',
                    b'{"cleanup": {"actions": "xlan-on-ms=1763000000000"}}'):
            self.assertIsNone(l3_lab.lan_on_seconds(raw, 2.0), raw)


class BootTests(L4Flow):
    def test_fewer_boots_than_the_job_planned_cannot_vouch_for_the_run(self):
        result = self.go(self.machines(chain=BOOTS[:2]))
        self.assertEqual((2, 'unverified'), (result['exit_code'], result['outcome']))
        self.assertIn('boot-chain:expected=3,seen=2', result['group']['unproven'])
        self.assertEqual(dict(expected=3, seen=2), result['group']['boot_chain'])

    def test_no_chain_at_all_is_unverified_too(self):
        result = self.go(self.machines(chain=[]))
        self.assertEqual(2, result['exit_code'])
        self.assertIn('boot-chain:expected=3,seen=0', result['group']['unproven'])

    def test_an_unplanned_reset_is_an_error_of_the_controller_and_exits_two(self):
        from tools.vm.matrix.lifecycle import LifecycleError
        result = self.go(self.machines(wait_error=LifecycleError('unplanned-guest-reset')))
        self.assertEqual((2, 'unverified'), (result['exit_code'], result['outcome']))
        self.assertEqual('wait', result['errors'][0]['stage'])
        self.assertIn('controller-error', result['group']['unproven'])

    def test_a_boot_nobody_observed_is_an_error_of_the_wait_and_the_disk_of_the_lab_is_read_all_the_same(self):
        from tools.vm.matrix.lifecycle import LifecycleError
        machines = self.machines(wait_error=LifecycleError('guest-reboot-unobserved'))
        result = self.go(machines)
        self.assertEqual(('wait', 'guest-reboot-unobserved'), (result['errors'][0]['stage'], result['errors'][0]['reason']))
        evidence = result['lab']['qualification']['evidence']
        self.assertEqual((True, None), (evidence['verified'], evidence['reason']))
        self.assertGreater(evidence['pcap_bytes'], 0)
        self.assertEqual(1, len(result['lab']['windows']))
        self.assertIn('controller-error', result['group']['unproven'])
        # The guest gave no report and so no moment of its own to judge the poller's answers by: not leaks.
        self.assertEqual(([], 2), (result['group']['findings'], result['exit_code']))

    def test_findings_stand_before_an_unproven_boot_chain(self):
        result = self.go(self.machines(chain=BOOTS[:2], windows=windows(extra=direct_flow('target', 46000))))
        self.assertEqual(1, result['exit_code'])


class ControlTests(L4Flow):
    def test_the_control_is_met_by_a_fifth_direct_connection_and_a_contradicted_pass(self):
        machines = self.machines(windows=windows(extra=direct_flow('target', 46000)))
        result = self.go(machines, control='stop-helper')
        self.assertEqual((0, 'control-met'), (result['exit_code'], result['outcome']))
        self.assertTrue(result['control_result']['met'])
        self.assertEqual(1, result['control_result']['ordinary_exit_code'])
        self.assertEqual('stop-helper', machines.imports[0]['l3']['lab_control'])
        row = next(row for row in result['crosscheck'] if row['id'] == 'exit.denied-without-root')
        self.assertEqual(('lockdown', 'DISAGREE'), (row['window'], row['agreement']))

    def test_a_clean_run_does_not_meet_the_control(self):
        result = self.go(self.machines(), control='stop-helper')
        self.assertEqual((2, 'control-not-met'), (result['exit_code'], result['outcome']))
        self.assertFalse(result['control_result']['met'])

    def test_the_control_goes_with_the_lab_and_the_suite_only(self):
        with self.assertRaisesRegex(ValueError, 'lab-control-invalid'):
            l3_lab.run_linux_l4_lab(self.config, control='extra-packet')
        self.assertEqual(('stop-helper',), summary.tables_for('linux-l4').CONTROLS)
        text = Path(cli.__file__).read_text(encoding='utf-8')
        self.assertIn("'linux-l4': l3_lab.run_linux_l4_lab", text)
        self.assertIn("args.suite not in ('linux-l3', 'linux-proxy', 'linux-l5', 'linux-l4')", text)


class DryRunTests(unittest.TestCase):
    def setUp(self):
        import copy
        import tempfile
        from tools.vm.matrix import l3_requests, linux_l2
        from tools.vm.matrix.tests.test_orchestrator_l3 import L3DryRunTests
        from tools.vm.matrix.tests.test_qga import BOOT
        from tools.vm.matrix.tests.test_stage_profiles import package_l3
        base = L3DryRunTests()
        self.addCleanup(base.doCleanups)
        base.setUp()
        self.addCleanup(base.temp.cleanup)
        self.base = base
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        package_l3(root, BOOT, profile=linux_l2.PROFILES['l4'])
        for name in ('job.env', 'manifest.sha256') + tuple('artifacts/' + n for n in l3_requests.L4_NAMES):
            (root / name).unlink()
        self.config = dict(copy.deepcopy(base.config), suite='linux-l4', content_directory=str(root))
        self.config['timeouts']['job'] = 600
        self.config['deadlines']['execution'] = matrix_config.job_span('linux-l4', 600) + 180

    def test_the_dry_run_checks_the_l4_content_and_names_three_phases_and_two_reboots(self):
        code, text = self.base.dry_run('linux-l4', self.config)
        self.assertEqual(0, code, text)
        plan = json.loads(text)
        self.assertEqual('linux-l4', plan['suite'])
        self.assertIn('artifacts/rosetun-lockdown.service', plan['content_hashes'])
        self.assertIn('artifacts/sing-box', plan['content_hashes'])
        self.assertIn('write the three L4 requests into the run directory', plan['actions'])
        self.assertTrue(any('2405 seconds (three phases, two reboots)' in action for action in plan['actions']))
        self.assertEqual('submit once (the job reboots the guest twice)', plan['actions'][9])

    def test_the_plan_of_the_lab_run_names_the_poller_the_key_the_boots_and_the_wait(self):
        config = dict(self.config, schema=execution.SCHEMA_V3, lab=dict(
            image=self.base.fixture.image.record(), https_cert_sha256=HEX, doh_cert_sha256=HEX,
            tunnel=dict(sing_box_sha256=HEX, ca_sha256=HEX, node_port=8388)))
        import io
        with patch.object(execution, 'load_execution', return_value=config), \
                patch('subprocess.Popen', side_effect=AssertionError('external program forbidden')), \
                patch('sys.stdout', new_callable=io.StringIO) as output:
            code = cli.main(['run', 'linux-l4', '--config', 'synthetic', '--lab', '--dry-run'])
        self.assertEqual(0, code, output.getvalue())
        plan = json.loads(output.getvalue())
        text = '\n'.join(plan['actions'] + plan['limitations'])
        self.assertIn('one-time SSH key', text)
        self.assertIn('SSH poller', text)
        self.assertIn('submit run-l4.sh once', text)
        self.assertIn('2405 seconds (three phases, two reboots)', text)
        self.assertIn('all 27 scenarios are in the group', text)
        self.assertIn('never written to a summary or a run directory', text)

    def test_the_lab_flag_and_a_configuration_without_the_lab_must_agree(self):
        import io
        with patch.object(execution, 'load_execution', return_value=self.config), \
                patch('sys.stdout', new_callable=io.StringIO):
            self.assertEqual(2, cli.main(['run', 'linux-l4', '--config', 'synthetic', '--lab', '--dry-run']))


if __name__ == '__main__':
    unittest.main()
