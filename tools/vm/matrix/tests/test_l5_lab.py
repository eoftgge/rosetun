"""Linux L5 in the lab (stage 8b): the tables of the suite, the run, the counter beside the observer and the exit code.

The numbers come from run-l5.sh alone: no L5 run has been through the lab yet.
"""

import copy
import io
from pathlib import Path
import unittest
from unittest.mock import patch

from tools.vm.matrix import cli, execution, l3_lab, l3_summary as summary, l5_tables as tables
from tools.vm.matrix.tests.test_l3_lab import Flow, HEX, Machines, clean_windows, example
from tools.vm.matrix.tests.test_l3_summary import LEAK
from tools.vm.matrix.tests.test_l5_script import SCRIPT
from tools.vm.matrix.tests.test_proxy_script import callers

CATALOG = Path(__file__).resolve().parents[2] / 'linux' / 'scenarios-l5.tsv'
# The windows of a run where every scenario passed, in the order run-l5.sh opens them.
LABELS = ('upgrade_ks', 'upgrade_lockdown')


def catalog():
    rows = [line.split('\t') for line in CATALOG.read_text(encoding='utf-8').splitlines()]
    return [row for row in rows[1:] if row and row[0]]


def passing_rows(**changes):
    """What a clean run of run-l5.sh reports, but for the ids given (dots as `__`, dashes as `_`)."""
    rows = {row[0]: ('PASS', 'ok') for row in catalog()}
    for key, value in changes.items():
        rows[key.replace('__', '.').replace('_', '-')] = value
    return rows


def windows(leak_in=None, drop=None, direct=None):
    """The windows of a clean run, with a leak in one, one left out, or the direct flows of `direct`."""
    spec = []
    for label, frames in clean_windows(LABELS, direct or {}):
        if label == drop:
            continue
        spec.append((label, tuple(frames) + ((LEAK,) if label == leak_in else ())))
    return spec


class TableTests(unittest.TestCase):
    def test_every_scenario_has_a_window_entry_and_the_group_is_all_seventeen(self):
        ids = [row[0] for row in catalog()]
        self.assertEqual(ids, list(tables.WINDOW_OF))
        self.assertEqual(ids, list(tables.GROUP))
        self.assertEqual(17, len(tables.GROUP))
        self.assertEqual({'upgrade_ks': ['upgrade.kill-switch-no-leak', 'upgrade.kill-switch-hold', 'upgrade.reconnect'],
                          'upgrade_lockdown': ['upgrade.lockdown', 'remove.refused', 'remove.lockdown']},
                         {label: [i for i in ids if tables.WINDOW_OF[i] == (label, 0)] for label in LABELS})

    def test_every_label_is_a_function_of_run_l5_sh_that_opens_its_window(self):
        self.assertEqual(LABELS, tables.GROUP_LABELS)
        text = SCRIPT.read_text(encoding='utf-8')
        self.assertEqual(['upgrade_ks'], callers(text, 'connect_with '))
        self.assertEqual(['connect_with', 'upgrade_lockdown'], callers(text, 'lab_mark open'))
        self.assertEqual(dict.fromkeys(LABELS, 1), tables.WINDOWS_PER_LABEL)
        self.assertEqual(({}, {}, {}, {}), (tables.WINDOWS_AT_MOST, tables.OWN_WINDOW_WHEN_OPENED,
                                            tables.WINDOW_ALLOWANCES, tables.EXPECTED_FLOWS))

    def test_the_control_and_the_counter_are_those_of_the_kill_switch_window(self):
        l5 = summary.tables_for('linux-l5')
        self.assertEqual(('upgrade_ks', 'upgrade.kill-switch-no-leak', ('stop-helper',)),
                         (l5.CONTROL_WINDOW, l5.CONTROL_SCENARIO, l5.CONTROLS))
        self.assertEqual(('upgrade_ks', 0), tables.WINDOW_OF[l5.CONTROL_SCENARIO])
        self.assertTrue(l5.LEAK_OUTSIDE_THE_GROUP_FAILS)
        self.assertEqual(summary.REQUIRED_FIXTURES, l5.REQUIRED_FIXTURES)
        self.assertEqual(dict(scenario='upgrade.kill-switch-no-leak', window=('upgrade_ks', 0),
                              table='inet rosetun-l5-watch', address='203.0.113.2',
                              reason=r'([0-9]+) packets past the tunnel: '), l5.COUNTER)
        text = SCRIPT.read_text(encoding='utf-8')
        self.assertIn('WATCH_TABLE=rosetun-l5-watch', text)
        self.assertIn('fail_reason="$packets packets past the tunnel: $(watch_senders', text)

    def test_the_tables_of_l3_and_proxy_are_unchanged_and_have_no_counter(self):
        l3 = summary.tables_for('linux-l3')
        for name in summary.TABLES:
            self.assertIs(getattr(summary, name), getattr(l3, name), name)
        self.assertEqual(40, len(l3.GROUP))
        self.assertEqual(27, len(summary.tables_for('linux-proxy').GROUP))
        self.assertEqual((None, None), (l3.COUNTER, summary.tables_for('linux-proxy').COUNTER))
        self.assertEqual(('linux-l3', 'linux-proxy', 'linux-l5'), summary.LAB_SUITES)
        with self.assertRaises(ValueError):
            summary.tables_for('linux-l4')


class L5Flow(Flow):
    def setUp(self):
        super().setUp()
        self.config['suite'] = 'linux-l5'
        # The packages bring their engines: the block names no engine hash.
        self.config['l3'].pop('sing_box_sha256')

    def machines(self, **options):
        options.setdefault('windows', windows())
        options.setdefault('rows', passing_rows())
        machines = Machines(self, **options)
        machines.report_directory = 'linux-l5'
        return machines

    def go(self, machines, **options):
        # Flow.go runs the L3 entry point; here the same steps go through the L5 one, each run on a stand of its own
        # so that one test may run several.
        self.runs = getattr(self, 'runs', 0) + 1
        self.config['state_directory'] = str(self.fixture.root / ('lab-state-' + str(self.runs)))
        with patch.object(l3_lab, 'run_linux_l3_lab', side_effect=l3_lab.run_linux_l5_lab):
            return super().go(machines, **options)


class RunTests(L5Flow):
    def agreements(self, result):
        return {row['id']: row['agreement'] for row in result['crosscheck']}

    def test_a_clean_run_agrees_with_the_counter_and_exits_zero(self):
        result = self.go(self.machines())
        self.assertEqual((0, 'group-clean'), (result['exit_code'], result['outcome']))
        self.assertEqual(('rosetun.matrix.l5-summary.v1', 'linux-l5'), (result['schema'], result['suite']))
        self.assertEqual(17, len(result['crosscheck']))
        agreements = self.agreements(result)
        self.assertEqual({'NOT_APPLICABLE'}, {agreements[i] for i in tables.GROUP if tables.WINDOW_OF[i] is None})
        self.assertEqual({'AGREE'}, {agreements[i] for i in tables.GROUP if tables.WINDOW_OF[i] is not None})
        self.assertEqual([('upgrade_ks', 'NONE'), ('upgrade_lockdown', 'NONE')],
                         [(w['label'], w['verdict']) for w in result['lab']['windows']])
        self.assertEqual({True}, {row['as_expected'] for row in result['lab']['window_counts']})
        self.assertEqual([], result['out_of_scope'])
        counter = result['group']['counter']
        self.assertEqual(dict(scenario='upgrade.kill-switch-no-leak', table='inet rosetun-l5-watch', window='upgrade_ks',
                              window_number=0, windows=[0], script_count=0, observer_direct_frames=0,
                              observer_frames_to_address=0, address='203.0.113.2', agreement='AGREE'), counter)
        self.assertEqual(([], []), (result['group']['findings'], result['group']['unproven']))
        self.assertFalse(result['release_gate'])

    def test_the_run_asks_for_the_l5_requests_media_without_an_engine_hash_and_the_marker_address(self):
        machines = self.machines()
        self.go(machines)
        self.assertEqual(dict(profile='l5'), machines.request_options)
        self.assertEqual(('l5', None), (machines.attach_options['profile'], machines.attach_options['sing_box_sha256']))
        self.assertEqual(l3_lab.marker_address(), machines.imports[0]['l3']['lab_marker_address'])
        self.assertNotIn('lab_control', machines.imports[0]['l3'])

    def test_a_direct_frame_the_counter_did_not_see_contradicts_it_and_the_scenarios_of_the_window(self):
        result = self.go(self.machines(windows=windows(direct={('upgrade_ks', 0): ('target',)})))
        self.assertEqual((1, 'findings'), (result['exit_code'], result['outcome']))
        agreements = self.agreements(result)
        self.assertEqual({'DISAGREE'}, {agreements[i] for i in ('upgrade.kill-switch-no-leak',
                                                                 'upgrade.kill-switch-hold', 'upgrade.reconnect')})
        counter = result['group']['counter']
        self.assertEqual((0, 3, 2, 'DISAGREE'), (counter['script_count'], counter['observer_direct_frames'],
                                                 counter['observer_frames_to_address'], counter['agreement']))
        self.assertIn('counter-contradicted-by-window', result['group']['findings'])

    def test_any_unexpected_frame_counts_against_the_counter_not_only_those_to_its_address(self):
        result = self.go(self.machines(windows=windows(leak_in='upgrade_ks')))
        counter = result['group']['counter']
        self.assertEqual((0, 1, 0, 'DISAGREE'), (counter['script_count'], counter['observer_direct_frames'],
                                                 counter['observer_frames_to_address'], counter['agreement']))

    def test_packets_the_counter_saw_that_the_wire_did_not_contradict_it_the_other_way_round(self):
        rows = passing_rows(upgrade__kill_switch_no_leak=('FAIL', '3 packets past the tunnel: 3 UID=0 PROTO=TCP DPT=443'))
        result = self.go(self.machines(rows=rows))
        self.assertEqual(1, result['exit_code'])
        counter = result['group']['counter']
        self.assertEqual((3, 0, 'DISAGREE'), (counter['script_count'], counter['observer_direct_frames'],
                                              counter['agreement']))
        self.assertEqual(['upgrade.kill-switch-no-leak'], result['group']['failed'])

    def test_a_count_the_wire_confirms_agrees_and_a_failure_without_a_count_is_unknown(self):
        rows = passing_rows(upgrade__kill_switch_no_leak=('FAIL', '2 packets past the tunnel: the kernel log has none'))
        result = self.go(self.machines(rows=rows, windows=windows(direct={('upgrade_ks', 0): ('target',)})))
        self.assertEqual(('AGREE', 2), (result['group']['counter']['agreement'],
                                        result['group']['counter']['script_count']))
        self.assertNotIn('counter-contradicted-by-window', result['group']['findings'])
        rows = passing_rows(upgrade__kill_switch_no_leak=('FAIL', 'the table was gone at 1 of 9 looks'))
        result = self.go(self.machines(rows=rows))
        self.assertEqual((None, 'UNKNOWN'), (result['group']['counter']['script_count'],
                                             result['group']['counter']['agreement']))

    def test_a_leak_under_lockdown_contradicts_the_scenarios_of_that_window_and_not_the_counter(self):
        result = self.go(self.machines(windows=windows(leak_in='upgrade_lockdown')))
        self.assertEqual(1, result['exit_code'])
        agreements = self.agreements(result)
        self.assertEqual({'DISAGREE'}, {agreements[i] for i in ('upgrade.lockdown', 'remove.refused', 'remove.lockdown')})
        self.assertEqual('AGREE', result['group']['counter']['agreement'])
        self.assertIn('leak-in-group-window', result['group']['findings'])

    def test_a_missing_window_cannot_vouch_for_the_run_or_the_counter(self):
        result = self.go(self.machines(windows=windows(drop='upgrade_ks')))
        self.assertEqual((2, 'unverified'), (result['exit_code'], result['outcome']))
        self.assertIn('window-count:upgrade_ks:expected=1,seen=0', result['group']['unproven'])
        self.assertEqual('UNOBSERVED', self.agreements(result)['upgrade.reconnect'])
        self.assertEqual(('UNKNOWN', None, []), (result['group']['counter']['agreement'],
                                                 result['group']['counter']['observer_direct_frames'],
                                                 result['group']['counter']['windows']))

    def test_the_control_is_met_only_when_the_kill_switch_window_shows_the_direct_request(self):
        stopped = windows(direct={('upgrade_ks', 0): ('target',)})
        rows = passing_rows(upgrade__kill_switch_hold=('FAIL', 'the service does not answer'),
                            upgrade__reconnect=('FAIL', 'connect failed'))
        result = self.go(self.machines(windows=stopped, rows=rows), control='stop-helper')
        self.assertEqual((0, 'control-met'), (result['exit_code'], result['outcome']))
        self.assertTrue(result['control_result']['met'])
        self.assertEqual(1, result['control_result']['ordinary_exit_code'])
        self.assertIn('window upgrade_ks DETECTED', result['control_result']['expected'])
        self.assertEqual('DISAGREE', result['group']['counter']['agreement'])
        self.assertEqual('stop-helper', self.last_control())
        result = self.go(self.machines(rows=rows), control='stop-helper')
        self.assertEqual((2, 'control-not-met'), (result['exit_code'], result['outcome']))

    def last_control(self):
        machines = self.machines()
        self.go(machines, control='stop-helper')
        return machines.imports[0]['l3']['lab_control']

    def test_a_diagnostic_l5_run_is_refused_before_anything_starts(self):
        machines = self.machines()
        with self.assertRaises(ValueError):
            self.go(machines, diagnostic=True)
        self.assertEqual([], machines.names())


class WithoutTheLabTests(unittest.TestCase):
    """`run linux-l5` without the lab: the shared orchestrator with the L5 requests and profile, no engine hash."""

    def setUp(self):
        from tools.vm.matrix import evidence, l3_requests, orchestrator
        from tools.vm.matrix.tests.test_orchestrator_l3 import L3FlowTests
        case = L3FlowTests('test_complete_order_late_agent_and_no_early_collection')
        self.addCleanup(case.doCleanups)
        case.setUp()
        case.config['suite'] = 'linux-l5'
        case.config['l3'].pop('sing_box_sha256')
        self.case, self.asked = case, []

        def requests(run, server, port, **options):
            self.asked.append((server, port, options))
            case.call('requests')
            for index, (name, data) in enumerate(l3_requests.render_for('l5', server, port).items()):
                run.register(dict(id='fake-request-' + str(index), kind='file', path='l3-requests/' + name))
                (run.directory / 'l3-requests').mkdir(exist_ok=True)
                evidence.write_file(run, 'l3-requests/' + name, data, mode='create', require_registered=True)
        case.adapters.requests = requests
        self.run_l5 = lambda: orchestrator.run_linux_l5(case.config, adapters=case.adapters, clock=case.clock,
                                                       sleep=case.clock.sleep, progress=lambda stage: None)

    def test_the_run_writes_the_l5_requests_and_passes_the_l5_profile_on_without_an_engine_hash(self):
        result = self.run_l5()
        self.assertEqual(0, result['exit_code'])
        self.assertEqual('linux-l5', result['suite'])
        self.assertEqual([('192.0.2.1', 8388, dict(profile='l5'))], self.asked)
        self.assertEqual(('l5', None), (self.case.media_options['profile'], self.case.media_options['sing_box_sha256']))
        self.assertNotIn('lab_marker_address', self.case.import_options['l3'])

    def test_an_l3_configuration_is_not_an_l5_one(self):
        from tools.vm.matrix import orchestrator
        self.case.config['suite'] = 'linux-l3'
        with self.assertRaises(ValueError):
            orchestrator.run_linux_l5(self.case.config, adapters=self.case.adapters)


class DryRunTests(unittest.TestCase):
    def setUp(self):
        import json
        import tempfile
        from tools.vm.matrix import l3_requests, linux_l2
        from tools.vm.matrix.tests.test_orchestrator_l3 import L3DryRunTests
        from tools.vm.matrix.tests.test_qga import BOOT
        from tools.vm.matrix.tests.test_stage_profiles import package_l3
        self.json = json
        base = L3DryRunTests()
        self.addCleanup(base.doCleanups)
        base.setUp()
        self.addCleanup(base.temp.cleanup)
        self.base = base
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        package_l3(root, BOOT, profile=linux_l2.PROFILES['l5'])
        for name in ('job.env', 'manifest.sha256') + tuple('artifacts/' + n for n in l3_requests.L5_NAMES):
            (root / name).unlink()
        l3 = dict(base.config['l3'])
        l3.pop('sing_box_sha256')
        self.config = dict(copy.deepcopy(base.config), suite='linux-l5', content_directory=str(root), l3=l3)

    def test_the_dry_run_checks_the_l5_content_and_names_the_l5_job(self):
        code, text = self.base.dry_run('linux-l5', self.config)
        self.assertEqual(0, code, text)
        plan = self.json.loads(text)
        self.assertEqual('linux-l5', plan['suite'])
        self.assertIn('artifacts/rosetun-old.deb', plan['content_hashes'])
        self.assertIn('artifacts/rosetun-new.deb', plan['content_hashes'])
        self.assertNotIn('artifacts/sing-box', plan['content_hashes'])
        self.assertIn('write the three L5 lab requests into the run directory', plan['actions'])
        self.assertIn('the two packages are hashed and their magic read, never installed, on the controller',
                      plan['limitations'])

    def test_an_l3_content_directory_or_an_engine_hash_is_not_an_l5_one(self):
        code, _ = self.base.dry_run('linux-l5', dict(self.config, content_directory=self.base.config['content_directory']))
        self.assertEqual(2, code)
        code, _ = self.base.dry_run('linux-l5', dict(self.config, l3=dict(self.config['l3'], sing_box_sha256=HEX)))
        self.assertEqual(2, code)


class ConfigurationTests(unittest.TestCase):
    def l5(self):
        config = example()
        config['suite'] = 'linux-l5'
        config['l3'].pop('sing_box_sha256')
        return config

    def test_an_l5_configuration_takes_the_l3_block_without_an_engine_hash_with_or_without_the_lab(self):
        config = execution.validate(self.l5())
        self.assertEqual(('linux-l5', execution.SCHEMA_V3), (execution.suite_of(config), config['schema']))
        self.assertNotIn('sing_box_sha256', config['l3'])
        v2 = self.l5()
        v2.pop('lab')
        v2['schema'] = execution.SCHEMA_V2
        self.assertIsNone(execution.lab_of(execution.validate(v2)))
        with_engine = self.l5()
        with_engine['l3']['sing_box_sha256'] = HEX
        with self.assertRaises(ValueError):
            execution.validate(with_engine)
        missing = self.l5()
        missing.pop('l3')
        with self.assertRaises(ValueError):
            execution.validate(missing)

    def test_l3_and_proxy_still_need_the_engine_hash(self):
        for suite in ('linux-l3', 'linux-proxy'):
            config = example()
            config['suite'] = suite
            execution.validate(copy.deepcopy(config))
            config['l3'].pop('sing_box_sha256')
            with self.subTest(suite=suite), self.assertRaises(ValueError):
                execution.validate(config)

    def test_the_command_line_sends_an_l5_run_to_the_l5_controller(self):
        seen = []

        def record(name):
            def run(config, **options):
                seen.append((name, options))
                return dict(exit_code=0)
            return run
        config = self.l5()
        plain = copy.deepcopy(config)
        plain.pop('lab')
        plain['schema'] = execution.SCHEMA_V2
        from tools.vm.matrix import orchestrator
        for chosen, arguments in ((config, ['--lab']), (config, ['--lab', '--control', 'stop-helper']),
                                  (plain, []), (config, ['--lab', '--diagnostic']), (plain, ['--control', 'stop-helper'])):
            with patch.object(execution, 'load_execution', return_value=chosen), \
                    patch.object(l3_lab, 'run_linux_l5_lab', side_effect=record('lab')), \
                    patch.object(l3_lab, 'run_linux_l3_lab', side_effect=record('l3')), \
                    patch.object(l3_lab, 'run_linux_proxy_lab', side_effect=record('proxy')), \
                    patch.object(orchestrator, 'run_linux_l5', side_effect=record('plain')), \
                    patch('sys.stdout', new_callable=io.StringIO):
                cli.main(['run', 'linux-l5', '--config', 'synthetic', *arguments])
        self.assertEqual([('lab', {}), ('lab', dict(control='stop-helper')), ('plain', {})], seen)


if __name__ == '__main__':
    unittest.main()
