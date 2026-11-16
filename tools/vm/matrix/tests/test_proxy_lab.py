"""Linux Proxy in the lab (stage 8a): the tables of the suite, the run, the cross-check and the exit code.

The numbers come from run-proxy.sh alone: no Proxy run has been through the lab yet.
"""

import copy
import io
from pathlib import Path
import unittest
from unittest.mock import patch

from tools.vm.matrix import cli, execution, l3_lab, l3_summary as summary, proxy_tables as tables
from tools.vm.matrix.tests.test_l3_lab import Flow, HEX, Machines, clean_windows, direct_flow, example
from tools.vm.matrix.tests.test_l3_summary import LEAK
from tools.vm.matrix.tests.test_proxy_script import OPENERS, SCRIPT, callers

CATALOG = Path(__file__).resolve().parents[2] / 'linux' / 'scenarios-proxy.tsv'
# The windows of a run where every scenario passed, in the order run-proxy.sh opens them.
LABELS = ('proxy_open', 'strict', 'mode_change', 'share', 'share_off', 'lockdown_share', 'stopped')
DIRECT = {('proxy_open', 0): ('target',)}


def catalog():
    rows = [line.split('\t') for line in CATALOG.read_text(encoding='utf-8').splitlines()]
    return [row for row in rows[1:] if row and row[0]]


def passing_rows(**changes):
    """What a clean run of run-proxy.sh reports, but for the ids given (dots as `__`, dashes as `_`)."""
    rows = {row[0]: ('SKIP', 'UNRUN: not provisioned') if row[2] == 'not-run' else ('PASS', 'ok') for row in catalog()}
    for key, value in changes.items():
        rows[key.replace('__', '.').replace('_', '-')] = value
    return rows


def windows(leak_in=None, drop=None, direct=None, extra=None):
    """The windows of a clean run, with a leak in one, one left out, or `extra` frames added to (label: frames)."""
    spec = []
    for label, frames in clean_windows(LABELS, DIRECT if direct is None else direct):
        if label == drop:
            continue
        added = (LEAK,) if label == leak_in else ()
        spec.append((label, tuple(frames) + added + tuple((extra or {}).get(label, ()))))
    return spec


class TableTests(unittest.TestCase):
    def test_every_scenario_has_a_window_entry_and_the_group_is_all_but_the_two_hop_exits(self):
        ids = [row[0] for row in catalog()]
        self.assertEqual(set(ids), set(tables.WINDOW_OF))
        self.assertEqual([i for i in ids if not i.startswith('two-hop.')], list(tables.GROUP))
        self.assertEqual(27, len(tables.GROUP))
        self.assertEqual(20, sum(row[2] == 'not-run' for row in catalog()))
        self.assertIn('share.listens', tables.GROUP)
        self.assertIn('lockdown.share-open', tables.GROUP)

    def test_every_label_is_a_function_of_run_proxy_sh_that_opens_a_session(self):
        self.assertEqual(set(OPENERS), set(tables.GROUP_LABELS))
        self.assertEqual(LABELS, tables.GROUP_LABELS)
        text = SCRIPT.read_text(encoding='utf-8')
        self.assertEqual(set(OPENERS) | {'opened'}, set(callers(text, 'connect_with ')))
        self.assertEqual(dict.fromkeys(LABELS, 1), tables.WINDOWS_PER_LABEL)
        self.assertEqual(({}, {}, {}), (tables.WINDOWS_AT_MOST, tables.OWN_WINDOW_WHEN_OPENED, tables.WINDOW_ALLOWANCES))

    def test_only_the_window_without_the_kill_switch_expects_one_direct_connection_to_the_target(self):
        self.assertEqual({('proxy_open', 0): {('tcp', 'target', '203.0.113.2:443'): 1}}, tables.EXPECTED_FLOWS)
        text = SCRIPT.read_text(encoding='utf-8')
        around = text.split('    around() { expect_reached', 1)[1].split('\n', 1)[0]
        self.assertIn('direct_https', around)

    def test_the_control_window_is_the_strict_session_and_the_rest_is_as_for_l3(self):
        proxy = summary.tables_for('linux-proxy')
        self.assertEqual(('strict', 'strict.through', ('stop-helper',)),
                         (proxy.CONTROL_WINDOW, proxy.CONTROL_SCENARIO, proxy.CONTROLS))
        self.assertEqual(('strict', 0), tables.WINDOW_OF['strict.through'])
        self.assertTrue(proxy.LEAK_OUTSIDE_THE_GROUP_FAILS)
        self.assertEqual(summary.REQUIRED_FIXTURES, proxy.REQUIRED_FIXTURES)

    def test_the_l3_tables_are_the_module_constants_unchanged(self):
        l3 = summary.tables_for('linux-l3')
        for name in summary.TABLES:
            self.assertIs(getattr(summary, name), getattr(l3, name), name)
        self.assertEqual(summary.CONTROL_EXPECTATIONS, l3.CONTROL_EXPECTATIONS)
        self.assertEqual(40, len(l3.GROUP))
        with self.assertRaises(ValueError):
            summary.tables_for('linux-l4')


class ProxyFlow(Flow):
    def setUp(self):
        super().setUp()
        self.config['suite'] = 'linux-proxy'

    def machines(self, **options):
        options.setdefault('windows', windows())
        options.setdefault('rows', passing_rows())
        machines = Machines(self, **options)
        machines.report_directory = 'linux-proxy'
        return machines

    def go(self, machines, **options):
        # Flow.go runs the L3 entry point; here the same steps go through the Proxy one, each run on a stand
        # of its own so that one test may run several.
        self.runs = getattr(self, 'runs', 0) + 1
        self.config['state_directory'] = str(self.fixture.root / ('lab-state-' + str(self.runs)))
        with patch.object(l3_lab, 'run_linux_l3_lab', side_effect=l3_lab.run_linux_proxy_lab):
            return super().go(machines, **options)


class RunTests(ProxyFlow):
    def agreements(self, result):
        return {row['id']: row['agreement'] for row in result['crosscheck']}

    def test_a_clean_run_agrees_and_exits_zero(self):
        machines = self.machines()
        result = self.go(machines)
        self.assertEqual((0, 'group-clean'), (result['exit_code'], result['outcome']))
        self.assertEqual(('rosetun.matrix.proxy-summary.v1', 'linux-proxy'), (result['schema'], result['suite']))
        self.assertEqual(27, len(result['crosscheck']))
        agreements = self.agreements(result)
        self.assertEqual({'NOT_APPLICABLE'}, {agreements[i] for i in tables.GROUP if tables.WINDOW_OF[i] is None})
        self.assertEqual({'AGREE'}, {agreements[i] for i in tables.GROUP if tables.WINDOW_OF[i] is not None})
        verdicts = {(w['label'], w['number']): w['verdict'] for w in result['lab']['windows']}
        self.assertEqual('EXPECTED', verdicts.pop(('proxy_open', 0)))
        self.assertEqual({'NONE'}, set(verdicts.values()))
        self.assertEqual(7, len(result['lab']['windows']))
        self.assertEqual({True}, {row['as_expected'] for row in result['lab']['window_counts']})
        self.assertEqual(20, len(result['out_of_scope']))
        self.assertEqual(([], []), (result['group']['findings'], result['group']['unproven']))
        self.assertFalse(result['release_gate'])

    def test_the_run_asks_for_the_proxy_requests_media_and_the_marker_address(self):
        machines = self.machines()
        self.go(machines)
        self.assertEqual(dict(profile='proxy'), machines.request_options)
        self.assertEqual('proxy', machines.attach_options['profile'])
        self.assertEqual(l3_lab.marker_address(), machines.imports[0]['l3']['lab_marker_address'])
        self.assertNotIn('lab_control', machines.imports[0]['l3'])

    def test_a_second_direct_connection_where_one_is_expected_is_a_leak(self):
        result = self.go(self.machines(windows=windows(extra={'proxy_open': direct_flow('target', 45000)})))
        self.assertEqual((1, 'findings'), (result['exit_code'], result['outcome']))
        self.assertEqual('DISAGREE', self.agreements(result)['proxy.around-open'])

    def test_the_expected_direct_connection_missing_is_a_mismatch(self):
        result = self.go(self.machines(windows=windows(direct={})))
        self.assertEqual(1, result['exit_code'])
        row = next(row for row in result['crosscheck'] if row['id'] == 'proxy.through')
        self.assertEqual(('MISMATCH', 'DISAGREE'), (row['window_verdict'], row['agreement']))

    def test_a_leak_under_the_kill_switch_or_lockdown_contradicts_the_scenarios_of_that_window(self):
        for label, scenarios in (('strict', ('strict.through', 'strict.disconnect')),
                                 ('lockdown_share', ('lockdown.share-closed', 'lockdown.share-open', 'lockdown.off')),
                                 ('share', ('share.listens', 'share.peer-refused')), ('stopped', ('stop.removes-table',))):
            with self.subTest(label=label):
                result = self.go(self.machines(windows=windows(leak_in=label)))
                self.assertEqual(1, result['exit_code'])
                agreements = self.agreements(result)
                self.assertEqual({'DISAGREE'}, {agreements[i] for i in scenarios})
                self.assertIn('leak-in-group-window', result['group']['findings'])

    def test_a_missing_window_cannot_vouch_for_the_run(self):
        result = self.go(self.machines(windows=windows(drop='stopped')))
        self.assertEqual((2, 'unverified'), (result['exit_code'], result['outcome']))
        self.assertIn('window-count:stopped:expected=1,seen=0', result['group']['unproven'])
        self.assertEqual('UNOBSERVED', self.agreements(result)['stop.removes-table'])

    def test_a_failed_scenario_of_the_group_is_a_finding(self):
        result = self.go(self.machines(rows=passing_rows(share__listens=('FAIL', 'nothing listens'))))
        self.assertEqual(1, result['exit_code'])
        self.assertEqual(['share.listens'], result['group']['failed'])

    def test_the_control_is_met_only_when_the_strict_window_shows_the_direct_request(self):
        stopped = windows(direct={('proxy_open', 0): ('target',), ('strict', 0): ('target',)})
        rows = passing_rows(strict__around_blocked=('FAIL', 'answered'))
        result = self.go(self.machines(windows=stopped, rows=rows), control='stop-helper')
        self.assertEqual((0, 'control-met'), (result['exit_code'], result['outcome']))
        self.assertTrue(result['control_result']['met'])
        self.assertEqual(1, result['control_result']['ordinary_exit_code'])
        self.assertIn('window strict DETECTED', result['control_result']['expected'])
        result = self.go(self.machines(rows=rows), control='stop-helper')
        self.assertEqual((2, 'control-not-met'), (result['exit_code'], result['outcome']))

    def test_a_diagnostic_proxy_run_is_refused_before_anything_starts(self):
        machines = self.machines()
        with self.assertRaises(ValueError):
            self.go(machines, diagnostic=True)
        self.assertEqual([], machines.names())


class WithoutTheLabTests(unittest.TestCase):
    """`run linux-proxy` without the lab: the shared orchestrator with the Proxy requests and profile."""

    def setUp(self):
        from tools.vm.matrix import evidence, l3_requests, orchestrator
        from tools.vm.matrix.tests.test_orchestrator_l3 import L3FlowTests
        case = L3FlowTests('test_complete_order_late_agent_and_no_early_collection')
        self.addCleanup(case.doCleanups)
        case.setUp()
        case.config['suite'] = 'linux-proxy'
        self.case, self.asked = case, []

        def requests(run, server, port, **options):
            self.asked.append((server, port, options))
            case.call('requests')
            for index, (name, data) in enumerate(l3_requests.render_for('proxy', server, port).items()):
                run.register(dict(id='fake-request-' + str(index), kind='file', path='l3-requests/' + name))
                (run.directory / 'l3-requests').mkdir(exist_ok=True)
                evidence.write_file(run, 'l3-requests/' + name, data, mode='create', require_registered=True)
        case.adapters.requests = requests
        self.run_proxy = lambda: orchestrator.run_linux_proxy(case.config, adapters=case.adapters, clock=case.clock,
                                                             sleep=case.clock.sleep, progress=lambda stage: None)

    def test_the_run_writes_the_proxy_requests_and_passes_the_proxy_profile_on(self):
        result = self.run_proxy()
        self.assertEqual(0, result['exit_code'])
        self.assertEqual('linux-proxy', result['suite'])
        self.assertEqual([('192.0.2.1', 8388, dict(profile='proxy'))], self.asked)
        self.assertEqual('proxy', self.case.media_options['profile'])
        self.assertNotIn('lab_marker_address', self.case.import_options['l3'])

    def test_an_l3_configuration_is_not_a_proxy_one(self):
        from tools.vm.matrix import orchestrator
        self.case.config['suite'] = 'linux-l3'
        with self.assertRaises(ValueError):
            orchestrator.run_linux_proxy(self.case.config, adapters=self.case.adapters)


class DryRunTests(unittest.TestCase):
    def setUp(self):
        import json
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
        import tempfile
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        package_l3(root, BOOT, profile=linux_l2.PROFILES['proxy'])
        for name in ('job.env', 'manifest.sha256') + tuple('artifacts/' + n for n in l3_requests.PROXY_NAMES):
            (root / name).unlink()
        self.config = dict(copy.deepcopy(base.config), suite='linux-proxy', content_directory=str(root))

    def test_the_dry_run_checks_the_proxy_content_and_names_the_proxy_job(self):
        code, text = self.base.dry_run('linux-proxy', self.config)
        self.assertEqual(0, code, text)
        plan = self.json.loads(text)
        self.assertEqual('linux-proxy', plan['suite'])
        self.assertIn('artifacts/desktop_proxy', plan['content_hashes'])
        self.assertIn('artifacts/rosetun-lockdown.service', plan['content_hashes'])
        self.assertIn('write the four Proxy lab requests into the run directory', plan['actions'])

    def test_an_l3_content_directory_is_not_a_proxy_one(self):
        self.assertEqual(0, self.base.dry_run()[0])
        code, _ = self.base.dry_run('linux-proxy', dict(self.config, content_directory=self.base.config['content_directory']))
        self.assertEqual(2, code)


class ConfigurationTests(unittest.TestCase):
    def proxy(self):
        config = example()
        config['suite'] = 'linux-proxy'
        return config

    def test_a_proxy_configuration_takes_the_l3_block_with_or_without_the_lab(self):
        config = execution.validate(self.proxy())
        self.assertEqual(('linux-proxy', execution.SCHEMA_V3), (execution.suite_of(config), config['schema']))
        v2 = self.proxy()
        v2.pop('lab')
        v2['schema'] = execution.SCHEMA_V2
        self.assertIsNone(execution.lab_of(execution.validate(v2)))
        missing = self.proxy()
        missing.pop('l3')
        with self.assertRaises(ValueError):
            execution.validate(missing)

    def test_the_command_line_sends_a_proxy_run_to_the_proxy_controller(self):
        seen = []

        def record(name):
            def run(config, **options):
                seen.append((name, options))
                return dict(exit_code=0)
            return run
        config = self.proxy()
        config['lab'] = dict(config['lab'], https_cert_sha256=HEX)
        plain = copy.deepcopy(config)
        plain.pop('lab')
        plain['schema'] = execution.SCHEMA_V2
        from tools.vm.matrix import orchestrator
        for chosen, arguments in ((config, ['--lab']), (config, ['--lab', '--control', 'stop-helper']),
                                  (plain, []), (config, ['--lab', '--diagnostic']), (plain, ['--control', 'stop-helper'])):
            with patch.object(execution, 'load_execution', return_value=chosen), \
                    patch.object(l3_lab, 'run_linux_proxy_lab', side_effect=record('lab')), \
                    patch.object(l3_lab, 'run_linux_l3_lab', side_effect=record('l3')), \
                    patch.object(orchestrator, 'run_linux_proxy', side_effect=record('plain')), \
                    patch('sys.stdout', new_callable=io.StringIO):
                cli.main(['run', 'linux-proxy', '--config', 'synthetic', *arguments])
        self.assertEqual([('lab', {}), ('lab', dict(control='stop-helper')), ('plain', {})], seen)


if __name__ == '__main__':
    unittest.main()
