"""The L3 path of the shared orchestrator, the v2 configuration and the CLI, on fake adapters."""

import copy
from dataclasses import asdict
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import tomllib
import unittest
from unittest.mock import patch

from tools.vm.matrix import cli, evidence, execution, l3_requests, orchestrator as o
from tools.vm.matrix.tests import test_orchestrator as base, test_qemu
from tools.vm.matrix.tests.test_qga import BOOT
from tools.vm.matrix.tests.test_stage_profiles import SING_BOX_SHA, package_l3

PACKAGE = Path(__file__).resolve().parents[1]
L3_BLOCK = dict(sing_box_sha256=SING_BOX_SHA, host_address='192.0.2.1', node_port=8388,
                probe_address='203.0.113.2', dns_probe_address='203.0.113.53')
ORDER = ['preflight', 'prepare', 'requests', 'media', 'start', 'resume', 'boot', 'import-create',
         'import', 'recovery', 'receipt', 'job-create', 'submit', 'collect', 'close']


class L3FlowTests(base.FlowTests):
    """Inherits the whole L2 battery on an L3 configuration; the order-specific tests are redone."""

    def setUp(self):
        super().setUp()
        self.config.update(suite='linux-l3', l3=copy.deepcopy(L3_BLOCK))
        self.written = self.media_options = self.import_options = None
        self.adapters.requests = self.requests
        self.adapters.attach = self.attach
        self.adapters.importer = self.importer_l3

    def requests(self, run, server, port):
        self.written = (run, server, port)
        self.call('requests')
        # What the real adapter does: registered files in the run, nothing in the content.
        for index, (name, data) in enumerate(l3_requests.render_all(server, port).items()):
            run.register(dict(id='fake-request-' + str(index), kind='file', path='l3-requests/' + name))
            (run.directory / 'l3-requests').mkdir(exist_ok=True)
            evidence.write_file(run, 'l3-requests/' + name, data, mode='create',
                                require_registered=True)

    def attach(self, *args, **kwargs):
        self.media_options = kwargs
        self.call('media')

    def importer_l3(self, *args, **kwargs):
        self.import_options = kwargs
        return self.importer(*args, **kwargs)

    def execute(self):
        return o.run_linux_l3(self.config, adapters=self.adapters, clock=self.clock,
                              sleep=self.clock.sleep, progress=lambda stage: None)

    def test_complete_order_late_agent_and_no_early_collection(self):
        result = self.execute()
        self.assertEqual(0, result['exit_code'])
        self.assertEqual(ORDER, [e[0] for e in self.events])
        times = dict(self.events)
        self.assertEqual(1025, times['collect'] - times['submit'])
        self.assertEqual((1, 1, 1), (self.imports, self.submits, self.collects))
        self.assertEqual('linux-l3', result['suite'])
        summary = Path(result['artifact_directory']) / 'execution-summary.json'
        self.assertEqual(result, json.loads(summary.read_bytes()))
        self.assertFalse(result['release_gate'])

    def test_requests_media_and_import_receive_the_l3_profile(self):
        self.execute()
        self.assertEqual(('192.0.2.1', 8388), self.written[1:])
        self.assertEqual(dict(profile='l3', sing_box_sha256=SING_BOX_SHA), {
            k: v for k, v in self.media_options.items() if k in ('profile', 'sing_box_sha256')})
        self.assertEqual(L3_BLOCK, self.import_options['l3'])
        self.assertEqual({'user_a': 'l2a', 'user_b': 'l2b'},
                         {k: v for k, v in self.import_options.items() if k.startswith('user_')})

    def test_requests_follow_prepare_and_precede_the_media(self):
        self.execute()
        names = [e[0] for e in self.events]
        self.assertLess(names.index('prepare'), names.index('requests'))
        self.assertLess(names.index('requests'), names.index('media'))

    def test_the_content_directory_is_not_touched_and_the_requests_live_in_the_run(self):
        with tempfile.TemporaryDirectory() as temp:
            content = Path(temp)
            (content / 'artifacts').mkdir()
            (content / 'artifacts/inert').write_bytes(b'inert')
            self.config['content_directory'] = temp
            def tree():
                return {p.relative_to(content).as_posix(): (p.read_bytes() if p.is_file() else None)
                        for p in content.rglob('*')}
            before = tree()
            result = self.execute()
            self.assertEqual(0, result['exit_code'])
            self.assertEqual(before, tree())
            created = Path(result['artifact_directory']) / 'l3-requests'
            self.assertEqual(l3_requests.render_all('192.0.2.1', 8388),
                             {p.name: p.read_bytes() for p in created.iterdir()})

    def test_failures_at_each_api_preserve_error_and_close(self):
        for failure in ORDER:
            with self.subTest(failure=failure):
                case = L3FlowTests('test_complete_order_late_agent_and_no_early_collection')
                case.setUp()
                try:
                    case.failure = failure
                    result = case.execute()
                    self.assertEqual(2, result['exit_code'])
                    self.assertTrue(result['errors'])
                    self.assertNotIn('private stderr', json.dumps(result))
                    if failure in ('requests', 'prepare', 'media'):
                        self.assertTrue(result['manual_recovery_required'])
                        self.assertFalse(result['completion'])
                finally:
                    case.doCleanups()

    def test_failed_requests_stop_before_any_vm_work(self):
        self.failure = 'requests'
        result = self.execute()
        self.assertEqual(2, result['exit_code'])
        self.assertEqual(['preflight', 'prepare', 'requests'], [e[0] for e in self.events])

    def test_import_refusal_stops_before_the_job_and_still_closes(self):
        self.failure = 'import'
        result = self.execute()
        self.assertEqual(2, result['exit_code'])
        self.assertEqual((1, 0, 0), (self.imports, self.submits, self.collects))
        names = [e[0] for e in self.events]
        self.assertNotIn('job-create', names)
        self.assertEqual('close', names[-1])
        self.assertTrue(result['errors'])
        self.assertIsNone(result['assessment'])

    def test_a_lost_collect_response_recovers_and_reads_again_without_resubmitting(self):
        def collect():
            if self.collects == 0:
                self.collects += 1
                self.vm.qga.valid = False
                raise ValueError('lost response')
            return self.collect()
        self.job.collect = collect
        result = self.execute()
        self.assertEqual(0, result['exit_code'])
        self.assertEqual((1, 1, 2), (self.imports, self.submits, self.collects))
        self.assertIn('collect-recovery', [s['stage'] for s in result['stages']])

    def test_the_expected_7a_outcome_is_a_rejected_but_complete_run(self):
        self.accepted = False
        result = self.execute()
        self.assertEqual(1, result['exit_code'])
        self.assertTrue(result['completion'])
        self.assertEqual([], result['errors'])
        self.assertFalse(result['execution']['accepted'])

    def test_configurations_of_the_other_suite_are_refused(self):
        with self.assertRaises(ValueError):
            o.run_linux_l2(self.config, adapters=self.adapters)
        l2_config = {k: v for k, v in self.config.items() if k not in ('suite', 'l3')}
        with self.assertRaises(ValueError):
            o.run_linux_l3(l2_config, adapters=self.adapters)
        self.assertEqual([], self.events)

    def test_the_l2_summary_names_its_suite_and_never_asks_for_requests(self):
        case = base.FlowTests('test_complete_order_late_agent_and_no_early_collection')
        case.setUp()
        self.addCleanup(case.doCleanups)
        case.adapters.requests = lambda *a: self.fail('L2 has no generated requests')
        result = case.execute()
        self.assertEqual(('linux-l2', 0), (result['suite'], result['exit_code']))
        self.assertNotIn('requests', [e[0] for e in case.events])


class ExecutionConfigTests(unittest.TestCase):
    def setUp(self):
        # The examples use Linux paths, which are not absolute on the Windows that runs the tests.
        patcher = patch.object(execution, '_state_path', side_effect=lambda value: value)
        patcher.start()
        self.addCleanup(patcher.stop)

    def v1(self):
        with (PACKAGE / 'execution.example.toml').open('rb') as stream:
            return tomllib.load(stream)

    def v2(self, suite='linux-l3'):
        config = self.v1()
        config.update(schema=execution.SCHEMA_V2, suite=suite)
        if suite == 'linux-l3':
            config['l3'] = dict(sing_box_sha256=SING_BOX_SHA)
        return config

    def test_version_1_still_reads_as_linux_l2_and_is_not_changed(self):
        config = self.v1()
        before = copy.deepcopy(config)
        self.assertIs(config, execution.validate(config))
        self.assertEqual(before, config)
        self.assertEqual('linux-l2', execution.suite_of(config))

    def test_version_1_cannot_name_a_suite_or_carry_an_l3_block(self):
        for extra in (dict(suite='linux-l2'), dict(suite='linux-l3'), dict(l3=L3_BLOCK)):
            with self.subTest(extra=extra):
                with self.assertRaises(ValueError):
                    execution.validate(dict(self.v1(), **extra))

    def test_version_2_l2_has_no_l3_block(self):
        config = self.v2('linux-l2')
        execution.validate(config)
        self.assertEqual('linux-l2', execution.suite_of(config))
        with self.assertRaises(ValueError):
            execution.validate(dict(self.v2('linux-l2'), l3=L3_BLOCK))

    def test_version_2_l3_fills_the_documented_defaults(self):
        config = execution.validate(self.v2())
        self.assertEqual(L3_BLOCK, config['l3'])
        self.assertEqual('linux-l3', execution.suite_of(config))

    def test_l3_values_are_strict(self):
        bad = ({'sing_box_sha256': 'A' * 64}, {'sing_box_sha256': 'a' * 63}, {'sing_box_sha256': 5},
               {'host_address': '10.0.0.1'}, {'host_address': '2001:db8::1'}, {'probe_address': '8.8.8.8'},
               {'dns_probe_address': '203.0.113.256'}, {'node_port': 0}, {'node_port': 65536},
               {'node_port': True}, {'node_port': '8388'}, {'extra': 1})
        for change in bad:
            with self.subTest(change=change):
                config = self.v2()
                config['l3'].update(change)
                with self.assertRaises(ValueError):
                    execution.validate(config)
        config = self.v2()
        del config['l3']['sing_box_sha256']
        with self.assertRaises(ValueError):
            execution.validate(config)
        config = self.v2()
        del config['l3']
        with self.assertRaises(ValueError):
            execution.validate(config)

    def test_unknown_suite_schema_and_extra_fields_are_refused(self):
        for change in (dict(suite='linux-l4'), dict(suite=None), dict(schema='rosetun.matrix.execution.v3'),
                       dict(boot_id=BOOT)):
            with self.subTest(change=change), self.assertRaises(ValueError):
                execution.validate(dict(self.v2(), **change))

    def test_both_example_files_validate_and_the_l3_one_is_for_l3(self):
        for name, suite in (('execution.example.toml', 'linux-l2'), ('execution-l3.example.toml', 'linux-l3')):
            with self.subTest(name=name):
                with (PACKAGE / name).open('rb') as stream:
                    config = execution.validate(tomllib.load(stream))
                self.assertEqual(suite, execution.suite_of(config))
        with (PACKAGE / 'execution-l3.example.toml').open('rb') as stream:
            config = execution.validate(tomllib.load(stream))
        self.assertEqual(L3_BLOCK['host_address'], config['l3']['host_address'])
        self.assertEqual(config['timeouts']['job'] + 180, config['deadlines']['execution'])


class L3DryRunTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_qemu.PreparationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.root = root
        package_l3(root, BOOT)
        (root / 'job.env').unlink()
        (root / 'manifest.sha256').unlink()
        for name in l3_requests.NAMES:
            (root / 'artifacts' / name).unlink()
        self.config = dict(schema=execution.SCHEMA_V2, suite='linux-l3', mode='exploratory',
            platform='linux-x86_64-kvm', state_directory=str(root / 'absent-state'), stand_id='synthetic',
            image=self.fixture.image.record(), qemu=asdict(self.fixture.config),
            xorriso=self.fixture.config.executable, content_directory=str(root),
            source_checkout=str(base.CHECKOUT), accounts=dict(user_a='l2a', user_b='l2b'),
            timeouts=dict(scenario=30, unit=180, job=300),
            deadlines=dict(preparation=600, boot=300, **{'import': 900}, execution=480),
            l3=dict(sing_box_sha256=SING_BOX_SHA))
        self.config['qemu'].update(machine='pc-i440fx-10.0', qga=True)

    def dry_run(self, suite='linux-l3', config=None):
        config = self.config if config is None else config
        with patch.object(execution, 'load_execution', return_value=config), \
                patch('subprocess.Popen', side_effect=AssertionError('external program forbidden')), \
                patch('sys.stdout', new_callable=io.StringIO) as output:
            code = cli.main(['run', suite, '--config', 'synthetic', '--dry-run'])
        return code, output.getvalue()

    def test_dry_run_checks_the_content_without_writing_requests_or_state(self):
        code, text = self.dry_run()
        self.assertEqual(0, code)
        plan = json.loads(text)
        self.assertEqual(('linux-l3', True), (plan['suite'], plan['dry_run']))
        self.assertTrue(any('requests' in action for action in plan['actions']))
        self.assertEqual(L3_BLOCK, plan['configuration']['l3'])
        self.assertFalse(any('request-' in n for n in plan['content_hashes']))
        self.assertIn('artifacts/sing-box', plan['content_hashes'])
        self.assertEqual([], [p for p in (self.root / 'artifacts').iterdir() if p.name.startswith('request-')])
        self.assertFalse(Path(self.config['state_directory']).exists())

    def test_dry_run_refuses_any_request_file_in_the_content_directory(self):
        self.assertEqual(0, self.dry_run()[0])
        l3_requests.write_all(self.root / 'artifacts')
        self.assertEqual(2, self.dry_run()[0])
        (self.root / 'artifacts/request-lan.json').write_bytes(b'{}\n')
        self.assertEqual(2, self.dry_run()[0])

    def test_dry_run_refuses_a_wrong_engine_hash_or_a_missing_binary(self):
        config = copy.deepcopy(self.config)
        config['l3']['sing_box_sha256'] = '1' * 64
        self.assertEqual(2, self.dry_run(config=config)[0])
        (self.root / 'artifacts/sing-box').unlink()
        self.assertEqual(2, self.dry_run()[0])

    def test_the_suite_on_the_command_line_must_match_the_configuration(self):
        self.assertEqual(2, self.dry_run('linux-l2')[0])
        v1 = {k: v for k, v in self.config.items() if k not in ('suite', 'l3')}
        v1['schema'] = execution.SCHEMA
        self.assertEqual(2, self.dry_run('linux-l3', v1)[0])

    def test_l2_dry_run_output_gains_only_the_suite(self):
        v1 = {k: v for k, v in self.config.items() if k not in ('suite', 'l3')}
        v1['schema'] = execution.SCHEMA
        with tempfile.TemporaryDirectory() as temp:
            from tools.vm.matrix.tests import test_linux_l2
            test_linux_l2.package(Path(temp), BOOT)
            for name in ('job.env', 'manifest.sha256'):
                (Path(temp) / name).unlink()
            v1['content_directory'] = temp
            code, text = self.dry_run('linux-l2', v1)
        self.assertEqual(0, code)
        plan = json.loads(text)
        self.assertEqual('linux-l2', plan['suite'])
        self.assertFalse(any('requests' in action for action in plan['actions']))
        self.assertEqual(['no controller restart recovery', 'no automatic file cleanup', 'no network',
                          'dry-run does not execute binary version checks'], plan['limitations'])


if __name__ == '__main__':
    unittest.main()
