import copy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools.vm.matrix.config import validate_plan as validate_foundation_plan
from tools.vm.matrix.report import assess_files
from tools.vm.matrix.windows_list import assess, make_plan, validate_plan

ROOT = Path(__file__).resolve().parents[4]
PRODUCER = ROOT / 'tools/vm/windows/tests/Test-RosetunListResults.ps1'


@unittest.skipUnless(shutil.which('pwsh'), 'PowerShell 7 required for serialization integration')
class WindowsListTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / 'run'

    def produce(self, case='success'):
        result = subprocess.run(['pwsh', '-NoProfile', '-File', str(PRODUCER),
                                 '-Directory', str(self.directory), '-Case', case],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def judge(self):
        return assess_files(self.directory / 'report.json', self.directory / 'plan.json')

    def load(self, name):
        return json.loads((self.directory / name).read_text(encoding='utf-8-sig'))

    def save(self, name, value):
        (self.directory / name).write_text(json.dumps(value), encoding='utf-8')

    def test_real_helper_serialization_and_snapshot_independence(self):
        self.produce()
        with patch('tools.vm.matrix.config.read_catalog', side_effect=AssertionError), \
             patch('tools.vm.matrix.windows_list.ROOT', Path('missing-current-catalog')):
            result = self.judge()
        self.assertTrue(result['acceptance']['accepted'], result)
        self.assertFalse(result['acceptance']['release'])
        self.assertEqual(result['invariant']['status'], 'UNVERIFIED')
        self.assertEqual(result['execution']['counts']['PASS'], 11)
        cli = subprocess.run(['python', '-B', '-m', 'tools.vm.matrix', 'report',
                              str(self.directory / 'report.json'), '--plan', str(self.directory / 'plan.json')],
                             cwd=ROOT, capture_output=True, text=True, timeout=30)
        self.assertEqual(cli.returncode, 0, cli.stdout + cli.stderr)
        plan = self.load('plan.json')
        plan['policy']['mode'] = 'release'
        self.save('plan.json', plan)
        self.assertFalse(self.judge()['acceptance']['accepted'])

    def test_failure_abort_srs_cleanup_and_fail_preservation(self):
        for case in ('fail', 'abort', 'srs', 'cleanup', 'fail-abort'):
            with self.subTest(case=case):
                self.directory = Path(self.temp.name) / case
                self.produce(case)
                result = self.judge()
                self.assertFalse(result['acceptance']['accepted'])
                if case in ('fail', 'srs', 'fail-abort'):
                    self.assertEqual(result['execution']['status'], 'FAIL')
                    self.assertEqual(result['execution']['counts']['FAIL'], 1)
                self.assertNotIn('private diagnostic marker', (self.directory / 'report.json').read_text())
                self.assertNotIn('private diagnostic marker', (self.directory / 'events.jsonl').read_text())
                if case == 'srs':
                    self.assertEqual(result['execution']['counts']['SKIP'], 4)
                if case == 'fail':
                    self.assertEqual(result['validation']['status'], 'PASS')

    def test_write_failure_and_directory_reuse(self):
        for case in ('write', 'reuse'):
            self.directory = Path(self.temp.name) / case
            self.produce(case)
            self.assertFalse((self.directory / 'status.json').exists())
            self.assertFalse(self.judge()['acceptance']['accepted'])

    def test_identity_schema_completion_and_summary(self):
        self.produce()
        for name in ('report.json', 'status.json'):
            original = self.load(name)
            for field in ('run_id', 'vm_id', 'boot_id'):
                bad = copy.deepcopy(original)
                bad['identity'][field] = 'foreign'
                self.save(name, bad)
                self.assertFalse(self.judge()['acceptance']['accepted'])
            for value in (None, [], {}, {'schema': True}):
                self.save(name, value)
                self.assertFalse(self.judge()['acceptance']['accepted'])
            self.save(name, original)
        original = self.load('report.json')
        bad = copy.deepcopy(original); bad['summary']['total'] = True
        self.save('report.json', bad)
        self.assertFalse(self.judge()['acceptance']['accepted'])
        self.save('report.json', original)
        (self.directory / 'status.json').unlink()
        self.assertFalse(self.judge()['acceptance']['accepted'])

    def test_invalid_events_keep_observed_failures(self):
        self.produce('fail')
        path = self.directory / 'events.jsonl'
        original = path.read_text(encoding='utf-8-sig')
        events = [json.loads(line) for line in original.splitlines()]
        cases = [original + '{', original + '{}\n', original.rstrip('\n'),
                 original + '{"x":1,"x":2}\n', original + '{"x":NaN}\n']
        for mutation in ('missing', 'unknown', 'duplicate', 'sequence', 'run', 'type'):
            changed = copy.deepcopy(events)
            if mutation == 'missing': changed.pop()
            if mutation == 'unknown': changed[-1]['id'] = 'unknown'
            if mutation == 'duplicate': changed[-1]['id'] = changed[0]['id']
            if mutation == 'sequence': changed[-1]['sequence'] = True
            if mutation == 'run': changed[-1]['run_id'] = 'foreign'
            if mutation == 'type': changed[-1]['result'] = []
            cases.append(''.join(json.dumps(e) + '\n' for e in changed))
        for content in cases:
            path.write_text(content, encoding='utf-8')
            result = self.judge()
            self.assertFalse(result['acceptance']['accepted'])
            self.assertEqual(result['execution']['status'], 'FAIL')
        path.write_text(original, encoding='utf-8')
        path.write_bytes(original.encode('utf-8') + b'\xff')
        self.assertEqual(self.judge()['execution']['status'], 'FAIL')
        path.unlink()
        self.assertEqual(self.judge()['execution']['status'], 'FAIL')
        path.write_text(original, encoding='utf-8')
        self.save('report.json', None)
        self.assertEqual(self.judge()['execution']['status'], 'FAIL')


class WindowsPlanTests(unittest.TestCase):
    def test_unbound_plan_is_inspectable_but_cannot_accept(self):
        plan = make_plan('test', {'mode': 'exploratory'})
        validate_plan(plan)
        validate_foundation_plan(plan)
        self.assertEqual(len(plan['catalog']), 11)
        self.assertFalse(assess({}, {}, [], plan)['acceptance']['accepted'])

    def test_source_has_each_catalog_id_once_in_order(self):
        import re
        source = (ROOT / 'tools/vm/windows/Invoke-ListMatrix.ps1').read_text()
        ids = re.findall(r"Test-Step '[^']+' '[^']+' -Id '([^']+)'", source)
        self.assertEqual(ids, [r['id'] for r in make_plan('test', {'mode': 'exploratory'})['catalog']])

    def test_invalid_windows_plan_fields_and_identity_types(self):
        plan = make_plan('test', {'mode': 'exploratory'})
        for field, value in (('schema', 1), ('identity', {}), ('identity', {'run_id': [], 'vm_id': 'v', 'boot_id': 'b'}),
                             ('policy', {'mode': 'invalid'}), ('catalog', []), ('profile', True)):
            bad = copy.deepcopy(plan)
            bad[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_plan(bad)
        with self.assertRaises(ValueError):
            make_plan('test', {'mode': 'exploratory', 'run_id': 'r', 'boot_id': 'b'})
