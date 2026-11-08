import copy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from tools.vm.matrix.report import assess_files
from tools.vm.matrix.windows_proxy import make_plan, assess, validate_plan, COMPONENTS
from tools.vm.matrix.catalog import digest

ROOT = Path(__file__).resolve().parents[4]


class ProxyPolicyTests(unittest.TestCase):
    def test_plan_variants_and_digest(self):
        for use in (True, False):
            plan = make_plan('test', {'mode': 'exploratory'}, use)
            self.assertEqual(len(plan['catalog']), 46)
            self.assertEqual(len({r['id'] for r in plan['catalog']}), 46)
            self.assertEqual(sum(not r['required'] for r in plan['catalog']), 0 if use else 2)
            self.assertEqual(plan['catalog_digest'], digest(plan['catalog']))
            plan['catalog_digest'] = 'wrong'
            with self.assertRaises(ValueError): validate_plan(plan)


@unittest.skipUnless(shutil.which('pwsh'), 'PowerShell unavailable: producer integration skipped')
class ProxyProducerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / 'relative location' / 'run'
        self.directory.parent.mkdir()

    def produce(self, case='success'):
        result = subprocess.run(['pwsh', '-NoProfile', '-File', str(ROOT / 'tools/vm/windows/tests/Test-RosetunProxyResults.ps1'),
            '-Directory', 'run', '-Case', case], cwd=self.directory.parent, capture_output=True, text=True,
            encoding='utf-8', errors='replace', timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def load(self, name):
        return json.loads((self.directory / name).read_text(encoding='utf-8-sig'))

    def judge(self):
        return assess_files(self.directory / 'report.json', self.directory / 'plan.json')

    def test_cleanup_integration(self):
        result = subprocess.run(['pwsh', '-NoProfile', '-File', str(ROOT / 'tools/vm/windows/tests/Test-RosetunProxyCleanup.ps1')],
            capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn('SECRET', result.stdout + result.stderr)

    def test_full_variants_serialization(self):
        for case in ('success', 'no-host'):
            with self.subTest(case=case):
                self.directory = self.directory.parent / case
                # The producer resolves Directory through its PowerShell location.
                result = subprocess.run(['pwsh', '-NoProfile', '-File', str(ROOT / 'tools/vm/windows/tests/Test-RosetunProxyResults.ps1'),
                    '-Directory', case, '-Case', case, '-Location', str(self.directory.parent)], cwd=ROOT, capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                assessment = self.judge()
                self.assertTrue(assessment['acceptance']['accepted'], assessment)
                self.assertFalse(assessment['acceptance']['release'])
                self.assertEqual(assessment['invariant']['status'], 'UNVERIFIED')
                self.assertEqual(assessment['coverage'], 'complete' if case == 'success' else 'selected-variant')

    def test_windows_powershell_serialization(self):
        if not shutil.which('powershell'):
            self.skipTest('Windows PowerShell unavailable')
        result = subprocess.run(['powershell', '-NoProfile', '-File', str(ROOT / 'tools/vm/windows/tests/Test-RosetunProxyResults.ps1'),
            '-Directory', 'run', '-Location', str(self.directory.parent)], cwd=ROOT,
            capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(self.judge()['acceptance']['accepted'])

    def test_interruption_and_invalid_conditional_skip(self):
        self.produce('abort')
        value = self.judge()
        self.assertFalse(value['acceptance']['accepted'])
        self.assertEqual(value['execution']['status'], 'SKIP')
        self.assertTrue(any(r['execution'] == 'SKIP' for r in value['rows']))

    def test_fail_survives_abort_cleanup_and_export(self):
        for case in ('fail-abort', 'fail-cleanup', 'fail-export'):
            with self.subTest(case=case):
                self.directory = self.directory.parent / 'run'
                if self.directory.exists(): shutil.rmtree(self.directory)
                self.produce(case)
                value = self.judge()
                self.assertEqual(value['execution']['status'], 'FAIL', value)
                self.assertFalse(value['acceptance']['accepted'])
                for file in self.directory.glob('*.json*'):
                    if file.is_file(): self.assertNotIn('SECRET-EXCEPTION', file.read_text())

    def test_corrupt_artifacts_identities_skips_and_components(self):
        self.produce('fail')
        plan, report, status = (self.load(n) for n in ('plan.json', 'report.json', 'status.json'))
        events = [json.loads(s) for s in (self.directory / 'events.jsonl').read_text().splitlines()]
        cases = []
        for name in ('run_id', 'vm_id', 'boot_id'):
            r = copy.deepcopy(report); r['identity'][name] = 'foreign'; cases.append((r, status, events))
        r = copy.deepcopy(report); r['boot_id_at_end'] = 'foreign'; cases.append((r,status,events))
        for component in COMPONENTS:
            for state in ('ERROR', 'UNVERIFIED'):
                r = copy.deepcopy(report); r['cleanup']['components'][component] = state; cases.append((r,status,events))
        e = copy.deepcopy(events); e[1].update(result='SKIP', reason='host-node-disabled'); cases.append((report,status,e))
        e = copy.deepcopy(events); e[1]['run_id'] = 'foreign'; cases.append((report,status,e))
        e = copy.deepcopy(events); e[1]['sequence'] = True; cases.append((report,status,e))
        e = copy.deepcopy(events); e[1]['sequence'] = 1; cases.append((report,status,e))
        e = copy.deepcopy(events); e[1]['id'] = e[0]['id']; cases.append((report,status,e))
        cases.extend([(None,status,events), (report,None,events), (report,{},events), (report,status,events[:25])])
        for r,s,e in cases:
            value = assess(r,s,e,plan)
            self.assertEqual(value['execution']['status'], 'FAIL')
            self.assertFalse(value['acceptance']['accepted'])
            self.assertEqual(value['validation']['status'], 'ERROR')
        bad_plan = copy.deepcopy(plan); bad_plan['catalog_digest'] = 'wrong'
        self.assertEqual(assess(report,status,events,bad_plan)['execution']['status'], 'FAIL')
        (self.directory / 'status.json').unlink()
        self.assertFalse(self.judge()['acceptance']['accepted'])
        (self.directory / 'status.json').write_text('{broken')
        self.assertFalse(self.judge()['acceptance']['accepted'])
