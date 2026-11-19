import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from l2_test_artifacts import required_tests, select_artifact, validate_harness


def artifact(path, test, kind='bin', name='rosetun-helper-privileged'):
    return json.dumps({'reason': 'compiler-artifact', 'executable': path,
                       'target': {'name': name, 'kind': [kind], 'test': True},
                       'profile': {'test': test}})


class ArtifactTests(unittest.TestCase):
    def test_production_binary_after_harness_is_never_selected(self):
        lines = [artifact('/build/tests', True), artifact('/build/service', False)]
        for order in [lines, list(reversed(lines))]:
            self.assertEqual(select_artifact(order, 'bin', 'rosetun-helper-privileged'), Path('/build/tests'))

    def test_target_test_flag_cannot_substitute_for_test_profile(self):
        with self.assertRaisesRegex(ValueError, 'found 0'):
            select_artifact([artifact('/build/service', False)], 'bin', 'rosetun-helper-privileged')

    def test_different_harnesses_are_ambiguous_but_repeated_message_is_not(self):
        line = artifact('/build/tests', True)
        self.assertEqual(select_artifact([line, line], 'bin', 'rosetun-helper-privileged'), Path('/build/tests'))
        with self.assertRaisesRegex(ValueError, 'found 2'):
            select_artifact([line, artifact('/other/tests', True)], 'bin', 'rosetun-helper-privileged')

    def test_wrong_target_and_null_executable_are_refused(self):
        for line in [artifact(None, True), artifact('/build/tests', True, 'test'),
                     artifact('/build/tests', True, name='another')]:
            with self.assertRaises(ValueError):
                select_artifact([line], 'bin', 'rosetun-helper-privileged')

    def test_real_scenario_catalog_has_five_required_tests_for_each_harness(self):
        scenarios = Path(__file__).resolve().parents[1] / 'scenarios.tsv'
        for group in ['unit_helper', 'unit_ipc']:
            with scenarios.open(encoding='utf-8') as stream:
                self.assertEqual(len(required_tests(stream, group)), 5)
        with self.assertRaises(ValueError):
            required_tests(io.StringIO(''), 'unit_helper')

    def test_listing_requires_exact_names_not_substring_matches(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'tests'
            binary.touch()
            with patch('l2_test_artifacts.subprocess.run') as run:
                run.return_value = subprocess.CompletedProcess([], 0, 'module::expected: test\n', '')
                validate_harness(binary, {'module::expected'})
                self.assertEqual(run.call_args.args[0], [str(binary), '--list', '--format', 'terse'])
                run.return_value = subprocess.CompletedProcess([], 0, 'prefix::module::expected: test\n', '')
                with self.assertRaisesRegex(ValueError, 'lacks required'):
                    validate_harness(binary, {'module::expected'})

    def test_usage_error_empty_listing_and_timeout_stop_packaging(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'service'
            binary.touch()
            with patch('l2_test_artifacts.subprocess.run') as run:
                run.return_value = subprocess.CompletedProcess([], 2, '', 'usage: helper')
                with self.assertRaisesRegex(ValueError, 'exit 2'):
                    validate_harness(binary, {'expected'})
                run.return_value = subprocess.CompletedProcess([], 0, '', '')
                with self.assertRaisesRegex(ValueError, 'lacks required'):
                    validate_harness(binary, {'expected'})
                run.side_effect = subprocess.TimeoutExpired([], 30)
                with self.assertRaises(subprocess.TimeoutExpired):
                    validate_harness(binary, {'expected'})


if __name__ == '__main__':
    unittest.main()
