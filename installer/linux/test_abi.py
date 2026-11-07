"""Regression checks for the release ABI gate."""

import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location('check_abi', Path(__file__).with_name('check-abi.py'))
abi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(abi)


class AbiChecks(unittest.TestCase):
    def check_symbols(self, *versions):
        return abi.requirements('\n'.join(f'0 DF *UND* 0 ({v}) symbol' for v in versions),
                                abi.BASELINES['debian12'])

    def test_numeric_maximum_and_unused_libraries(self):
        result = self.check_symbols('GLIBC_2.9', 'GLIBC_2.36', 'GCC_4.2.0')
        self.assertEqual(result['GLIBC'], '2.36')
        self.assertEqual(result['GLIBCXX'], 'none')

    def test_every_runtime_ceiling_is_enforced(self):
        for version in ('GLIBC_2.37', 'GLIBCXX_3.4.31', 'CXXABI_1.3.14', 'GCC_13.0.0'):
            with self.subTest(version=version), self.assertRaisesRegex(ValueError, 'exceeds baseline'):
                self.check_symbols(version)

    def test_unrecognised_abi_tags_fail_closed(self):
        with self.assertRaisesRegex(ValueError, 'unsupported symbol version'):
            self.check_symbols('GLIBC_ABI_DT_RELR')

    def test_defined_symbols_do_not_raise_the_requirement(self):
        result = abi.requirements('0 DF .text 0 GLIBC_2.99 symbol', abi.BASELINES['debian12'])
        self.assertEqual(result['GLIBC'], 'none')


if __name__ == '__main__':
    unittest.main()
