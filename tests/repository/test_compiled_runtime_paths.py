"""Source inventories cannot replace compiled module/test discovery."""
from pathlib import Path
import importlib.util
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('compiled_runtime', ROOT / 'scripts/verify_compiled_runtime_paths.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

class CompiledRuntimePathsTests(unittest.TestCase):
    def test_complete_linux_discovery(self):
        output = '\n'.join(name + ': test' for name in MODULE.SERVER_TESTS | MODULE.PROXY_TESTS)
        self.assertEqual([], MODULE.missing_tests(output, True))

    def test_missing_module_is_not_covered_by_source_count(self):
        output = 'source_inventory: 46 modules\ntests: 500\n'
        self.assertEqual(sorted(MODULE.SERVER_TESTS | MODULE.PROXY_TESTS), MODULE.missing_tests(output, True))

    def test_one_missing_runtime_regression_fails(self):
        required = MODULE.SERVER_TESTS | MODULE.PROXY_TESTS
        omitted = sorted(required)[0]
        output = '\n'.join(name + ': test' for name in required if name != omitted)
        self.assertEqual([omitted], MODULE.missing_tests(output, True))

    def test_nonlinux_is_not_misreported_as_linux_runtime(self):
        output = '\n'.join(name + ': test' for name in MODULE.SERVER_TESTS)
        self.assertEqual([], MODULE.missing_tests(output, False))
        self.assertEqual(sorted(MODULE.PROXY_TESTS), MODULE.missing_tests(output, True))

if __name__ == '__main__':
    unittest.main()
