from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

SPEC = importlib.util.spec_from_file_location(
    "validate_dependency_execution_profiles_v1",
    SCRIPTS / "validate_dependency_execution_profiles_v1.py",
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class DependencyExecutionProfileTests(unittest.TestCase):
    def test_four_profiles_are_specified_and_unexecuted(self):
        self.assertEqual(MODULE.validate(), 4)

    def test_main_returns_success(self):
        self.assertEqual(MODULE.main(), 0)


if __name__ == "__main__":
    unittest.main()
