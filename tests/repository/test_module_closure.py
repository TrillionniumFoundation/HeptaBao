"""Machine checks for the per-module design and acceptance dossiers."""
from __future__ import annotations
import importlib.util
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
SPEC=importlib.util.spec_from_file_location('module_closure', ROOT/'scripts/validate_module_closure.py')
assert SPEC and SPEC.loader
MOD=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(MOD)
class ModuleClosureTests(unittest.TestCase):
    def test_all_workspace_modules_have_source_bound_dossiers(self):
        self.assertEqual(0, MOD.main())
    def test_registry_is_exactly_workspace(self):
        self.assertEqual(46, len(MOD.crates()))
if __name__=='__main__': unittest.main()
