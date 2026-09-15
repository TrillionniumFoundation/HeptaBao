"""Mutation tests: requirements never manufacture runtime or acceptance facts."""
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('replacement_execution', ROOT/'scripts/validate_replacement_execution.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ReplacementExecutionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.matrix = module.load(ROOT/module.MATRIX)
        paths = {module.MATRIX, module.CORPUS, module.GUIDE,
                 'oracle/inventory/openbao-v2.6.2/surface-catalog.yaml'}
        for row in self.matrix['surfaces']:
            for key in ('runtime_sources', 'contract_sources', 'guides', 'executable_profiles'):
                paths.update(row[key])
        for name in paths:
            dest = self.root/name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT/name, dest)

    def save(self):
        (self.root/module.MATRIX).write_text(json.dumps(self.matrix))

    def check(self):
        self.save()
        return module.validate(self.root, check_render=False)

    def test_current_exact_sixty_rows_match(self):
        self.assertEqual(module.validate(self.root), [])
        self.assertEqual(len(self.matrix['surfaces']), 60)

    def test_missing_and_duplicate_surfaces_rejected(self):
        original = copy.deepcopy(self.matrix)
        self.matrix['surfaces'].pop()
        self.assertTrue(self.check())
        self.matrix = original
        self.matrix['surfaces'][-1] = self.matrix['surfaces'][0]
        self.assertTrue(self.check())

    def test_runtime_requires_real_entry_not_a_label(self):
        self.matrix['surfaces'][0]['runtime_sources'] = []
        self.assertTrue(self.check())

    def test_requirements_cannot_self_admit(self):
        for value in (True, 0, None, 'false'):
            with self.subTest(value=value):
                self.matrix['surfaces'][0]['independently_admitted'] = value
                self.assertTrue(self.check())

    def test_missing_hostile_or_lifecycle_not_substantive(self):
        self.matrix['surfaces'][0]['hostile'] = 'TODO'
        self.assertTrue(self.check())

    def test_category_drift_rejected(self):
        self.matrix['surfaces'][0]['category'] = 'unrelated'
        self.assertTrue(self.check())

    def test_work_package_cannot_be_silently_reassigned(self):
        self.matrix['surfaces'][0]['owner_work_packages'] = ['INVENTED']
        self.assertTrue(self.check())

    def test_reference_cannot_be_rebound(self):
        self.matrix['surfaces'][0]['public_baseline_reference'] = 'public-docs://invented'
        self.assertTrue(self.check())

    def test_missing_dimension_rejected(self):
        self.matrix['acceptance_axes'].pop('crash_replay')
        self.assertTrue(self.check())

    def test_source_escape_and_missing_file_rejected(self):
        for path in ('../outside.rs', '/etc/passwd', 'crates/missing.rs'):
            with self.subTest(path=path):
                self.matrix['surfaces'][0]['runtime_sources'] = [path]
                self.assertTrue(self.check())

    def test_unknown_state_rejected(self):
        self.matrix['surfaces'][0]['implementation'] = 'FULLY_COMPLETE'
        self.assertTrue(self.check())

    def test_render_drift_rejected_without_repair(self):
        path = self.root/module.GUIDE
        path.write_text('stale projection')
        self.assertTrue(module.validate(self.root))
        self.assertEqual(path.read_text(), 'stale projection')

    def test_duplicate_json_member_rejected(self):
        path = self.root/module.MATRIX
        path.write_text('{"schema":"one","schema":"two"}')
        self.assertTrue(module.validate(self.root))

    def test_symlink_source_rejected(self):
        name = self.matrix['surfaces'][0]['runtime_sources'][0]
        path = self.root/name
        path.unlink()
        try:
            path.symlink_to(ROOT/name)
        except OSError:
            self.skipTest('symlink unavailable')
        self.assertTrue(module.validate(self.root))
