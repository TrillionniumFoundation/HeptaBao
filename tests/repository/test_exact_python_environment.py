import importlib.util
import importlib.metadata
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('python_environment', ROOT/'scripts/verify_python_environment.py')
module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


class ExactPythonEnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'requirements.txt'

    def pins(self, value):
        self.path.write_text(value)
        return self.path

    def test_exact_versions_are_observed_without_claiming_transitive_lock(self):
        result=module.inspect(self.pins('PyYAML==6.0.2\njsonschema==4.23.0 # fixed\n'),
                              {'pyyaml':'6.0.2','jsonschema':'4.23.0'}.__getitem__)
        self.assertTrue(result['exact_direct_pins'])
        self.assertFalse(result['transitive_dependency_lock'])
        self.assertFalse(result['qualification'])

    def test_newer_version_is_not_exact(self):
        result=module.inspect(self.pins('PyYAML==6.0.2\n'), lambda _: '6.0.3')
        self.assertFalse(result['exact_direct_pins'])

    def test_absent_package_is_blocked(self):
        def absent(_):raise importlib.metadata.PackageNotFoundError
        result=module.inspect(self.pins('PyYAML==6.0.2\n'), absent)
        self.assertFalse(result['exact_direct_pins'])
        self.assertIsNone(result['installed']['pyyaml'])

    def test_empty_requirements_do_not_vacuously_pass(self):
        with self.assertRaises(ValueError):module.required(self.pins('# empty\n'))

    def test_ambient_index_and_loose_ranges_reject(self):
        for line in ['pkg>=1.0','--index-url https://example.invalid','pkg==1.0; sys_platform=="linux"','pkg @ https://example.invalid']:
            with self.subTest(line=line),self.assertRaises(ValueError):module.required(self.pins(line))

    def test_normalized_duplicate_is_rejected(self):
        with self.assertRaises(ValueError):module.required(self.pins('some_pkg==1.0\nsome-pkg==1.0\n'))

    def test_workflow_checks_exact_environment_before_native_tests(self):
        text=(ROOT/'.github/workflows/codex-openbao-replacement-ci.yml').read_text()
        self.assertIn('python scripts/verify_python_environment.py',text)
        self.assertLess(text.index('python scripts/verify_python_environment.py'),text.index('cargo +1.98.0 test'))
