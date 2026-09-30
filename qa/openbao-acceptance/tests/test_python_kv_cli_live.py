"""Check fixed CLI evidence scope and secret-free receipt projection."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

QA = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(QA))
spec = importlib.util.spec_from_file_location("python_kv_cli_live", QA / "python_kv_cli_live.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class PythonKVCLIEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.instance = {"root": str(self.root), "address": "https://localhost:8200", "ca_file": "unused.crt", "token": "synthetic-proof-bearer"}

    def completed(self, case, arguments):
        failures = {"v1_missing", "v2_stale_cas", "metadata_missing"}
        if case in failures:
            return subprocess.CompletedProcess(arguments, 2, b"", b"fixed API diagnostic")
        values = {"v2_create": 1, "v2_replace": 2, "v2_patch": 3, "v2_remove": 4, "v2_rw_patch": 5, "v2_rollback": 6}
        if case in ("v1_get", "v2_field", "v2_history", "v2_restored"):
            stdout = b'"synthetic-cli-requested-value"'
        elif case in ("v1_list", "v2_list"):
            stdout = b'["key"]'
        elif case in values:
            stdout = json.dumps({"data": {"version": values[case]}}).encode()
        elif case in ("v2_deleted", "v2_destroyed"):
            stdout = json.dumps({"data": {"data": None, "metadata": {"destroyed": case == "v2_destroyed"}}}).encode()
        elif case == "v2_read":
            stdout = b'{"data":{"data":{"value":"second","keep":"yes"}}}'
        elif case == "metadata_get":
            stdout = b'{"data":{"current_version":6,"max_versions":9,"custom_metadata":{"team":"test"}}}'
        else:
            # Success without data need not be JSON; official v1 output uses a
            # success message even when format=json was requested.
            stdout = b"Success!"
        return subprocess.CompletedProcess(arguments, 0, stdout, b"")

    def execute(self, kind, corrupt=None):
        operations = iter(runner.OPERATIONS)
        def actual(arguments, **kwargs):
            case = next(operations)
            result = self.completed(case, arguments)
            return corrupt(case, result) if corrupt else result
        rows = []
        with patch.object(runner.subprocess, "run", side_effect=actual):
            runner.run_interface(kind, self.instance, self.root, Path("/pinned/bao"), rows)
        return rows

    def test_fixed_denominator_complete_trace_and_positive_values_never_in_rows(self):
        rows = self.execute("python")
        self.assertEqual(len(rows), 68)
        self.assertEqual(len(set(runner.REQUIRED_INTERFACE_CASES)), 68)
        self.assertEqual({row["case"] for row in rows}, set(runner.REQUIRED_INTERFACE_CASES))
        self.assertTrue(all(row["passed"] is True for row in rows))
        serialized = json.dumps(rows)
        for value in ("synthetic-proof-bearer", "synthetic-cli-requested-value", str(self.root)):
            self.assertNotIn(value, serialized)

    def test_matching_failed_prefix_cannot_qualify_interface(self):
        def bad(case, result):
            if case == "v2_stale_cas":
                result.returncode = 0
            return result
        with self.assertRaisesRegex(runner.ScenarioFailure, "v2_stale_cas_exit"):
            self.execute("python", bad)

    def test_fixed_trace_exercises_both_positive_patch_cas_and_zero_patch_cas(self):
        operations = iter(runner.OPERATIONS)
        observed = {}
        def actual(arguments, **kwargs):
            case = next(operations)
            observed[case] = arguments
            return self.completed(case, arguments)
        with patch.object(runner.subprocess, "run", side_effect=actual):
            runner.run_interface("python", self.instance, self.root, Path("/pinned/bao"), [])
        self.assertIn("-cas=2", observed["v2_patch"])
        self.assertIn("-method=patch", observed["v2_remove"])
        self.assertIn("-cas=0", observed["v2_remove"])

    def test_bearer_in_positive_stdout_is_refused_even_when_value_was_requested(self):
        def bad(case, result):
            if case == "v1_get":
                result.stdout += b"synthetic-proof-bearer"
            return result
        with self.assertRaisesRegex(runner.ScenarioFailure, "v1_get_safe_errors"):
            self.execute("python", bad)

    def test_private_error_body_is_never_evidence_and_rejected_when_it_contains_synthetic_value(self):
        def bad(case, result):
            if case == "v1_missing":
                result.stderr += b"synthetic-cli-requested-value"
            return result
        with self.assertRaisesRegex(runner.ScenarioFailure, "v1_missing_safe_errors"):
            self.execute("bao", bad)


if __name__ == "__main__":
    unittest.main()
