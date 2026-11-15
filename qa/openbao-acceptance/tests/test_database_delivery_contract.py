"""Verdict tests only: mocked outcomes do not execute or qualify a provider."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import database_delivery_live as target


class DatabaseDeliveryVerdictTests(unittest.TestCase):
    def execute(self, cases=("one", "two"), outcome=None, identities=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "synthetic-binary"
            binary.write_bytes(b"not-executable; verdict-test-only")
            outcome = outcome or (lambda _b, _r, case: {"case": case, "passed": True})
            with patch.object(target, "CASES", cases), patch.object(target, "check_case", side_effect=outcome):
                with patch.object(target, "source_identity", side_effect=identities or [{"head": "same"}, {"head": "same"}]):
                    with patch("builtins.print"):
                        status = target.run(binary, root / "report")
            return status, json.loads((root / "report/summary.json").read_text())

    def test_success_requires_all_named_cases_and_unchanged_identity(self):
        status, report = self.execute()
        self.assertEqual(status, 0)
        self.assertEqual([row["case"] for row in report["cases"]], ["one", "two"])
        self.assertFalse(report["independent_qualification"])
        self.assertFalse(report["full_openbao_compatibility"])
        self.assertFalse(report["native_database_provider"])

    def test_one_failed_case_cannot_be_masked_by_other_success(self):
        status, report = self.execute(outcome=lambda _b, _r, case: {"case": case, "passed": case != "two"})
        self.assertEqual(status, 1)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(len(report["cases"]), 2)

    def test_empty_and_duplicate_case_sets_are_rejected(self):
        for cases in ((), ("same", "same")):
            with self.subTest(cases=cases):
                self.assertEqual(self.execute(cases=cases)[0], 1)

    def test_source_change_invalidates_all_successful_observations(self):
        status, report = self.execute(identities=[{"head": "before"}, {"head": "after"}])
        self.assertEqual(status, 1)
        self.assertFalse(report["source_binary_and_runner_unchanged"])

    def test_exception_details_do_not_leak_into_report(self):
        def fail(*_):
            raise ValueError("synthetic-sensitive-provider-output")
        status, report = self.execute(outcome=fail)
        self.assertEqual(status, 1)
        self.assertNotIn("synthetic-sensitive-provider-output", json.dumps(report))
        self.assertEqual({row["safe_failure_code"] for row in report["cases"]}, {"ValueError"})
