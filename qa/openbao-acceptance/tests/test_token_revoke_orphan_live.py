"""Harness integrity checks; the native comparison remains independently required."""
from pathlib import Path
from types import SimpleNamespace
import json
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import core_isolation
import token_revoke_orphan_live as profile


class FakeClient:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = []

    def request(self, method, path, body=None, **kwargs):
        self.calls.append((method, path, body, kwargs))
        status, body = next(self.responses)
        return SimpleNamespace(status=status, body=body)


class OrphanProfileTests(unittest.TestCase):
    def tearDown(self):
        profile._CONTEXT.clear()

    def test_failed_status_keeps_safe_failure_row(self):
        rows = []
        client = FakeClient([(404, {"data": "synthetic-private-response"})])
        with self.assertRaisesRegex(profile.ScenarioFailure, "orphan270.discard"):
            profile.Trace(client, rows).call("discard", "POST", "auth/token/revoke-orphan", 204,
                                             {"token": "synthetic-private-bearer"})
        self.assertEqual(rows, [{"case": "orphan270.discard", "status": 404, "passed": False}])
        self.assertNotIn("synthetic-private", json.dumps(rows))

    def test_wrong_parent_edge_never_qualifies(self):
        rows = []
        client = FakeClient([(200, {"data": {"orphan": False}})])
        with self.assertRaisesRegex(profile.ScenarioFailure, "parent_binding"):
            profile.Trace(client, rows).live("child", "synthetic-test-only", True)
        self.assertFalse(rows[-1]["passed"])

    def test_missing_restart_context_is_not_an_empty_pass(self):
        with self.assertRaisesRegex(profile.ScenarioFailure, "restart_context_missing"):
            profile.run_after_restart(FakeClient([]), [])

    def test_equal_failed_prefixes_remain_failed(self):
        rows = [{"case": "orphan270.discard", "status": 404, "passed": False}]
        self.assertFalse(core_isolation.successful_comparison({"candidate": rows, "oracle": rows}, {}))

    def test_historical_oracle_rejected_before_fixture_allocation(self):
        with tempfile.TemporaryDirectory() as directory:
            argv = ["orphan270", "--binary", sys.executable, "--output", directory + "/report.json",
                    "--oracle-version", "2.6.2"]
            with patch.object(sys, "argv", argv), patch.object(core_isolation.tempfile, "mkdtemp") as allocate:
                with self.assertRaises(SystemExit) as error:
                    profile.main()
                self.assertEqual(error.exception.code, 2)
                allocate.assert_not_called()


if __name__ == "__main__":
    unittest.main()
