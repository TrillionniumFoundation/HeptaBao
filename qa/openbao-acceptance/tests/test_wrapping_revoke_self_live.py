"""Harness contract tests, not a replacement for native differential execution."""
from pathlib import Path
from types import SimpleNamespace
import json
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import core_isolation
import wrapping_revoke_self_live as wrapping


class Client:
    def __init__(self, responses):
        self.responses, self.calls = iter(responses), []

    def request(self, method, path, body=None, **kwargs):
        self.calls.append((method, path, body, kwargs))
        status, body = next(self.responses)
        return SimpleNamespace(status=status, body=body)


class WrappingSelfRevokeTests(unittest.TestCase):
    def tearDown(self):
        wrapping._RESTART_STATE.clear()

    def test_wrong_status_retains_failure_without_sensitive_body(self):
        rows = []
        client = Client([(403, {"secret": "synthetic-private-secret"})])
        with self.assertRaisesRegex(wrapping.ScenarioFailure, "wrapping270.revoke"):
            wrapping.Trace(client, rows).call("revoke", "POST", "auth/token/revoke-self", 204,
                                             {}, token="synthetic-private-token")
        self.assertEqual(rows, [{"case": "wrapping270.revoke", "status": 403, "passed": False}])
        self.assertNotIn("synthetic-private", json.dumps(rows))

    def test_creation_failure_never_claims_complete_or_allocates_restart_context(self):
        rows = []
        with self.assertRaises(wrapping.ScenarioFailure):
            wrapping.run_scenarios(Client([(503, {})]), rows)
        self.assertEqual(len(rows), 1)
        self.assertFalse(rows[0]["passed"])
        self.assertNotIn(id(rows), wrapping._RESTART_STATE)

    def test_restart_cannot_be_synthesized_without_original_context(self):
        with self.assertRaisesRegex(wrapping.ScenarioFailure, "restart_context_missing"):
            wrapping.run_after_restart(Client([]), [])

    def test_restart_reuses_exact_bearers_and_never_serializes_them(self):
        rows = []
        wrapping._RESTART_STATE[id(rows)] = {
            "revoked": ["synthetic-private-revoked"], "pending": "synthetic-private-pending",
            "peer": "synthetic-private-peer"}
        client = Client([(400, {}), (400, {}), (403, {}), (204, {}), (400, {}),
                         (200, {"data": {"synthetic": "independent-peer"}}), (200, {})])
        wrapping.run_after_restart(client, rows)
        self.assertNotIn(id(rows), wrapping._RESTART_STATE)
        self.assertEqual(client.calls[2][3]["token"], "synthetic-private-revoked")
        self.assertEqual(client.calls[3][3]["token"], "synthetic-private-pending")
        self.assertEqual(client.calls[5][3]["token"], "synthetic-private-peer")
        self.assertEqual(rows[-1], {"case": "wrapping270.complete", "passed": True})
        self.assertNotIn("synthetic-private", json.dumps(rows))
        self.assertEqual(len(rows), len({row["case"] for row in rows}))

    def test_wrong_peer_payload_cannot_pass_restart(self):
        rows = []
        wrapping._RESTART_STATE[id(rows)] = {"revoked": [], "pending": "pending", "peer": "peer"}
        client = Client([(204, {}), (400, {}), (200, {"data": {"wrong": "payload"}})])
        with self.assertRaisesRegex(wrapping.ScenarioFailure, "restart_peer_exact_payload"):
            wrapping.run_after_restart(client, rows)
        self.assertFalse(rows[-1]["passed"])
        self.assertFalse(any(row["case"] == "wrapping270.complete" for row in rows))

    def test_legacy_oracle_is_rejected_before_allocating_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            argv = ["wrapping270", "--binary", sys.executable, "--output", directory + "/report.json",
                    "--oracle-version", "2.6.2"]
            with patch.object(sys, "argv", argv), patch.object(core_isolation.tempfile, "mkdtemp") as allocate:
                with self.assertRaises(SystemExit) as error:
                    wrapping.main()
                self.assertEqual(error.exception.code, 2)
                allocate.assert_not_called()

    def test_current_oracle_default_reaches_fixture_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory).chmod(0o700)
            argv = ["wrapping270", "--binary", sys.executable, "--output", directory + "/report.json"]
            with patch.object(sys, "argv", argv), patch.object(core_isolation.tempfile, "mkdtemp",
                    side_effect=RuntimeError("correct-version-admitted")):
                with self.assertRaisesRegex(RuntimeError, "correct-version-admitted"):
                    wrapping.main()

    def test_equal_failed_prefixes_do_not_qualify(self):
        rows = [{"case": "wrapping270.revoke", "status": 403, "passed": False}]
        self.assertFalse(core_isolation.successful_comparison({"candidate": rows, "oracle": rows}, {}))


if __name__ == "__main__":
    unittest.main()
