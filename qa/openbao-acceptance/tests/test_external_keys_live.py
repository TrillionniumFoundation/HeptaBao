"""Trace-integrity checks; native TLS comparison is a separate mandatory lane."""
import copy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import core_isolation
import external_keys_live as external


class Client:
    namespace = "original"
    def __init__(self, status=200, body=None):
        self.status, self.body, self.calls = status, body or {}, []
    def request(self, method, path, body=None, **kwargs):
        self.calls.append((self.namespace, method, path, body, kwargs))
        return SimpleNamespace(status=self.status, body=self.body)


class ExternalKeysTests(unittest.TestCase):
    def tearDown(self):
        external._RESTART_STATE.clear()

    def test_failed_status_does_not_publish_request_or_response(self):
        client = Client(403, {"token": "private-canary"})
        rows = []
        with self.assertRaisesRegex(external.ScenarioFailure, "externalkeys270.write"):
            external.Trace(client, rows).call("write", "POST", external.CONFIG, 204,
                {"token": "private-canary"}, token="private-bearer")
        self.assertEqual(rows, [{"case": "externalkeys270.write", "status": 403, "passed": False}])
        self.assertNotIn("private-", json.dumps(rows))

    def test_success_status_with_secret_instead_of_redaction_fails(self):
        rows = []
        with self.assertRaises(external.ScenarioFailure):
            external.Trace(Client(200, {"data": {"token": "private-canary"}}), rows).call(
                "read", "GET", external.CONFIG, 200, data={"token": "(redacted)"})
        self.assertFalse(rows[0]["passed"])
        self.assertNotIn("private-", json.dumps(rows))

    def test_namespace_and_patch_transport_are_explicit(self):
        client = Client(204)
        external.Trace(client, []).call("patch", "PATCH", external.CONFIG, 204,
            {"verify": False}, namespace="team")
        self.assertEqual(client.namespace, "original")
        self.assertEqual(client.calls[0][0], "team")
        self.assertEqual(client.calls[0][4]["content_type"], "application/merge-patch+json")

    def test_missing_restart_context_is_rejected(self):
        with self.assertRaisesRegex(external.ScenarioFailure, "restart_context_missing"):
            external.run_after_restart(Client(), [])

    def test_fixed_denominator_rejects_partial_duplicate_and_reordered_success(self):
        names = external.PRE_CASES + external.RESTART_CASES
        self.assertEqual(len(names), 62)
        self.assertEqual(len(names), len(set(names)))
        rows = [{"case": name, "passed": True} for name in names]
        external.require_sequence(rows, names)
        for bad in (rows[:-1], rows + rows[-1:], rows[::-1]):
            with self.assertRaises(external.ScenarioFailure):
                external.require_sequence(bad, names)

    def test_equal_failed_prefixes_are_not_a_comparison_pass(self):
        rows = [{"case": "externalkeys270.empty", "passed": False, "status": 503}]
        self.assertFalse(core_isolation.successful_comparison({"candidate": rows, "oracle": rows}, {}))

    def test_wrong_version_is_rejected_before_any_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            argv = ["externalkeys", "--binary", sys.executable, "--output", directory + "/result.json",
                    "--oracle-version", "2.6.2"]
            with patch.object(sys, "argv", argv), patch.object(core_isolation.tempfile, "mkdtemp") as allocate:
                with self.assertRaises(SystemExit) as error:
                    external.main()
                self.assertEqual(error.exception.code, 2)
                allocate.assert_not_called()

    def test_current_default_reaches_fixture_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory).chmod(0o700)
            argv = ["externalkeys", "--binary", sys.executable, "--output", directory + "/result.json"]
            with patch.object(sys, "argv", argv), patch.object(core_isolation.tempfile, "mkdtemp",
                    side_effect=RuntimeError("selected-270")):
                with self.assertRaisesRegex(RuntimeError, "selected-270"):
                    external.main()


if __name__ == "__main__":
    unittest.main()
