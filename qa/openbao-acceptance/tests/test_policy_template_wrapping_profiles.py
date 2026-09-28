"""Verdict/transport-shape tests only; these are not product qualification."""
from pathlib import Path
from types import SimpleNamespace
import json
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import core_isolation
import policy_templates_live as templates
import policy_wrapping_ttl_live as wrapping


class Client:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = []

    def request(self, method, path, body=None, token=None, wrap_ttl=None):
        self.calls.append((method, path, body, token, wrap_ttl))
        status, response = next(self.responses)
        return SimpleNamespace(status=status, body=response)


class IdentityTemplateHarnessTests(unittest.TestCase):
    def test_trace_records_status_and_equality_not_secret_payloads(self):
        rows = []
        trace = templates.Trace(None, rows)
        secret = {"data": {"key": "synthetic-private-value"}, "auth": {"client_token": "synthetic-private-token"}}
        trace.check("safe", SimpleNamespace(status=200, body=secret), 200, secret["data"])
        self.assertEqual(rows, [{"case": "acl_templates.safe", "status": 200, "passed": True, "data_matches": True}])
        self.assertNotIn("synthetic-private", json.dumps(rows))

    def test_wrong_status_or_payload_preserves_failed_observation(self):
        for response in [SimpleNamespace(status=403, body={}), SimpleNamespace(status=200, body={"data": {"wrong": True}})]:
            rows = []
            with self.assertRaisesRegex(templates.ScenarioFailure, "acl_templates.mismatch"):
                templates.Trace(None, rows).check("mismatch", response, 200, {"expected": True})
            self.assertEqual(len(rows), 1)
            self.assertIs(rows[0]["passed"], False)
            self.assertNotIn("complete", rows[0]["case"])

    def test_restart_requires_original_context(self):
        rows = []
        with self.assertRaisesRegex(templates.ScenarioFailure, "restart_context_missing"):
            templates.run_after_restart(Client([]), rows)
        self.assertEqual(rows, [])

    def test_restart_uses_original_tokens_and_checks_revocation_before_completion(self):
        rows = []
        templates._RESTART_STATE[id(rows)] = {
            "token": "synthetic-service", "batch": "synthetic-batch",
            "entity_path": "identity/entity/id/synthetic-entity", "own": "acl-template/entity/synthetic-entity/item",
            "group_path": "acl-template/group-id/synthetic-group/item",
        }
        payload = {"data": {"synthetic": "original"}}
        client = Client([(200, payload), (200, payload), (403, {}), (200, payload),
                         (403, {}), (403, {}), (204, {}), (403, {}), (403, {})])
        templates.run_after_restart(client, rows)
        self.assertNotIn(id(rows), templates._RESTART_STATE)
        self.assertEqual(rows[-1], {"case": "acl_templates.complete", "passed": True})
        self.assertEqual(len(rows), 10)
        self.assertEqual([call[3] for call in client.calls[:2]], ["synthetic-service", "synthetic-batch"])
        self.assertTrue(all(row["passed"] is True for row in rows))
        self.assertEqual(len({row["case"] for row in rows}), len(rows))
        self.assertNotIn("synthetic-service", json.dumps(rows))
        self.assertNotIn("synthetic-batch", json.dumps(rows))

    def test_failure_at_first_runtime_boundary_cannot_make_complete_trace(self):
        rows = []
        with self.assertRaisesRegex(templates.ScenarioFailure, "acl_templates.mount_kv"):
            templates.run_scenarios(Client([(403, {})]), rows)
        self.assertEqual(rows, [{"case": "acl_templates.mount_kv", "status": 403, "passed": False}])


class WrappingTTLProfileTests(unittest.TestCase):
    def test_native_absent_zero_and_boundary_table(self):
        ttls = [None, "0", "9", "10", "20", "30", "31"]
        expected = {
            "min": [403, 403, 403, 200, 200, 200, 200],
            "max": [403, 200, 200, 200, 200, 200, 403],
            "range": [403, 403, 403, 200, 200, 200, 403],
            "zero": [200, 200, 200, 200, 200, 200, 200],
        }
        for name, statuses in expected.items():
            self.assertEqual([wrapping.expected_boundary_status(name, ttl) for ttl in ttls], statuses)

    def test_policy_rejection_keeps_prefix_and_never_issues_a_token(self):
        client = Client([(204, {}), (200, {}), (400, {"errors": ["synthetic-private-error"]})])
        rows = []
        with self.assertRaisesRegex(wrapping.ScenarioFailure, "acl_wrap.policy_min"):
            wrapping.run_scenarios(client, rows)
        self.assertEqual([row["case"] for row in rows], ["acl_wrap.mount", "acl_wrap.seed", "acl_wrap.policy_min"])
        self.assertIs(rows[-1]["passed"], False)
        self.assertNotIn("synthetic-private-error", json.dumps(rows))
        self.assertFalse(any(call[1] == "/v1/auth/token/create" for call in client.calls))

    def test_unknown_boundary_kind_is_not_implicitly_admitted(self):
        with self.assertRaises(KeyError):
            wrapping.expected_boundary_status("unknown", "10")

    def test_shared_verdict_rejects_empty_failed_or_duplicated_observations(self):
        for prefix in ["acl_templates", "acl_wrap"]:
            failed = [{"case": prefix + ".rejected", "status": 400, "passed": False}]
            passed = [{"case": prefix + ".prefix", "status": 200, "passed": True}]
            for rows, failures in [([], {}), (failed, {}), (passed, {"oracle": prefix + ".incomplete"}), (passed * 2, {})]:
                self.assertFalse(core_isolation.successful_comparison({"candidate": rows, "oracle": rows}, failures))


if __name__ == "__main__":
    unittest.main()
