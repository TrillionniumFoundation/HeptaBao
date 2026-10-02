"""Exact declarative-device differential, not a candidate-only status union."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import audit_file_live
import official_openbao_launcher
from bao_http import BaoError, Response


class FileAuditClient:
    def __init__(self, *, duplicate=400, detail=405, drift=False):
        self.duplicate, self.detail, self.drift = duplicate, detail, drift
        self.lists = 0
        self.calls = []

    def request(self, method, path, body=None):
        self.calls.append((method, path))
        if path == "/v1/sys/audit":
            self.lists += 1
            file = "/synthetic/audit.jsonl"
            if self.drift and self.lists > 1:
                file = "/synthetic/rebound.jsonl"
            return Response(200, {"data": {"file/": {
                "type": "file", "options": {"file_path": file}}}})
        status = self.detail if method == "GET" else self.duplicate if method == "PUT" else 400
        return Response(status, {"errors": ["synthetic-private-text-not-for-report"]})


class AuditFileProfileTests(unittest.TestCase):
    def test_exact_standard_refusals_and_successful_unchanged_list(self):
        client = FileAuditClient()
        results = audit_file_live.run_scenarios(client)
        self.assertEqual(len(results), 8)
        self.assertTrue(all(row["passed"] for row in results))
        self.assertEqual(client.lists, 2)
        self.assertNotIn("synthetic-private-text", str(results))

    def test_old_candidate_only_success_is_a_mismatch_not_an_allowed_union(self):
        for option in ({"detail": 200}, {"duplicate": 204}, {"drift": True}):
            with self.subTest(option=option), self.assertRaises(audit_file_live.ScenarioFailure):
                audit_file_live.run_scenarios(FileAuditClient(**option))

    def test_audit_launcher_accepts_only_fixed_boolean_profile_before_allocation(self):
        for option in ({"file_path": "/arbitrary"}, 1, "true"):
            with self.subTest(option=option), patch.object(official_openbao_launcher, "verify_inputs") as verify:
                with self.assertRaisesRegex(BaoError, "official_oracle_invalid_audit_profile"):
                    official_openbao_launcher.start_oracle(8200, audit_file=option)
                verify.assert_not_called()


if __name__ == "__main__":
    unittest.main()
