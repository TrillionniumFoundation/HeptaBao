"""Selected Identity comparison harness must not self-admit failed traces."""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import core_isolation
import identity_live
from bao_http import Response


class FailingClient:
    def request(self, method, path, payload=None, *, token=None):
        return Response(503, {"errors": ["private-sentinel"],
                              "auth": {"client_token": "do-not-retain"}})


class IdentityLiveHarnessTests(unittest.TestCase):
    def test_failure_records_only_fixed_case_status(self):
        observations = []
        with self.assertRaisesRegex(core_isolation.ScenarioFailure, "^identity.mount_kv$"):
            identity_live.run_scenarios(FailingClient(), observations)
        self.assertEqual(observations, [{"case": "identity.mount_kv", "status": 503, "passed": False}])
        self.assertNotIn("private-sentinel", json.dumps(observations))
        self.assertNotIn("do-not-retain", json.dumps(observations))

    def test_existing_partial_sink_is_preserved(self):
        observations = [{"case": "previous", "passed": True}]
        with self.assertRaises(core_isolation.ScenarioFailure):
            identity_live.run_scenarios(FailingClient(), observations)
        self.assertEqual(len(observations), 2)

    def test_empty_failed_or_unknown_completion_is_not_success(self):
        for row in ([], [{"case": "x", "passed": False}], [{"case": "x", "passed": 1}],
                    [{"case": "x"}], [{"passed": True}]):
            with self.subTest(row=row):
                self.assertFalse(core_isolation.successful_comparison({"candidate": row, "oracle": row}, {}))
        self.assertFalse(core_isolation.successful_comparison({}, {}))

    def test_mismatched_duplicate_and_failed_prefixes_are_rejected(self):
        row = {"case": "x", "status": 204, "passed": True}
        good = {"candidate": [row], "oracle": [row]}
        self.assertTrue(core_isolation.successful_comparison(good, {}))
        self.assertFalse(core_isolation.successful_comparison(good, {"candidate": "later_failure"}))
        self.assertFalse(core_isolation.successful_comparison({"candidate": [row, row], "oracle": [row, row]}, {}))
        other = {"case": "x", "status": 200, "passed": True}
        self.assertFalse(core_isolation.successful_comparison({"candidate": [row], "oracle": [other]}, {}))


if __name__ == "__main__":
    unittest.main()
