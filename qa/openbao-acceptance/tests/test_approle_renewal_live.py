"""AppRole fixture guards reject failed prefixes and unsafe observations."""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from approle_renewal_live import EXPECTED_COUNT, complete_side, run_scenarios, ttl_matches
from bao_http import Response
from core_isolation import ScenarioFailure, successful_comparison


class FailingClient:
    def request(self, *args, **kwargs):
        return Response(503, {"errors": ["private-error"], "auth": {"client_token": "private-token"}})


class AppRoleRenewalTests(unittest.TestCase):
    def test_failure_prefix_cannot_qualify_or_echo_response_credentials(self):
        rows = []
        with self.assertRaisesRegex(ScenarioFailure, "^approle_renewal.mount$"):
            run_scenarios(FailingClient(), lambda: None, rows, wait=lambda _: None)
        self.assertFalse(complete_side(rows))
        self.assertFalse(successful_comparison({"candidate": rows, "oracle": rows}, {}))
        self.assertNotIn("private", json.dumps(rows))

    def test_count_failed_rows_duplicates_and_missing_final_case_do_not_qualify(self):
        complete = [{"case": "case." + str(i), "passed": True} for i in range(EXPECTED_COUNT)]
        complete[-1]["case"] = "approle_renewal.orphan_after_unmount.ttl"
        self.assertTrue(complete_side(complete))
        for rows in ([], complete[:-1], complete[:-2] + complete[-1:], complete[:-1] + [complete[0]]):
            self.assertFalse(complete_side(rows))
        self.assertFalse(complete_side([{**row, "passed": False} for row in complete]))

    def test_role_default_and_period_need_exact_ttl(self):
        self.assertTrue(ttl_matches(120, exact=120))
        for value in (0, 119, 121, True, "120", None):
            self.assertFalse(ttl_matches(value, exact=120))

    def test_captured_explicit_cap_rejects_extension_and_expired_lease(self):
        for value in (1, 19, 20):
            self.assertTrue(ttl_matches(value, maximum=20))
        for value in (0, -1, 21, 120, True, "20"):
            self.assertFalse(ttl_matches(value, maximum=20))


if __name__ == "__main__":
    unittest.main()
