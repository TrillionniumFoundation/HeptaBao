"""AppRole fixture guards reject failed prefixes and unsafe observations."""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from approle_renewal_live import REQUIRED_CASES, complete_side, run_scenarios, ttl_matches
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

    def test_required_phases_replace_count_and_allow_new_observations(self):
        terminal = "approle_renewal.complete"
        rows = [{"case": name, "passed": True} for name in sorted(REQUIRED_CASES - {terminal})]
        rows.append({"case": terminal, "passed": True})
        self.assertTrue(complete_side(rows))
        self.assertTrue(complete_side(rows[:-1] + [{"case": "approle_renewal.new_check", "passed": True}, rows[-1]]))
        for missing in REQUIRED_CASES:
            self.assertFalse(complete_side([row for row in rows if row["case"] != missing]))
        fabricated = [{"case": "approle_renewal.case_" + str(i), "passed": True} for i in range(153)]
        fabricated[-1]["case"] = terminal
        self.assertFalse(complete_side(fabricated))
        for invalid in ([], rows + [rows[-1]], rows[:-1], rows[:-1] + [None],
                        rows[:-1] + [{"case": terminal, "passed": 1}],
                        rows[:-1] + [{"case": terminal, "passed": False}]):
            self.assertFalse(complete_side(invalid))

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
