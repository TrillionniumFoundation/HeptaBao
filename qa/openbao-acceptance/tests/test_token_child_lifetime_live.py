"""Reject ancestor-clamped TTLs, incorrect period shapes and unsafe receipts."""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bao_http import Response
from core_isolation import ScenarioFailure, successful_comparison
from token_child_lifetime_live import REQUIRED_CASES, complete_side, period_matches, run_scenarios


class FailedClient:
    def request(self, *args, **kwargs):
        return Response(503, {"errors": ["private-error"], "auth": {"client_token": "private-token"}})


class ClampedClient:
    def __init__(self, *, clamp_create):
        self.clamp_create = clamp_create
        self.children = 0
        self.ttls = {"private-parent": 60}

    def request(self, method, path, payload=None, *, token=None):
        if path.endswith("/role-id"):
            return Response(200, {"data": {"role_id": "private-role-id"}})
        if path.endswith("/secret-id"):
            return Response(200, {"data": {"secret_id": "private-secret-id"}})
        if path.endswith("/login"):
            return Response(200, {"auth": {"client_token": "private-parent", "accessor": "private-parent-accessor"}})
        if path.endswith("/create"):
            self.children += 1
            raw = "private-child-" + str(self.children)
            ttl = min(payload["ttl"], payload["explicit_max_ttl"]) if payload["explicit_max_ttl"] else payload["ttl"]
            if self.clamp_create:
                ttl = min(ttl, 60)
            self.ttls[raw] = ttl
            return Response(200, {"auth": {"client_token": raw, "accessor": raw + "-accessor", "lease_duration": ttl}})
        if path.endswith("/lookup-self"):
            return Response(200, {"data": {"ttl": self.ttls[token]}})
        if path.endswith("/renew-self"):
            return Response(200, {"auth": {"client_token": token, "renewable": True, "lease_duration": 60}})
        return Response(204, {})


class ChildLifetimeTests(unittest.TestCase):
    def run_trace(self, client, rows):
        return run_scenarios(client, lambda: None, {}, lambda: "private-assertion", rows, wait=lambda _: None)

    def test_failed_prefix_never_qualifies_or_reflects_credential_bytes(self):
        rows = []
        with self.assertRaisesRegex(ScenarioFailure, "^token_child_lifetime.issuer_policy$"):
            self.run_trace(FailedClient(), rows)
        self.assertFalse(complete_side(rows))
        self.assertFalse(successful_comparison({"candidate": rows, "oracle": rows}, {}))
        self.assertNotIn("private", json.dumps(rows))

    def test_parent_clamping_at_creation_and_renewal_are_independently_detected(self):
        for at_creation, expected in ((True, "child120.reported_ttl"), (False, "child.renew-self.renew_ttl")):
            rows = []
            with self.assertRaisesRegex(ScenarioFailure, "^token_child_lifetime." + expected + "$"):
                self.run_trace(ClampedClient(clamp_create=at_creation), rows)
            self.assertFalse(complete_side(rows))
            self.assertNotIn("private", json.dumps(rows))

    def test_zero_period_is_omitted_and_nonzero_is_an_exact_integer_snapshot(self):
        self.assertTrue(period_matches({}, 0))
        for value in (0, None, False, "0"):
            self.assertFalse(period_matches({"period": value}, 0))
        self.assertTrue(period_matches({"period": 30}, 30))
        for value in (0, 45, None, True, "30"):
            self.assertFalse(period_matches({"period": value}, 30))

    def test_required_phases_replace_count_and_allow_new_observations(self):
        terminal = "token_child_lifetime.complete"
        rows = [{"case": name, "passed": True} for name in sorted(REQUIRED_CASES - {terminal})]
        rows.append({"case": terminal, "passed": True})
        self.assertTrue(complete_side(rows))
        self.assertTrue(complete_side(rows[:-1] + [{"case": "token_child_lifetime.new_check", "passed": True}, rows[-1]]))
        for missing in REQUIRED_CASES:
            self.assertFalse(complete_side([row for row in rows if row["case"] != missing]))
        fabricated = [{"case": "token_child_lifetime.case_" + str(i), "passed": True} for i in range(202)]
        fabricated[-1]["case"] = terminal
        self.assertFalse(complete_side(fabricated))
        for invalid in ([], rows + [rows[-1]], rows[:-1], rows[:-1] + [None],
                        rows[:-1] + [{"case": terminal, "passed": 1}],
                        rows[:-1] + [{"case": terminal, "passed": False}]):
            self.assertFalse(complete_side(invalid))


if __name__ == "__main__":
    unittest.main()
