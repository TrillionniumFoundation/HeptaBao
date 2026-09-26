"""Guard exact status, full trace, TLS adaptation ordering and safe receipts."""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bao_http import Response
from cert_renewal_live import ADAPTATION, EXPECTED_COUNT, complete_side, renewal_shape, run_scenarios
from core_isolation import ScenarioFailure, successful_comparison


class ScriptedClient:
    def __init__(self, state, *, plain=False):
        self.state, self.plain = state, plain

    def request(self, method, path, payload=None, *, token=None):
        state = self.state
        if self.plain and not state.get("restarted"):
            raise AssertionError("no-certificate request must follow listener adaptation")
        if path.endswith("/login"):
            return Response(200, {"auth": {"client_token": "private-direct"}})
        if path.endswith("/create"):
            label = "orphan" if payload.get("no_parent") else "child"
            return Response(200, {"auth": {"client_token": "private-" + label, "accessor": "private-accessor-" + label}})
        if path.endswith("/certs/operator") and method == "POST" and payload["token_max_ttl"] == 1:
            state["shortened"] = True
        if path.endswith("/cert-renewal") and method == "DELETE":
            state["disabled"] = True
        if "/renew" in path:
            if self.plain and token == "private-direct":
                return Response(state.get("missing_certificate_status", 400), {"errors": ["private-error"]})
            if token == "private-direct" and state.get("shortened"):
                return Response(state.get("maximum_status", 500), {"errors": ["private-error"]})
            ttl = state.get("raised_ttl", 500) if token == "private-direct" and payload.get("increment") == 500 else 60
            if token == "private-direct" and "increment" not in payload:
                ttl = state.get("omitted_increment_ttl", 120)
            return Response(200, {"auth": {"renewable": True, "lease_duration": ttl, "token_policies": ["default"]}})
        if path.endswith("/lookup-self"):
            revoked = state.get("disabled") and (token == "private-child" or state.get("revoke_orphan"))
            return Response(403 if revoked else 200, {"data": {"ttl": 100}, "private": "private-token"})
        if path.endswith("/health"):
            return Response(200, {})
        return Response(204, {})


def run_scripted(state=None, rows=None):
    state = {} if state is None else state
    return run_scenarios(ScriptedClient(state), ScriptedClient(state, plain=True), "private-pem",
                         lambda: state.update(restarted=True), rows, wait=lambda seconds: None)


class CertRenewalTests(unittest.TestCase):
    def test_full_trace_and_listener_adaptation_are_explicit(self):
        rows = run_scripted()
        self.assertEqual(EXPECTED_COUNT, 46)
        self.assertTrue(complete_side(rows))
        self.assertTrue(successful_comparison({"candidate": rows, "oracle": rows}, {}))
        self.assertNotIn("private-", json.dumps(rows))
        self.assertIn("same store restarted", ADAPTATION["candidate"])
        self.assertIs(ADAPTATION["configuration_api_parity"], False)

    def test_past_maximum_status_is_not_normalized(self):
        for status in (200, 400, 403, 503):
            rows = []
            with self.assertRaisesRegex(ScenarioFailure, "^cert_renewal.past_issue_time_maximum$"):
                run_scripted({"maximum_status": status}, rows)
            self.assertFalse(complete_side(rows))
            self.assertFalse(successful_comparison({"candidate": rows, "oracle": rows}, {}))
            self.assertNotIn("private-", json.dumps(rows))

    def test_unmount_cannot_silently_revoke_independent_orphan(self):
        rows = []
        with self.assertRaisesRegex(ScenarioFailure, "^cert_renewal.orphan_survives_parent_mount$"):
            run_scripted({"revoke_orphan": True}, rows)
        self.assertFalse(complete_side(rows))
        self.assertNotIn("private-", json.dumps(rows))

    def test_stale_issue_time_role_cap_cannot_qualify_after_raising(self):
        rows = []
        with self.assertRaisesRegex(ScenarioFailure, "^cert_renewal.raised_maximum_extends_beyond_issue_snapshot$"):
            run_scripted({"raised_ttl": 300}, rows)
        self.assertFalse(complete_side(rows))

    def test_child_relaxation_must_not_remove_direct_certificate_binding(self):
        rows = []
        with self.assertRaisesRegex(ScenarioFailure, "^cert_renewal.direct_binding_requires_client_certificate$"):
            run_scripted({"missing_certificate_status": 200}, rows)
        self.assertFalse(complete_side(rows))

    def test_omitted_increment_is_not_replaced_by_role_maximum(self):
        rows = []
        with self.assertRaisesRegex(ScenarioFailure, "^cert_renewal.omitted_increment_uses_current_role_ttl$"):
            run_scripted({"omitted_increment_ttl": 600}, rows)
        self.assertFalse(complete_side(rows))

    def test_matching_prefix_duplicate_or_unrelated_cases_cannot_qualify(self):
        rows = run_scripted()
        for bad in ([], rows[:-1], rows[:-1] + [rows[0]], [{"case": str(i), "passed": True} for i in range(EXPECTED_COUNT)]):
            self.assertFalse(complete_side(bad))
        self.assertFalse(complete_side([{**row, "passed": False} for row in rows]))

    def test_renewal_shape_requires_bounded_live_lease_and_attenuated_policy(self):
        self.assertTrue(renewal_shape({"auth": {"renewable": True, "lease_duration": 60, "token_policies": ["default"]}}, 60))
        for ttl in (0, -1, True, 61, "60"):
            self.assertFalse(renewal_shape({"auth": {"renewable": True, "lease_duration": ttl, "token_policies": ["default"]}}, 60))
        self.assertFalse(renewal_shape({"auth": {"renewable": True, "lease_duration": 60, "token_policies": ["default", "issuer"]}}, 60))


if __name__ == "__main__":
    unittest.main()
