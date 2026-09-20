"""Guards for event proof, rejected publication, and redacted diagnostics."""
import copy
import threading
import unittest

from jwt_split_phase_live import (EVENTS, PHASES, Failure, complete_checks, gate,
                                  refused, safe_failure, valid_observations)


class IssuerGate:
    def __init__(self):
        self.block_entered = threading.Event()
        self.block_release = threading.Event()

    def block_next(self, path):
        if path != "/keys":
            raise AssertionError("wrong gate")
        self.block_entered.clear()
        self.block_release.clear()

    def release_block(self):
        self.block_release.set()

    def request(self):
        self.block_entered.set()
        if not self.block_release.wait(2):
            raise RuntimeError("gate test timeout")
        return 204, {}


class JwtSplitPhaseGuards(unittest.TestCase):
    def test_gate_proves_completion_before_release(self):
        issuer, rows = IssuerGate(), []
        def concurrent():
            self.assertTrue(issuer.block_entered.is_set())
            self.assertFalse(issuer.block_release.is_set())
            return "transient-sensitive-response"
        response, value = gate(issuer, "config_success", issuer.request, concurrent, rows)
        self.assertEqual(response, (204, {}))
        self.assertEqual(value, "transient-sensitive-response")
        self.assertEqual(rows[0]["events"], EVENTS)
        self.assertNotIn("transient-sensitive-response", repr(rows))
        for field, value in rows[0].items():
            if field not in ("phase", "events"):
                self.assertIs(value, True)

    def test_eventual_success_cannot_hide_a_locked_writer(self):
        issuer, rows = IssuerGate(), []
        def waits_for_release():
            issuer.block_release.wait(2)
            return 200, {}
        with self.assertRaisesRegex(Failure, "concurrent_request_blocked_by_jwks"):
            gate(issuer, "config_success", issuer.request, waits_for_release, rows, budget=.03)
        self.assertFalse(rows[0]["concurrent_completed_before_release"])
        self.assertNotEqual(rows[0]["events"], EVENTS)
        self.assertTrue(issuer.block_release.is_set())

    def test_premature_external_completion_is_not_a_gate_proof(self):
        issuer, rows = IssuerGate(), []
        def already_completed():
            issuer.block_entered.set()
            return 204, {}
        with self.assertRaisesRegex(Failure, "jwks_gate_did_not_prove_order"):
            gate(issuer, "config_success", already_completed, lambda: True, rows)
        self.assertFalse(rows[0]["request_pending_before_release"])

    def test_observation_validator_rejects_missing_phase_reorder_and_fake_truth(self):
        rows = [{"phase": phase, "events": list(EVENTS), "held_before_release": True,
                 "concurrent_completed_before_release": True,
                 "request_pending_before_release": True, "within_enrolled_deadline": True}
                for phase in sorted(PHASES)]
        self.assertTrue(valid_observations(rows))
        self.assertFalse(valid_observations(rows[:-1]))
        for field in ("events", "held_before_release", "phase"):
            bad = copy.deepcopy(rows)
            bad[0][field] = {"events": list(reversed(EVENTS)), "held_before_release": 1,
                             "phase": bad[1]["phase"]}[field]
            self.assertFalse(valid_observations(bad))

    def test_refusal_cannot_publish_bearer_wrapper_or_data(self):
        self.assertTrue(refused(409, {"errors": ["conflict"]}, 409))
        for field in ("auth", "wrap_info", "data"):
            self.assertFalse(refused(409, {field: {"token": "sensitive"}}, 409))
        self.assertFalse(refused(200, {}, 409))
        self.assertFalse(refused(True, {}, 1))

    def test_checks_and_errors_never_promote_incomplete_or_sensitive_result(self):
        checks = [{"case": "complete", "passed": True}]
        self.assertTrue(complete_checks(checks))
        self.assertFalse(complete_checks([]))
        self.assertFalse(complete_checks(checks * 2))
        self.assertFalse(complete_checks([{"case": "complete", "passed": 1}]))
        sentinel = "secret-jwt-userinfo-response"
        self.assertEqual(safe_failure(RuntimeError(sentinel), []), "fixture_RuntimeError")
        self.assertEqual(safe_failure(Failure("jwks_gate_not_entered"), []), "jwks_gate_not_entered")
        self.assertNotIn(sentinel, safe_failure(Failure(sentinel), []))


if __name__ == "__main__":
    unittest.main()
