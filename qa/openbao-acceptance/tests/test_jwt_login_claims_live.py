"""JWT login evidence checks omissions and new service tokens without secrets."""
import base64
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bao_http import Response
from core_isolation import ScenarioFailure, successful_comparison
from jwt_login_claims_live import Trace, distinct_service_tokens, native_time_matrix, service_token_shape, signed_assertion
from remote_jwks_live import signing_key


def auth(token="private-first", accessor="private-accessor", entity="private-entity"):
    return {"client_token": token, "accessor": accessor, "entity_id": entity,
            "lease_duration": 60, "renewable": True}


class IssuerStub:
    calls = []


class DeniedClient:
    def request(self, *args, **kwargs):
        return Response(403, {"errors": ["private-jwt-assertion"], "auth": auth()})


class JwtLoginClaimsTests(unittest.TestCase):
    def test_repeated_assertion_must_issue_new_bearer_and_accessor_same_entity(self):
        first = auth()
        self.assertTrue(distinct_service_tokens(first, auth("private-second", "private-accessor-2")))
        for second in [first, auth("private-second"), auth(accessor="private-accessor-2"),
                       auth("private-second", "private-accessor-2", "private-other-entity"), None]:
            self.assertFalse(distinct_service_tokens(first, second))

    def test_service_token_shape_rejects_missing_fields_and_assertion_capped_ttl(self):
        self.assertTrue(service_token_shape(auth()))
        for field in ("client_token", "accessor", "entity_id", "renewable", "lease_duration"):
            value = auth()
            value.pop(field)
            self.assertFalse(service_token_shape(value))
        self.assertFalse(service_token_shape(dict(auth(), lease_duration=2)))

    def test_optional_claims_are_absent_not_json_null(self):
        private, jwk = signing_key("ES256", "synthetic")
        for omit in [("jti",), ("iat",), ("iat", "jti"), ("iat", "nbf", "exp")]:
            assertion = signed_assertion(private, jwk, "https://synthetic.invalid", omit=omit)
            payload = assertion.split(".")[1]
            claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
            self.assertTrue(all(field not in claims for field in omit))
            self.assertEqual(claims["aud"], "heptabao-test")

    def test_failed_login_cannot_qualify_or_echo_claims_into_receipt(self):
        rows = []
        with self.assertRaisesRegex(ScenarioFailure, "^jwt_login_claims.static.login$"):
            Trace(DeniedClient(), IssuerStub(), "static", rows).call("login", "auth/jwt/login")
        self.assertFalse(rows[-1]["passed"])
        self.assertNotIn("private", json.dumps(rows))
        self.assertFalse(successful_comparison({"candidate": rows, "oracle": rows}, {}))

    def test_signer_preserves_numeric_null_and_empty_claims_without_normalizing(self):
        private, jwk = signing_key("ES256", "synthetic")
        for values in [{"iat": -0.5, "nbf": -1, "exp": 1234.75},
                       {"iat": None, "nbf": 0, "exp": True, "jti": ""}]:
            assertion = signed_assertion(private, jwk, "https://synthetic.invalid", **values)
            payload = assertion.split(".")[1]
            claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
            for key, value in values.items():
                self.assertEqual(claims[key], value)
                self.assertIs(type(claims[key]), type(value))

    def test_time_matrix_distinguishes_real_claim_grace_from_missing_claim_synthesis(self):
        rows = {name: (leeway, omit, claims, status) for name, leeway, omit, claims, status in native_time_matrix(10000)}
        self.assertEqual(len(rows), 41)
        self.assertEqual(rows["positive_expiry_synthesis"][3], 200)
        self.assertEqual(rows["expiry_leeway_does_not_relax_present_exp"][3], 400)
        self.assertEqual(rows["positive_nbf_synthesis"][3], 200)
        self.assertEqual(rows["nbf_leeway_does_not_relax_present_nbf"][3], 400)
        self.assertEqual(rows["zero_clock_defaults_accept_recent_expiry"][0]["clock_skew_leeway"], 0)
        self.assertEqual(rows["negative_clock_disables_exp_grace"][0]["clock_skew_leeway"], -1)
        self.assertEqual(rows["all_times_zero"][3], 400)
        self.assertEqual(rows["all_times_null"][3], 400)
        self.assertEqual(rows["no_implicit_hour_lifetime_cap"][2]["exp"], 17200)

    def test_time_matrix_rebases_live_offsets_but_preserves_literal_numeric_probes(self):
        first, second = native_time_matrix(10000), native_time_matrix(20000)
        self.assertEqual([row[0] for row in first], [row[0] for row in second])
        a, b = {row[0]: row[3] for row in first}, {row[0]: row[3] for row in second}
        self.assertEqual(b["exp_only_far_future_synthesized_nbf"]["exp"] - a["exp_only_far_future_synthesized_nbf"]["exp"], 10000)
        self.assertEqual(a["negative_iat"], b["negative_iat"])
        self.assertEqual(a["all_times_null"], b["all_times_null"])


if __name__ == "__main__":
    unittest.main()
