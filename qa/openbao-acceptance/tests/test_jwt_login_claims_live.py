"""JWT login evidence checks omissions and new service tokens without secrets."""
import base64
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bao_http import Response
from core_isolation import ScenarioFailure, successful_comparison
from jwt_login_claims_live import Trace, distinct_service_tokens, service_token_shape, signed_assertion
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


if __name__ == "__main__":
    unittest.main()
