"""JWT renewal receipts must distinguish role renewal from issuer revalidation."""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bao_http import Response
from core_isolation import ScenarioFailure, successful_comparison
from jwt_renewal_live import (ADAPTATION, Trace, configuration, issued_policy_snapshot, role)
from remote_jwks_live import signing_key


class IssuerStub:
    origin = "https://localhost:20000"

    def __init__(self):
        self.calls = []


class ClientStub:
    def __init__(self, issuer, *, status=200, calls_provider=False):
        self.issuer, self.status, self.calls_provider = issuer, status, calls_provider

    def request(self, *args, **kwargs):
        if self.calls_provider:
            self.issuer.calls.append("/private-issuer-path")
        return Response(self.status, {"auth": {"client_token": "private-bearer"},
                                      "errors": ["private-error-with-signed-jwt"]})


class JwtRenewalHarnessTests(unittest.TestCase):
    def test_success_that_recontacts_provider_cannot_qualify(self):
        issuer, rows = IssuerStub(), []
        with self.assertRaisesRegex(ScenarioFailure, "^jwt_renewal.remote.renew$"):
            Trace(ClientStub(issuer, calls_provider=True), issuer, "remote", rows).call(
                "renew", "auth/token/renew-self", no_provider=True)
        self.assertFalse(rows[-1]["no_provider_request"])
        self.assertNotIn("private", json.dumps(rows))
        self.assertFalse(successful_comparison({"candidate": rows, "oracle": rows}, {}))

    def test_provider_failure_cannot_be_mistaken_for_role_success(self):
        issuer, rows = IssuerStub(), []
        with self.assertRaises(ScenarioFailure):
            Trace(ClientStub(issuer, status=503), issuer, "remote", rows).call(
                "renew", "auth/token/renew-self", no_provider=True)
        self.assertTrue(rows[-1]["no_provider_request"])
        self.assertFalse(rows[-1]["passed"])
        self.assertNotIn("private", json.dumps(rows))

    def test_prior_login_provider_calls_do_not_mask_new_renewal_calls(self):
        issuer = IssuerStub()
        issuer.calls.append("/keys")
        rows = []
        Trace(ClientStub(issuer), issuer, "remote", rows).call("renew", "auth/token/renew-self", no_provider=True)
        self.assertTrue(rows[-1]["passed"])
        with self.assertRaises(ScenarioFailure):
            Trace(ClientStub(issuer, calls_provider=True), issuer, "remote", rows).call(
                "renew_again", "auth/token/renew-self", no_provider=True)

    def test_policy_change_requires_preserving_issue_snapshot(self):
        self.assertTrue(issued_policy_snapshot({"token_policies": ["default", "jwt-old"]}))
        for policies in [["default", "jwt-new"], ["jwt-old", "jwt-new"], [], "jwt-old", None]:
            self.assertFalse(issued_policy_snapshot({"token_policies": policies}))

    def test_role_updates_send_complete_role_and_preserve_unmodified_fields(self):
        changed = role(token_max_ttl=600, token_policies=["jwt-new"])
        self.assertEqual(changed["role_type"], "jwt")
        self.assertEqual(changed["user_claim"], "sub")
        self.assertEqual(changed["bound_audiences"], ["heptabao-test"])
        self.assertEqual(changed["token_ttl"], 60)
        self.assertEqual(changed["token_max_ttl"], 600)

    def test_static_and_remote_configuration_adapters_are_explicit(self):
        issuer = IssuerStub()
        private, jwk = signing_key("ES256", "synthetic")
        candidate = configuration("candidate", "static", issuer, private, jwk, "private-ca")
        oracle = configuration("oracle", "static", issuer, private, jwk, "private-ca")
        self.assertIn("jwks", candidate)
        self.assertIn("PUBLIC KEY", oracle["jwt_validation_pubkeys"][0])
        self.assertNotIn("PRIVATE KEY", json.dumps(oracle))
        self.assertEqual(configuration("candidate", "remote", issuer, private, jwk, "private-ca")["jwks_ca_pem"], "private-ca")
        self.assertIn("jwks_ca_pem", configuration("oracle", "remote", issuer, private, jwk, "private-ca"))
        self.assertIs(ADAPTATION["configuration_api_parity"], False)


if __name__ == "__main__":
    unittest.main()
