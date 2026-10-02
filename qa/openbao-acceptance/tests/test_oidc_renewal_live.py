"""OIDC renewal receipts must not hide an available issuer or failed renewal."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bao_http import Response
from core_isolation import ScenarioFailure, successful_comparison
from oidc_renewal_live import ADAPTATION, Trace, configuration, policy_snapshot, role


class IssuerStub:
    discovery = "https://localhost:20000/v1/identity/oidc/provider/test"
    client_id = "private-client-id"
    client_secret = "private-client-secret"
    def __init__(self, stopped=True):
        self.is_stopped = stopped
    def stopped(self):
        return self.is_stopped


class ClientStub:
    def __init__(self, status=200):
        self.status = status
    def request(self, *args, **kwargs):
        return Response(self.status, {"auth": {"client_token": "private-bearer"},
                                      "errors": ["private-error-with-code"]})


class OidcRenewalHarnessTests(unittest.TestCase):
    def test_available_issuer_cannot_qualify_offline_renewal(self):
        rows = []
        with self.assertRaisesRegex(ScenarioFailure, "^oidc_renewal.renew$"):
            Trace(ClientStub(), IssuerStub(stopped=False), rows).call("renew", "auth/token/renew-self", offline=True)
        self.assertFalse(rows[-1]["issuer_stopped"])
        self.assertFalse(successful_comparison({"candidate": rows, "oracle": rows}, {}))
        self.assertNotIn("private", json.dumps(rows))

    def test_provider_failure_cannot_masquerade_as_native_success(self):
        rows = []
        with self.assertRaises(ScenarioFailure):
            Trace(ClientStub(503), IssuerStub(), rows).call("renew", "auth/token/renew-self", offline=True)
        self.assertTrue(rows[-1]["issuer_stopped"])
        self.assertFalse(rows[-1]["passed"])
        self.assertNotIn("private", json.dumps(rows))

    def test_issuer_restarted_during_request_does_not_pass(self):
        issuer, rows = IssuerStub(), []
        class Client(ClientStub):
            def request(self, *args, **kwargs):
                issuer.is_stopped = False
                return super().request(*args, **kwargs)
        with self.assertRaises(ScenarioFailure):
            Trace(Client(), issuer, rows).call("renew", "auth/token/renew-self", offline=True)
        self.assertFalse(rows[-1]["issuer_stopped"])

    def test_policy_update_must_not_replace_issued_policy_snapshot(self):
        self.assertTrue(policy_snapshot({"token_policies": ["default", "oidc-old"]}))
        for policies in [["oidc-new"], ["oidc-old", "oidc-new"], [], "oidc-old", None]:
            self.assertFalse(policy_snapshot({"token_policies": policies}))

    def test_complete_role_keeps_redirect_binding(self):
        value = role("http://127.0.0.1:20000/oidc/callback", token_period=20, token_explicit_max_ttl=120)
        self.assertEqual(value["role_type"], "oidc")
        self.assertEqual(value["allowed_redirect_uris"], ["http://127.0.0.1:20000/oidc/callback"])
        self.assertEqual(value["token_max_ttl"], 90)
        self.assertEqual(value["token_period"], 20)
        self.assertEqual(value["token_explicit_max_ttl"], 120)

    def test_configuration_and_callback_differences_are_not_api_parity(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "ca.pem"
            path.write_text("private-test-ca")
            issuer = IssuerStub()
            issuer.server = {"ca_file": str(path)}
            candidate, oracle = configuration("candidate", issuer), configuration("oracle", issuer)
        self.assertIs(candidate["pkce_s256_enrolled"], True)
        self.assertEqual(candidate["oidc_discovery_ca_pem"], "private-test-ca")
        self.assertEqual(oracle["oidc_discovery_ca_pem"], "private-test-ca")
        self.assertNotIn("pkce_s256_enrolled", oracle)
        self.assertIs(ADAPTATION["configuration_api_parity"], False)
        self.assertIs(ADAPTATION["callback_api_parity"], False)
        self.assertIn("POST", ADAPTATION["candidate"])
        self.assertIn("GET", ADAPTATION["oracle"])


if __name__ == "__main__":
    unittest.main()
