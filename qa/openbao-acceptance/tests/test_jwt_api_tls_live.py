import copy
from types import SimpleNamespace
import unittest

from jwt_api_tls_live import MODES, Failure, Trace, ca_variant, configuration, discovery, successful


class JwtApiTlsGuards(unittest.TestCase):
    def test_active_ca_fields_and_only_oidc_callback_adaptation(self):
        oidc = SimpleNamespace(discovery="https://issuer:443/provider", client_id="id", client_secret="secret")
        issuer = SimpleNamespace(origin="https://issuer:443")
        for mode in MODES:
            candidate = configuration(mode, "candidate", issuer, oidc, "test-pem")
            official = configuration(mode, "oracle", issuer, oidc, "test-pem")
            if mode == "oidc":
                self.assertIs(candidate.pop("pkce_s256_enrolled"), True)
            self.assertEqual(candidate, official)
            field = "jwks_ca_pem" if mode == "jwks" else "oidc_discovery_ca_pem"
            self.assertEqual(candidate[field], "test-pem")

    def test_ca_variants_are_distinct_and_do_not_mutate_predecessor(self):
        original = {"jwks_ca_pem": "correct", "jwks_url": "https://issuer/keys"}
        before = copy.deepcopy(original)
        self.assertNotIn("jwks_ca_pem", ca_variant(original, "jwks_ca_pem", "omitted", "wrong-pem"))
        self.assertIsNone(ca_variant(original, "jwks_ca_pem", None, "wrong-pem")["jwks_ca_pem"])
        self.assertEqual(ca_variant(original, "jwks_ca_pem", "", "wrong-pem")["jwks_ca_pem"], "")
        self.assertEqual(ca_variant(original, "jwks_ca_pem", "wrong", "wrong-pem")["jwks_ca_pem"], "wrong-pem")
        self.assertEqual(original, before)

    def test_trace_never_accepts_arbitrary_response_or_credentials(self):
        rows = []
        trace = Trace(None, rows, "jwks")
        trace.check("fixed", True, status=204, no_body=True)
        with self.assertRaises(Failure):
            trace.check("leaked", True, secret="sensitive-bearer")
        with self.assertRaises(Failure):
            trace.check("unsafe?secret=sensitive-bearer", True)
        self.assertNotIn("sensitive-bearer", repr(rows))

    def test_false_or_nonboolean_success_is_not_promoted(self):
        for value in (False, 1, "true"):
            rows = []
            with self.assertRaises(Failure):
                Trace(None, rows).check("failure", value)
            self.assertIs(rows[0]["passed"], False)

    def test_completeness_rejects_missing_modes_duplicates_and_data(self):
        rows = [{"case": "api_tls." + mode + ".complete", "passed": True} for mode in MODES]
        self.assertTrue(successful(rows))
        self.assertFalse(successful(rows[:-1]))
        self.assertFalse(successful(rows + rows[:1]))
        for field, value in (("passed", 1), ("raw_response", {"client_token": "sensitive"})):
            bad = copy.deepcopy(rows)
            bad[0][field] = value
            self.assertFalse(successful(bad))

    def test_san_fixture_metadata_would_be_valid_without_the_tls_rejection(self):
        metadata = discovery("https://localhost:4443")
        self.assertEqual(metadata["issuer"], "https://localhost:4443")
        self.assertEqual(metadata["jwks_uri"], "https://localhost:4443/keys")
        self.assertEqual(metadata["code_challenge_methods_supported"], ["S256"])
        self.assertEqual(metadata["token_endpoint_auth_methods_supported"], ["client_secret_basic"])


if __name__ == "__main__":
    unittest.main()
