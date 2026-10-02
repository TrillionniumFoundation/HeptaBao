import base64
from types import SimpleNamespace
import unittest

from jwt_api_tls_upgrade import (LEGACY_HARNESS_SOURCE, LEGACY_SHA256, LEGACY_SOURCE, MODES,
                                  admit_legacy_receipt, complete, legacy_configuration, retained_oidc_auth_url_body)


class JwtApiTlsUpgradeGuards(unittest.TestCase):
    def test_legacy_input_never_inherits_new_ca_transport_fields(self):
        issuer = SimpleNamespace(origin="https://localhost:443")
        oidc = SimpleNamespace(discovery="https://localhost:443/provider", client_id="id", client_secret="secret")
        for mode in MODES:
            config = legacy_configuration(mode, issuer, oidc)
            self.assertFalse({"jwks_ca_pem", "oidc_discovery_ca_pem", "transport"}.intersection(config))
            if mode == "oidc":
                self.assertIs(config["pkce_s256_enrolled"], True)

    def test_unenrolled_oidc_request_has_canonical_32_byte_nonce(self):
        redirect = "http://127.0.0.1:8443/oidc/callback"
        body = retained_oidc_auth_url_body(redirect)
        self.assertEqual(set(body), {"role", "redirect_uri", "client_nonce"})
        self.assertEqual(body["role"], "app")
        self.assertEqual(body["redirect_uri"], redirect)
        nonce = body["client_nonce"]
        self.assertRegex(nonce, r"^[A-Za-z0-9_-]{43}$")
        decoded = base64.urlsafe_b64decode(nonce + "=")
        self.assertEqual(len(decoded), 32)
        self.assertEqual(base64.urlsafe_b64encode(decoded).decode().rstrip("="), nonce)

    def test_historical_receipt_requires_exact_binary_build_and_clean_evidence(self):
        receipt = {"status": "passed", "source_and_binary_unchanged": True, "runner_unchanged": True,
                   "source_commit": LEGACY_HARNESS_SOURCE, "build_source_commit": LEGACY_SOURCE,
                   "source_dirty": False, "binary_sha256": LEGACY_SHA256}
        admit_legacy_receipt(LEGACY_SHA256, receipt)
        for name, value in (("status", "failed"), ("source_dirty", True), ("source_commit", "0" * 40),
                            ("build_source_commit", "0" * 40), ("binary_sha256", "0" * 64),
                            ("runner_unchanged", False), ("source_and_binary_unchanged", False)):
            with self.assertRaises(ValueError):
                admit_legacy_receipt(LEGACY_SHA256, dict(receipt, **{name: value}))
        with self.assertRaises(ValueError):
            admit_legacy_receipt("0" * 64, receipt)

    def test_preparation_is_never_an_upgrade_receipt(self):
        rows = [{"case": "api_tls.upgrade.legacy.complete", "passed": True}]
        self.assertTrue(complete(rows, True))
        self.assertFalse(complete(rows, False))
        self.assertFalse(complete([], True))
        self.assertFalse(complete(rows * 2, True))
        self.assertFalse(complete([dict(rows[0], passed=1)], True))


if __name__ == "__main__":
    unittest.main()
