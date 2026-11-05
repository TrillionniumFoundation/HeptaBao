"""Historical OIDC upgrade receipts must not invent a build or pending session."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bao_http import Response
from core_isolation import ScenarioFailure
import oidc_native_upgrade as upgrade
from oidc_renewal_live import OfficialIssuer


class OidcNativeUpgradeTests(unittest.TestCase):
    source = "a" * 40
    digest = "b" * 64
    def receipt(self):
        return {"build_source_commit": self.source, "harness_source_commit": self.source,
                "harness_source_dirty": False, "harness_source_unchanged": True,
                "candidate_binary_unchanged": True, "candidate_binary_sha256": self.digest,
                "status": "passed"}

    def test_unconfigured_historical_pin_must_fail(self):
        with patch.object(upgrade, "LEGACY_SOURCE", ""), patch.object(upgrade, "LEGACY_SHA256", ""):
            with self.assertRaisesRegex(ValueError, "pin_not_configured"):
                upgrade.admit_legacy(Path("new"), Path("old"), self.digest, self.receipt())

    def test_old_binary_requires_the_observed_clean_build(self):
        with patch.object(upgrade, "LEGACY_SOURCE", self.source), patch.object(upgrade, "LEGACY_SHA256", self.digest):
            for field, wrong in [("build_source_commit", "other"), ("harness_source_dirty", True),
                                 ("harness_source_unchanged", False), ("candidate_binary_unchanged", False),
                                 ("candidate_binary_sha256", "0" * 64), ("status", "failed")]:
                with self.assertRaises(ValueError):
                    upgrade.admit_legacy(Path("new"), Path("old"), self.digest,
                                         dict(self.receipt(), **{field: wrong}))
            with patch.object(upgrade, "validate_binary_pins", return_value=("current", "legacy")) as pins:
                self.assertEqual(upgrade.admit_legacy(Path("new"), Path("old"), self.digest, self.receipt()),
                                 ("current", "legacy"))
                pins.assert_called_once_with(Path("new"), Path("old"), self.digest)

    def test_failed_downgrade_cannot_continue_or_disclose_credentials(self):
        class Client:
            def request(self, *args, **kwargs):
                return Response(200, {"auth": {"client_token": "private-bearer"}, "errors": ["private-error"]})
        class Issuer:
            def stopped(self): return True
        rows = []
        with self.assertRaisesRegex(ScenarioFailure, "^oidc_native_upgrade.downgrade$"):
            upgrade.Trace(Client(), Issuer(), rows).call("downgrade", "sys/unseal", {"key": "private-key"}, expected=503)
        self.assertEqual(rows, [{"case": "oidc_native_upgrade.downgrade", "status": 200, "passed": False}])
        self.assertNotIn("private", json.dumps(rows))

    def test_begin_creates_pending_code_without_consumer_callback(self):
        calls = []
        class IssuerClient:
            def request(self, *args, **kwargs):
                calls.append("authorize")
                return Response(200, {"code": "private-issuer-code"})
        class Trace:
            def call(self, name, path, body=None, **kwargs):
                calls.append("auth_url" if path.endswith("auth_url") else "callback")
                if path.endswith("auth_url"):
                    return {"data": {"auth_url": "https://localhost/authorize?client_id=test-client&redirect_uri=http%3A%2F%2F127.0.0.1%3A20000%2Foidc%2Fcallback&response_type=code&code_challenge_method=S256&state=private-state&nonce=private-nonce&code_challenge=private-challenge"}}
                return {"auth": {"client_token": "private-service", "accessor": "private-accessor", "entity_id": "entity"}}
            def check(self, name, condition):
                if not condition: raise AssertionError(name)
        issuer = OfficialIssuer.__new__(OfficialIssuer)
        issuer.redirect = "http://127.0.0.1:20000/oidc/callback"
        issuer.client_id, issuer.client_secret, issuer.enduser = "test-client", "private-client-secret", "private-user-token"
        issuer.admin = IssuerClient()
        pending = issuer.begin(Trace(), "old.pending", "browser/upgrade", "test")
        self.assertEqual(calls, ["auth_url", "authorize"])
        self.assertEqual(pending["code"], "private-issuer-code")
        self.assertEqual(pending["state"], "private-state")
        self.assertTrue(pending["client_nonce"])
        issuer.finish(Trace(), "candidate", "new.pending", "browser/upgrade", pending)
        self.assertEqual(calls, ["auth_url", "authorize", "callback"])


if __name__ == "__main__":
    unittest.main()
