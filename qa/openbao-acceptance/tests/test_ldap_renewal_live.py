"""LDAP renewal evidence rejects local-only success and identity-policy freezing."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bao_http import Response
from core_isolation import ScenarioFailure, successful_comparison
from ldap_renewal_live import (ADAPTATION, RenewalDirectory, Trace,
                               configuration, identity_projection_matches, user_configuration)


class DirectoryStub:
    origin = "ldaps://127.0.0.1:20000"
    admin_dn = "cn=admin,dc=example,dc=test"
    admin_password = "private-synthetic-admin-password"

    def __init__(self, bound=False, searched=False):
        self.bound, self.searched = bound, searched

    def cursor(self):
        return 0

    def observed(self, cursor, *, search):
        return self.bound and (not search or self.searched)


class ClientStub:
    def __init__(self, status=200):
        self.status = status

    def request(self, *args, **kwargs):
        return Response(self.status, {"auth": {"client_token": "private-bearer"},
                                      "errors": ["private-provider-error"]})


class LdapRenewalHarnessTests(unittest.TestCase):
    def test_provider_success_requires_fresh_bind_and_search(self):
        for bound, searched in [(False, False), (True, False), (False, True)]:
            rows = []
            trace = Trace(ClientStub(), DirectoryStub(bound, searched), rows)
            with self.assertRaisesRegex(ScenarioFailure, "^ldap_renewal.accepted$"):
                trace.call("accepted", "auth/token/renew-self", provider="search")
            self.assertFalse(rows[-1]["provider_checked"])
            self.assertNotIn("private", json.dumps(rows))
            self.assertFalse(successful_comparison({"candidate": rows, "oracle": rows}, {}))

    def test_rejection_requires_bind_but_not_post_bind_search(self):
        rows = []
        Trace(ClientStub(400), DirectoryStub(True, False), rows).call(
            "denied", "auth/token/renew-self", expected=400, provider="bind")
        self.assertTrue(rows[-1]["passed"])
        self.assertNotIn("private", json.dumps(rows))

    def test_wrong_http_status_cannot_qualify_even_with_provider_activity(self):
        rows = []
        with self.assertRaises(ScenarioFailure):
            Trace(ClientStub(503), DirectoryStub(True, True), rows).call(
                "accepted", "auth/token/renew-self", provider="search")
        self.assertFalse(successful_comparison({"candidate": rows, "oracle": rows}, {}))
        self.assertNotIn("private", json.dumps(rows))

    def test_only_new_log_suffix_counts_and_log_contents_never_escape(self):
        with tempfile.TemporaryDirectory() as root:
            directory = RenewalDirectory.__new__(RenewalDirectory)
            directory.root = Path(root)
            log = directory.root / "slapd.log"
            log.write_bytes(b"do_bind private-old-secret do_search\n")
            cursor = directory.cursor()
            self.assertFalse(directory.observed(cursor, search=True))
            self.assertTrue(directory.unchanged(cursor))
            with log.open("ab") as stream:
                stream.write(b"do_bind private-new-secret\n")
            self.assertTrue(directory.observed(cursor, search=False))
            self.assertFalse(directory.observed(cursor, search=True))
            with log.open("ab") as stream:
                stream.write(b"do_search\n")
            self.assertTrue(directory.observed(cursor, search=True))
            self.assertFalse(directory.unchanged(cursor))

    def test_identity_grants_must_not_be_frozen_in_token_policy(self):
        wanted = {"reader": True, "other": False}
        valid = {"auth": {"identity_policies": ["reader"], "token_policies": ["default"],
                          "policies": ["default", "reader"]}}
        self.assertTrue(identity_projection_matches(valid, wanted, envelope="auth"))
        for value in [{"identity_policies": ["reader"], "token_policies": ["default", "reader"]},
                      {"identity_policies": ["reader", "other"], "token_policies": ["default"]},
                      {"identity_policies": [], "token_policies": ["default"]},
                      {"identity_policies": "reader", "token_policies": ["default"]}, None]:
            self.assertFalse(identity_projection_matches({"auth": value}, wanted, envelope="auth"))

    def test_lookup_policy_projection_accepts_legacy_token_policy_field(self):
        body = {"data": {"identity_policies": ["other"], "policies": ["default"]}}
        self.assertTrue(identity_projection_matches(body, {"reader": False, "other": True}, envelope="data"))
        self.assertFalse(identity_projection_matches(body, {"reader": True, "other": True}, envelope="data"))

    def test_configuration_and_disabled_account_limits_are_explicit(self):
        directory = DirectoryStub()
        candidate = configuration("candidate", directory, "private-ca")
        oracle = configuration("oracle", directory, "private-ca")
        self.assertNotIn("bindpass", candidate)
        self.assertIn("bindpass", oracle)
        self.assertIn("user_dn_template", candidate)
        self.assertNotIn("user_dn_template", oracle)
        self.assertIn("password", user_configuration("candidate", ["default"]))
        self.assertNotIn("password", user_configuration("oracle", ["default"]))
        self.assertIs(ADAPTATION["configuration_api_parity"], False)
        self.assertIn("no claim", ADAPTATION["disabled_credential"])


if __name__ == "__main__":
    unittest.main()
