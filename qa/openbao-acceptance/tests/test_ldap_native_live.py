"""Guard native LDAP observations against cached success and secret reflection."""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bao_http import Response
from core_isolation import ScenarioFailure
from ldap_native_live import Trace, config_matches, mapping_matches, complete_scenarios


class Directory:
    user_password = "private-directory-password"

    def cursor(self):
        return 0

    def observed(self, cursor, *, search):
        return False


class FailedClient:
    def request(self, *args, **kwargs):
        return Response(503, {"errors": ["private-provider-error"],
                              "auth": {"client_token": "private-token"},
                              "data": {"bindpass": "private-manager-password"}})


class CachedLogin:
    def request(self, *args, **kwargs):
        return Response(200, {"auth": {"client_token": "private-token", "entity_id": "private-entity",
                                      "lease_duration": 75, "token_policies": ["default"]}})


class NativeLdapTests(unittest.TestCase):
    def test_failed_provider_response_is_not_reflected_or_admitted(self):
        rows = []
        trace = Trace(FailedClient(), Directory(), {}, rows)
        with self.assertRaisesRegex(ScenarioFailure, "^ldap_native.failed$"):
            trace.call("failed", "auth/native/login/alice", {"password": "private"}, provider=True)
        self.assertFalse(rows[-1]["passed"])
        self.assertNotIn("private", json.dumps(rows))
        self.assertFalse(complete_scenarios(rows))

    def test_local_success_without_new_directory_operations_fails(self):
        rows = []
        trace = Trace(CachedLogin(), Directory(), {}, rows)
        with self.assertRaisesRegex(ScenarioFailure, "^ldap_native.cached$"):
            trace.login("cached", "native")
        self.assertFalse(rows[-1]["provider_checked"])
        self.assertNotIn("private", json.dumps(rows))

    def test_missing_or_multivalue_alias_cannot_be_silently_accepted(self):
        class ObservedDirectory(Directory):
            def observed(self, cursor, *, search):
                return True
        for name in ("alias_missing.attribute_rejected", "alias_multiple.attribute_rejected"):
            rows = []
            trace = Trace(CachedLogin(), ObservedDirectory(), {}, rows)
            with self.assertRaises(ScenarioFailure):
                trace.login(name, "native", expected=400)
            self.assertFalse(rows[-1]["passed"])
            self.assertNotIn("private", json.dumps(rows))

    def test_config_readback_rejects_secrets_and_wrong_default_types(self):
        data = {"case_sensitive_names": False, "token_ttl": 0, "token_policies": []}
        expected = dict(data)
        self.assertTrue(config_matches(data, **expected))
        self.assertFalse(config_matches(dict(data, bindpass="private"), **expected))
        self.assertFalse(config_matches(dict(data, case_sensitive_names=0), **expected))
        self.assertFalse(config_matches(dict(data, token_ttl=False), **expected))
        self.assertFalse(config_matches(dict(data, token_policies=["default"]), **expected))

    def test_config_case_requires_actual_normalized_readback(self):
        expected = {"userattr": "uid", "url": "ldaps://127.0.0.1:12345"}
        self.assertTrue(config_matches(dict(expected), **expected))
        self.assertFalse(config_matches(dict(expected, userattr="UID"), **expected))
        self.assertFalse(config_matches(dict(expected, url="LDAPS://127.0.0.1:12345"), **expected))

    def test_mapping_readback_requires_native_groups_string(self):
        self.assertTrue(mapping_matches({"groups": "aux", "policies": ["direct"]}, "aux", ["direct"]))
        self.assertTrue(mapping_matches({"groups": "", "policies": []}, "", []))
        for groups in ([], None, ["aux"], "AUX"):
            self.assertFalse(mapping_matches({"groups": groups, "policies": ["direct"]}, "aux", ["direct"]))

    def test_completion_rejects_missing_provider_mapping_identity_or_lifetime_proof(self):
        names = ["ldap_native.transport.dns_login.auth", "ldap_native.transport.failed_lease_unchanged",
                 "ldap_native.transport.restored_without_restart.lease", "ldap_native.transport.private_ca_not_system_trusted",
                 "ldap_native.transport.default_timeouts", "ldap_native.transport.wrong_san_before_ldap",
                 "ldap_native.transport.complete",
                 "ldap_native.directory.complete", "ldap_native.mapping.complete",
                 "ldap_native.config_case.create.normalized", "ldap_native.config_case.partial.normalized",
                 "ldap_native.config_case.create.login.auth", "ldap_native.config_case.partial.login.auth",
                 "ldap_native.alias_missing.username_login.auth", "ldap_native.alias_missing.attribute_rejected",
                 "ldap_native.alias_multiple.attribute_rejected", "ldap_native.alias_multiple.username_login.auth",
                 "ldap_native.no_mapping.uppercase_login.auth", "ldap_native.multiple_user_dn",
                 "ldap_native.alias.attribute.name", "ldap_native.alias.exact.name",
                 "ldap_native.mapping.deleted_still_directory_login.auth",
                 "ldap_native.identity.removed.kv", "ldap_native.identity.reopened_provider_checked.lease",
                 "ldap_native.lifetime.explicit_snapshot", "ldap_native.lifetime.issued_period_snapshot",
                 "ldap_native.identity_lifetime.complete"]
        rows = [{"case": name, "passed": True} for name in names]
        self.assertTrue(complete_scenarios(rows))
        for i in range(len(rows)):
            self.assertFalse(complete_scenarios(rows[:i] + rows[i + 1:]))
        self.assertFalse(complete_scenarios([dict(rows[0], passed=False)] + rows[1:]))
        self.assertFalse(complete_scenarios(rows[:-1] + [rows[0], rows[-1]]))
        self.assertTrue(complete_scenarios([{"case":"new_real_observation", "passed":True}] + rows))


if __name__ == "__main__":
    unittest.main()
