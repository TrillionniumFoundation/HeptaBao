"""Pin the real legacy profile and prevent unsafe or partial upgrade receipts."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bao_http import Response
from core_isolation import ScenarioFailure
from ldap_transport_upgrade import (LEGACY_SHA256, LEGACY_SOURCE, MILESTONES,
    TRANSPORT_FIELDS, Trace, admit_legacy, admit_legacy_receipt,
    complete_scenarios, legacy_configuration)


class DirectoryStub:
    origin = "ldaps://127.0.0.1:1636"
    admin_dn = "cn=admin,dc=example,dc=test"
    admin_password = "private-manager-password"
    def cursor(self): return 0
    def observed(self, cursor, *, search): return False


class ClientStub:
    def request(self, *args, **kwargs):
        return Response(200, {"auth": {"client_token": "private-token"}, "errors": ["private-credential"]})


class LdapTransportUpgradeTests(unittest.TestCase):
    def receipt(self):
        return {"status": "passed", "source_and_binary_unchanged": True, "cases_match": True,
                "source_identity": {"source_commit": LEGACY_SOURCE,
                                    "binary_sha256": LEGACY_SHA256, "source_dirty": False}}

    def test_clean_real_schema24_receipt_and_binary_pin_are_required(self):
        for key, value in [("status", "failed"), ("source_and_binary_unchanged", False), ("cases_match", False)]:
            with self.assertRaises(ValueError):
                admit_legacy_receipt(LEGACY_SHA256, dict(self.receipt(), **{key: value}))
        for key, value in [("source_commit", "other"), ("binary_sha256", "0" * 64), ("source_dirty", True)]:
            receipt = self.receipt()
            receipt["source_identity"][key] = value
            with self.assertRaises(ValueError):
                admit_legacy_receipt(LEGACY_SHA256, receipt)
        with self.assertRaises(ValueError):
            admit_legacy_receipt("0" * 64, self.receipt())
        with patch("ldap_transport_upgrade.validate_binary_pins", return_value=("new", "old")) as pins:
            self.assertEqual(admit_legacy(Path("new"), Path("old"), LEGACY_SHA256, self.receipt()), ("new", "old"))
            pins.assert_called_once_with(Path("new"), Path("old"), LEGACY_SHA256)

    def test_legacy_configuration_cannot_accidentally_create_new_transport(self):
        config = legacy_configuration(DirectoryStub())
        self.assertFalse(TRANSPORT_FIELDS.intersection(config))
        self.assertEqual(config["bindpass"], DirectoryStub.admin_password)
        self.assertEqual(config["token_policies"], ["upgrade-reader"])

    def test_wrong_status_and_missing_provider_checks_never_reflect_credentials(self):
        for expected, provider in [(503, None), (200, "search")]:
            rows = []
            with self.assertRaises(ScenarioFailure):
                Trace(ClientStub(), DirectoryStub(), rows).call("rejected", "sys/unseal",
                    {"key": "private-key"}, expected=expected, provider=provider)
            self.assertIs(rows[-1]["passed"], False)
            self.assertNotIn("private", json.dumps(rows))
        with self.assertRaises(ValueError):
            Trace(None, None, []).check("unsafe", True, credential="private")

    def test_failed_atomicity_check_aborts(self):
        rows = []
        t = Trace(None, None, rows)
        t.check("ready", True)
        with self.assertRaises(ScenarioFailure):
            t.check("no_extension_or_mutation", False)
        self.assertIs(rows[-1]["passed"], False)

    def test_completion_requires_upgrade_milestones_not_a_fixed_count(self):
        rows = [{"case": "ldap_transport_upgrade." + name, "passed": True}
                for name in sorted(MILESTONES - {"complete"}) + ["complete"]]
        self.assertTrue(complete_scenarios(rows))
        for index in range(len(rows)):
            self.assertFalse(complete_scenarios(rows[:index] + rows[index + 1:]))
        self.assertFalse(complete_scenarios(rows + [rows[-1]]))
        self.assertFalse(complete_scenarios([dict(rows[0], passed=False)] + rows[1:]))
        self.assertTrue(complete_scenarios(rows[:-1] + [{"case": "extra_detail", "passed": True}] + rows[-1:]))


if __name__ == "__main__":
    unittest.main()
