"""Guard real schema-22 build provenance and fail-closed LDAP upgrade reporting."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bao_http import Response
from core_isolation import ScenarioFailure
from ldap_native_upgrade import LEGACY_SHA256, LEGACY_SOURCE, Trace, admit_legacy, provider_idle


class DirectoryStub:
    def cursor(self): return 0
    def observed(self, cursor, *, search): return False


class ClientStub:
    def request(self, *args, **kwargs):
        return Response(200, {"auth": {"client_token": "private-token"}, "errors": ["private-credential"]})


class LdapNativeUpgradeTests(unittest.TestCase):
    def test_connection_close_is_not_authentication_but_bind_or_search_is(self):
        with tempfile.TemporaryDirectory() as path:
            directory = DirectoryStub()
            directory.root = Path(path)
            log = directory.root / "slapd.log"
            prior = b"do_bind\ndo_search\n"
            log.write_bytes(prior + b"connection_close: conn=1\n")
            self.assertTrue(provider_idle(directory, len(prior)))
            for operation in (b"do_bind", b"do_search"):
                log.write_bytes(prior + b"connection_close: conn=1\n" + operation)
                self.assertFalse(provider_idle(directory, len(prior)))

    def receipt(self):
        return {"build_source_commit": LEGACY_SOURCE, "harness_source_commit": LEGACY_SOURCE,
                "harness_source_dirty": False, "harness_source_unchanged": True,
                "binaries_unchanged": True, "candidate_binary_sha256": LEGACY_SHA256, "status": "passed"}

    def test_old_binary_must_match_the_actual_clean_build(self):
        for key, value in [("build_source_commit", "other"), ("harness_source_commit", "other"),
                           ("harness_source_dirty", True), ("harness_source_unchanged", False),
                           ("binaries_unchanged", False), ("candidate_binary_sha256", "0" * 64), ("status", "failed")]:
            with self.assertRaises(ValueError):
                admit_legacy(Path("new"), Path("old"), LEGACY_SHA256, dict(self.receipt(), **{key: value}))
        with self.assertRaises(ValueError):
            admit_legacy(Path("new"), Path("old"), "0" * 64, self.receipt())
        with patch("ldap_native_upgrade.validate_binary_pins", return_value=("new", "old")) as pins:
            self.assertEqual(admit_legacy(Path("new"), Path("old"), LEGACY_SHA256, self.receipt()), ("new", "old"))
            pins.assert_called_once_with(Path("new"), Path("old"), LEGACY_SHA256)

    def test_wrong_status_cannot_pass_or_reflect_secrets(self):
        rows = []
        with self.assertRaisesRegex(ScenarioFailure, "^ldap_native_upgrade.downgrade$"):
            Trace(ClientStub(), DirectoryStub(), rows).call("downgrade", "sys/unseal", {"key": "private-key"}, expected=503)
        self.assertEqual(rows, [{"case": "ldap_native_upgrade.downgrade", "status": 200, "passed": False}])
        self.assertNotIn("private", json.dumps(rows))

    def test_a_successful_http_status_cannot_hide_missing_directory_verification(self):
        rows = []
        with self.assertRaises(ScenarioFailure):
            Trace(ClientStub(), DirectoryStub(), rows).call("renew", "auth/token/renew-self", {}, provider="search")
        self.assertIs(rows[-1]["provider_checked"], False)
        self.assertIs(rows[-1]["passed"], False)
        self.assertNotIn("private", json.dumps(rows))

    def test_failed_storage_invariant_aborts_after_successful_prefix(self):
        rows = []
        trace = Trace(None, DirectoryStub(), rows)
        trace.check("unsealed", True)
        with self.assertRaises(ScenarioFailure):
            trace.check("application_unchanged", False)
        self.assertIs(rows[-1]["passed"], False)


if __name__ == "__main__":
    unittest.main()
