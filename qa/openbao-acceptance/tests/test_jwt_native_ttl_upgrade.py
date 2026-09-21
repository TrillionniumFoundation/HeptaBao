from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import jwt_native_ttl_upgrade as upgrade


class JwtNativeTtlUpgradeGuards(unittest.TestCase):
    def receipt(self):
        return {"status":"passed", "build_source_commit":upgrade.LEGACY_SOURCE,
                "source_and_binary_unchanged":True, "runner_unchanged":True,
                "candidate_source":{"source_commit":upgrade.LEGACY_SOURCE,
                                    "source_dirty":False, "binary_sha256":upgrade.LEGACY_SHA256}}

    def test_pin_is_mandatory_and_exact_clean_receipt_cannot_be_substituted(self):
        for field in ("LEGACY_SOURCE", "LEGACY_SHA256", "LEGACY_RECEIPT"):
            with patch.object(upgrade, field, None):
                with self.assertRaisesRegex(ValueError, "pin_not_available"):
                    upgrade.admit_legacy_receipt(upgrade.LEGACY_SHA256, self.receipt())
        upgrade.admit_legacy_receipt(upgrade.LEGACY_SHA256, self.receipt())
        for field, value in (("status","failed"), ("build_source_commit","0"*40),
                             ("source_and_binary_unchanged",False), ("runner_unchanged",False)):
            with self.assertRaises(ValueError):
                upgrade.admit_legacy_receipt(upgrade.LEGACY_SHA256, self.receipt() | {field:value})
        for field, value in (("source_commit","0"*40), ("binary_sha256","0"*64),
                             ("source_dirty",True), ("source_dirty",0)):
            receipt = self.receipt()
            receipt["candidate_source"][field] = value
            with self.assertRaises(ValueError):
                upgrade.admit_legacy_receipt(upgrade.LEGACY_SHA256, receipt)
        with self.assertRaises(ValueError):
            upgrade.admit_legacy_receipt("0"*64, self.receipt())

    def test_old_role_omits_limits_and_config_is_independent_of_evolving_helpers(self):
        self.assertFalse(set(upgrade.DURATION_FIELDS).intersection(upgrade.old_role()))
        self.assertEqual(upgrade.old_role()["role_type"], "jwt")
        issuer = SimpleNamespace(origin="https://localhost:443")
        for mode in upgrade.MODES:
            config = upgrade.legacy_configuration(mode, issuer, {"kid":"safe"}, "synthetic-ca")
            self.assertFalse(set(upgrade.DURATION_FIELDS).intersection(config))
            if mode == "remote":
                self.assertEqual(config["jwks_ca_pem"], "synthetic-ca")
            else:
                self.assertEqual(config["jwks"], {"keys":[{"kid":"safe"}]})

    def rows(self, prepare):
        end = "jwt_native_ttl_upgrade." + ("legacy.plaintext_credentials_absent" if prepare else "complete")
        names = sorted(upgrade.required_cases(prepare) - {end}) + [end]
        return [{"case":name, "passed":True} for name in names]

    def test_semantic_milestones_reject_omissions_duplicate_failure_raw_data_and_early_completion(self):
        for prepare in (True, False):
            rows = self.rows(prepare)
            self.assertTrue(upgrade.complete(rows, prepare))
            extra = {"case":"jwt_native_ttl_upgrade.extra", "passed":True}
            self.assertTrue(upgrade.complete(rows[:-1] + [extra] + rows[-1:], prepare))
            for index in range(len(rows)):
                self.assertFalse(upgrade.complete(rows[:index] + rows[index+1:], prepare), rows[index])
            self.assertFalse(upgrade.complete(rows + [rows[-1]], prepare))
            self.assertFalse(upgrade.complete(rows[:-1] + [dict(extra, passed=False)] + rows[-1:], prepare))
            self.assertFalse(upgrade.complete(rows[:-1] + [dict(extra, passed=1)] + rows[-1:], prepare))
            self.assertFalse(upgrade.complete(rows[:-1] + [dict(extra, raw="secret")] + rows[-1:], prepare))
            self.assertFalse(upgrade.complete(rows[-1:] + rows[:-1], prepare))
        self.assertFalse(upgrade.complete([], True))
        self.assertFalse(upgrade.complete([None], True))
        self.assertFalse(upgrade.complete(self.rows(True), False))

    def test_captured_explicit_cap_and_period_require_exact_absolute_expiry(self):
        issued = {"period":180, "explicit_max_ttl":480, "creation_time":1000}
        current = issued | {"expire_time_unix":1480}
        self.assertTrue(upgrade.caps_preserved(current, issued))
        for field, value in (("period",0), ("explicit_max_ttl",0), ("creation_time",1001),
                             ("expire_time_unix",1479), ("expire_time_unix",1481)):
            self.assertFalse(upgrade.caps_preserved(current | {field:value}, issued))
        self.assertFalse(upgrade.caps_preserved({}, issued))

    def test_store_scan_requires_real_artifacts_and_excludes_only_control_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "data").mkdir()
            (root / "server.log").write_text("safe")
            self.assertFalse(upgrade.scan_storage(root, ["sentinel-secret"]))
            (root / "data" / "encrypted").write_text("opaque")
            (root / "server.json").write_text("sentinel-secret")
            (root / "root.token").write_text("sentinel-secret")
            self.assertTrue(upgrade.scan_storage(root, ["sentinel-secret"]))
            for path in (root / "data" / "encrypted", root / "server.log", root / "audit.jsonl"):
                path.write_text("sentinel-secret")
                self.assertFalse(upgrade.scan_storage(root, ["sentinel-secret"]))
                path.write_text("opaque")
            self.assertFalse(upgrade.scan_storage(root, []))


if __name__ == "__main__":
    unittest.main()
