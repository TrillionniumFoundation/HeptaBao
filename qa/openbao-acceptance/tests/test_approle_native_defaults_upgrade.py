from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from bao_http import Response
import approle_native_defaults_upgrade as upgrade


class AppRoleDefaultsUpgradeGuards(unittest.TestCase):
    def receipt(self):
        return {"status":"passed", "build_source_commit":upgrade.LEGACY_SOURCE,
                "source_and_binary_unchanged":True, "runner_unchanged":True,
                "candidate_source":{"source_commit":upgrade.LEGACY_SOURCE, "source_dirty":False,
                                    "binary_sha256":upgrade.LEGACY_SHA256}}

    def test_unknown_historical_pin_is_not_an_executable_fixture(self):
        for field in ("LEGACY_SOURCE", "LEGACY_SHA256", "LEGACY_RECEIPT"):
            with patch.object(upgrade, field, None):
                with self.assertRaisesRegex(ValueError, "pin_not_available"):
                    upgrade.admit_legacy_receipt(upgrade.LEGACY_SHA256, self.receipt())

    def test_receipt_binding_requires_exact_clean_runtime_identity(self):
        with patch.multiple(upgrade, LEGACY_SOURCE="1"*40, LEGACY_SHA256="2"*64,
                            LEGACY_RECEIPT=Path("/synthetic/unit-only")):
            upgrade.admit_legacy_receipt(upgrade.LEGACY_SHA256, self.receipt())
            for field, value in (("status","failed"), ("build_source_commit","0"*40),
                                 ("source_and_binary_unchanged",False), ("runner_unchanged",False)):
                with self.assertRaises(ValueError):
                    upgrade.admit_legacy_receipt(upgrade.LEGACY_SHA256, self.receipt() | {field:value})
            for field, value in (("source_commit","0"*40), ("binary_sha256","0"*64), ("source_dirty",True), ("source_dirty",0)):
                receipt = self.receipt()
                receipt["candidate_source"][field] = value
                with self.assertRaises(ValueError):
                    upgrade.admit_legacy_receipt(upgrade.LEGACY_SHA256, receipt)

    def old_secret(self):
        return {"secret_id_accessor":"synthetic-accessor", "secret_id_num_uses":1, "expiration_time_unix":3600}

    def extended_old_secret(self):
        return self.old_secret() | {"expiration_time":"1970-01-01T01:00:00Z", "metadata":{},
                                   "cidr_list":[], "token_bound_cidrs":[]}

    def test_legacy_metadata_cannot_be_invented_and_original_expiry_and_use_limit_are_exact(self):
        old, current = self.old_secret(), self.extended_old_secret()
        self.assertTrue(upgrade.retained_secret(current, old))
        for field, value in (("secret_id_ttl",3600), ("creation_time","1970-01-01T00:00:00Z"),
                             ("last_updated_time","1970-01-01T00:00:00Z"), ("secret_id_num_uses",0),
                             ("expiration_time_unix",None), ("expiration_time","1970-01-01T01:00:01Z"),
                             ("cidr_list",None), ("cidr_list",["127.0.0.1/32"]), ("extra",True)):
            self.assertFalse(upgrade.retained_secret(current | {field:value}, old))

    def test_native_requested_ttl_and_actual_clamped_expiry_are_independent(self):
        info = {"secret_id_accessor":"safe", "secret_id_ttl":3600, "secret_id_num_uses":1,
                "creation_time":"1970-01-01T00:00:00Z", "last_updated_time":"1970-01-01T00:00:00Z",
                "expiration_time":"1970-01-01T00:10:00Z", "expiration_time_unix":600}
        self.assertTrue(upgrade.native_secret(info, ttl=3600, uses=1, lifetime=600))
        for field, value in (("secret_id_ttl",600), ("secret_id_num_uses",0), ("expiration_time_unix",601),
                             ("creation_time",None), ("last_updated_time","1969-12-31T23:59:59Z")):
            self.assertFalse(upgrade.native_secret(info | {field:value}, ttl=3600, uses=1, lifetime=600))
        unlimited = info | {"secret_id_ttl":0, "secret_id_num_uses":0,
                            "expiration_time":"0001-01-01T00:00:00Z", "expiration_time_unix":None}
        self.assertTrue(upgrade.native_secret(unlimited, ttl=0, uses=0, lifetime=0))
        self.assertFalse(upgrade.native_secret(unlimited | {"expiration_time_unix":600}, ttl=0, uses=0, lifetime=0))

    def test_actual_pure_read_phases_have_unique_labels_and_no_fake_secret_metadata(self):
        class ReachedMigration(Exception):
            pass
        saved = {profile:{"role":{"token_ttl":75}, "held":{"secret_id":"synthetic-secret"},
                          "held_lookup":self.old_secret(), "auth":{"client_token":"synthetic-token"},
                          "token_lookup":{"ttl":75, "creation_time":1000}}
                 for profile in upgrade.MOUNTS}
        def request(method, path, body=None, **_kwargs):
            if method == "POST" and "/role/" in path and not path.endswith("/lookup"):
                raise ReachedMigration
            if path == "/v1/" + upgrade.VALUE:
                return Response(200, {"data":{"data":{"synthetic":True}}})
            if path.endswith("/secret-id/lookup"):
                return Response(200, {"data":self.extended_old_secret()})
            if "/role/" in path:
                return Response(200, {"data":{"token_ttl":75}})
            if path == "/v1/auth/token/lookup":
                return Response(200, {"data":{"ttl":74, "creation_time":1000}})
            return Response(200, {})
        rows = []
        with tempfile.TemporaryDirectory() as directory:
            instance = SimpleNamespace(root=Path(directory), address="https://localhost:443", token="synthetic-root",
                                       start=lambda:None, stop=lambda:None)
            with patch.object(upgrade, "Client", return_value=SimpleNamespace(request=request)):
                trace = upgrade.Trace(instance, rows)
            with patch.object(upgrade, "prepare_legacy", return_value=(trace, "synthetic-key", saved)), \
                 patch.object(upgrade, "durable_manifest", return_value="unchanged"):
                with self.assertRaises(ReachedMigration):
                    upgrade.run_upgrade(instance, Path("candidate"), Path("legacy"), rows)
        names = [row["case"] for row in rows]
        self.assertEqual(len(names), len(set(names)))
        self.assertTrue(all(row["passed"] is True for row in rows))
        for phase in ("current", "untouched_restart"):
            self.assertIn("approle_defaults_upgrade." + phase + ".reads_preserve_entire_store", names)

    def test_all_semantic_milestones_are_required_without_a_fixed_count(self):
        for prepare in (True, False):
            end = "approle_defaults_upgrade." + ("legacy.plaintext_credentials_absent" if prepare else "complete")
            names = sorted(upgrade.required_cases(prepare) - {end}) + [end]
            rows = [{"case":name, "passed":True} for name in names]
            self.assertTrue(upgrade.complete(rows, prepare))
            extra = {"case":"approle_defaults_upgrade.extra", "passed":True}
            self.assertTrue(upgrade.complete(rows[:-1] + [extra] + rows[-1:], prepare))
            for index in range(len(rows)):
                self.assertFalse(upgrade.complete(rows[:index] + rows[index+1:], prepare), rows[index])
            self.assertFalse(upgrade.complete(rows + [rows[-1]], prepare))
            for invalid in (dict(extra, passed=False), dict(extra, passed=1), dict(extra, raw="secret")):
                self.assertFalse(upgrade.complete(rows[:-1] + [invalid] + rows[-1:], prepare))
            self.assertFalse(upgrade.complete(rows[-1:] + rows[:-1], prepare))
        self.assertFalse(upgrade.complete([], False))
        self.assertFalse(upgrade.complete([None], False))


if __name__ == "__main__":
    unittest.main()
