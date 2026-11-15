from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import token_defaults_upgrade as upgrade
from bao_http import Response


class TokenDefaultsUpgradeGuards(unittest.TestCase):
    def test_real_read_phase_control_flow_produces_unique_evidence_names(self):
        class ReachedMigration(Exception):
            pass
        kinds = ("ordinary", "child", "explicit", "periodic")
        auth = {kind:{"client_token":"synthetic-" + kind} for kind in kinds}
        snapshots = {kind:{"ttl":300, "creation_time":1000, "expire_time_unix":1300}
                     for kind in kinds}
        saved = {"auth":auth, "snapshots":snapshots, "role":{"token_ttl":120},
                 "tune":{"default_lease_ttl":0, "max_lease_ttl":0, "description":"kept"}}
        def request(method, path, body=None, **_kwargs):
            if path == "/v1/auth/token/create":
                raise ReachedMigration
            if path == "/v1/" + upgrade.VALUE:
                return Response(200, {"data":{"data":{"synthetic":True}}})
            if path == "/v1/" + upgrade.TUNE:
                return Response(200, {"data":saved["tune"] | {"default_lease_ttl":3600, "max_lease_ttl":upgrade.MAX_TTL}})
            if path == "/v1/" + upgrade.ROLE:
                return Response(200, {"data":saved["role"]})
            if path == "/v1/auth/token/lookup":
                kind = body["token"].removeprefix("synthetic-")
                return Response(200, {"data":snapshots[kind] | {"ttl":299}})
            return Response(200, {})
        rows = []
        with tempfile.TemporaryDirectory() as directory:
            instance = SimpleNamespace(root=Path(directory), address="https://localhost:443", token="synthetic-root",
                                       start=lambda:None, stop=lambda:None)
            with patch.object(upgrade, "Client", return_value=SimpleNamespace(request=request)):
                trace = upgrade.Trace(instance, "default", rows)
            with patch.object(upgrade, "prepare_legacy", return_value=(trace, "synthetic-key", saved)), \
                 patch.object(upgrade, "durable_manifest", return_value="unchanged"):
                with self.assertRaises(ReachedMigration):
                    upgrade.run_upgrade(instance, "default", Path("candidate"), Path("legacy"), rows)
        names = [row["case"] for row in rows]
        self.assertEqual(len(names), len(set(names)))
        self.assertTrue(all(row["passed"] is True for row in rows))
        for phase in ("current", "untouched_restart"):
            self.assertIn("token_defaults_upgrade.default." + phase + ".reads_preserve_entire_store", names)

    def receipt(self):
        return {"status":"passed", "build_source_commit":upgrade.LEGACY_SOURCE,
                "source_and_binary_unchanged":True, "runner_unchanged":True,
                "candidate_source":{"source_commit":upgrade.LEGACY_SOURCE,
                                    "source_dirty":False, "binary_sha256":upgrade.LEGACY_SHA256}}

    def test_none_pin_refuses_before_receipt_admission(self):
        for field in ("LEGACY_SOURCE", "LEGACY_SHA256", "LEGACY_RECEIPT"):
            with patch.object(upgrade, field, None):
                with self.assertRaisesRegex(ValueError, "pin_not_available"):
                    upgrade.admit_legacy_receipt(upgrade.LEGACY_SHA256, self.receipt())

    def test_pinned_clean_receipt_requires_every_identity_fact(self):
        # This unit exercises only receipt validation, never creates old state
        # or starts a server under synthetic binary identities.
        with patch.multiple(upgrade, LEGACY_SOURCE="1"*40, LEGACY_SHA256="2"*64,
                            LEGACY_RECEIPT=Path("/synthetic/unit-only-receipt")):
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

    def test_effective_tune_readback_allows_only_explained_inherited_zero_fields(self):
        old = {"default_lease_ttl":0, "max_lease_ttl":0, "description":"kept", "revision":3, "accessor":"safe"}
        current = old | {"default_lease_ttl":3600, "max_lease_ttl":upgrade.MAX_TTL}
        self.assertTrue(upgrade.retained_tune(current, old))
        for key, value in (("default_lease_ttl",upgrade.MAX_TTL), ("max_lease_ttl",600),
                           ("description","changed"), ("revision",4), ("accessor","different"), ("extra",True)):
            self.assertFalse(upgrade.retained_tune(current | {key:value}, old))
        tuned = old | {"default_lease_ttl":75, "max_lease_ttl":600}
        self.assertTrue(upgrade.retained_tune(tuned, tuned))
        self.assertFalse(upgrade.retained_tune(current, tuned))

    def test_old_token_lookup_ignores_only_dynamic_remaining_ttl(self):
        old = {"ttl":3600, "expire_time_unix":4000, "creation_time":400, "explicit_max_ttl":upgrade.MAX_TTL,
               "policies":["default"], "period":180}
        self.assertTrue(upgrade.retained_lookup(old | {"ttl":3599}, old))
        for key, value in (("expire_time_unix",4001), ("creation_time",401), ("explicit_max_ttl",0),
                           ("policies",[]), ("period",0), ("extra",True)):
            self.assertFalse(upgrade.retained_lookup(old | {key:value}, old))
        self.assertFalse(upgrade.retained_lookup({key:value for key,value in old.items() if key != "period"}, old))

    def test_explicit_cap_requires_original_issue_time_and_exact_deadline(self):
        old = {"creation_time":1000}
        current = {"creation_time":1000, "explicit_max_ttl":480, "expire_time_unix":1480}
        self.assertTrue(upgrade.cap_deadline(current, old, 480))
        for key, value in (("creation_time",1001), ("explicit_max_ttl",0), ("expire_time_unix",1479), ("expire_time_unix",1481)):
            self.assertFalse(upgrade.cap_deadline(current | {key:value}, old, 480))

    def test_actual_renew_routes_reject_invalid_or_over_cap_grants(self):
        auth = {"client_token":"synthetic-token", "accessor":"synthetic-accessor"}
        instance = SimpleNamespace(root=Path("/unit-only"), address="https://localhost:443", token="synthetic-root")
        for grant in (479, 480, 481, 0, True, 480.0):
            def request(_method, path, _body=None, **_kwargs):
                body = {"lease_duration":grant}
                if not path.endswith("renew-accessor"):
                    body["client_token"] = auth["client_token"]
                return Response(200, {"auth":body})
            with patch.object(upgrade, "Client", return_value=SimpleNamespace(request=request)):
                trace = upgrade.Trace(instance, "default", [])
            if type(grant) is int and 0 < grant <= 480:
                trace.renew("unit", auth, max_lease=480)
                self.assertEqual(sum(row["case"].endswith(".shape") for row in trace.rows), 3)
            else:
                with self.assertRaises(upgrade.ScenarioFailure):
                    trace.renew("unit", auth, max_lease=480)
                self.assertIs(trace.rows[-1]["passed"], False)

    def rows(self, prepare):
        end = "token_defaults_upgrade." + ("tuned.legacy.plaintext_credentials_absent" if prepare else "fresh.complete")
        return [{"case":name, "passed":True} for name in sorted(upgrade.required_cases(prepare) - {end}) + [end]]

    def test_every_required_phase_and_fresh_store_cannot_be_omitted(self):
        for prepare in (True, False):
            rows = self.rows(prepare)
            self.assertTrue(upgrade.complete(rows, prepare))
            extra = {"case":"token_defaults_upgrade.extra", "passed":True}
            self.assertTrue(upgrade.complete(rows[:-1] + [extra] + rows[-1:], prepare))
            for index in range(len(rows)):
                self.assertFalse(upgrade.complete(rows[:index] + rows[index+1:], prepare), rows[index])
            self.assertFalse(upgrade.complete(rows + [rows[-1]], prepare))
            for invalid in (dict(extra, passed=False), dict(extra, passed=1), dict(extra, raw="secret")):
                self.assertFalse(upgrade.complete(rows[:-1] + [invalid] + rows[-1:], prepare))
            self.assertFalse(upgrade.complete(rows[-1:] + rows[:-1], prepare))
        self.assertFalse(upgrade.complete([], True))
        self.assertFalse(upgrade.complete([None], True))
        self.assertFalse(upgrade.complete(self.rows(True), False))


if __name__ == "__main__":
    unittest.main()
