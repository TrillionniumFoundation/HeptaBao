from types import SimpleNamespace
import unittest

from jwt_bound_claims_upgrade import (LEGACY_SHA256, LEGACY_SOURCE, MODES, admit_legacy_receipt,
    complete, legacy_configuration, old_role, required_cases, retained_role_readback)


class JwtBoundUpgradeGuards(unittest.TestCase):
    def receipt(self):
        return {"status":"passed", "build_source_commit":LEGACY_SOURCE,
            "source_and_binary_unchanged":True, "runner_unchanged":True,
            "candidate_source":{"source_commit":LEGACY_SOURCE, "source_dirty":False,
                                "binary_sha256":LEGACY_SHA256}}

    def test_historical_receipt_is_exact_and_does_not_accept_dirty_or_changed_evidence(self):
        admit_legacy_receipt(LEGACY_SHA256, self.receipt())
        for field, value in [("status","failed"), ("build_source_commit","0"*40),
                             ("runner_unchanged",False), ("source_and_binary_unchanged",False)]:
            with self.assertRaises(ValueError):
                admit_legacy_receipt(LEGACY_SHA256, self.receipt() | {field:value})
        for field, value in [("source_commit","0"*40), ("binary_sha256","0"*64), ("source_dirty",True), ("source_dirty",0)]:
            receipt = self.receipt()
            receipt["candidate_source"][field] = value
            with self.assertRaises(ValueError):
                admit_legacy_receipt(LEGACY_SHA256, receipt)
        with self.assertRaises(ValueError):
            admit_legacy_receipt("0"*64, self.receipt())

    def test_old_shape_uses_no_new_bound_fields_and_remote_api_ca_is_explicit(self):
        self.assertFalse({"bound_claims", "bound_claims_type"}.intersection(old_role()))
        issuer = SimpleNamespace(origin="https://localhost:443")
        for mode in MODES:
            config = legacy_configuration(mode, issuer, {"kid":"safe"}, "synthetic-ca")
            self.assertFalse({"bound_claims", "bound_claims_type"}.intersection(config))
            if mode == "remote":
                self.assertEqual(config["jwks_ca_pem"], "synthetic-ca")
            else:
                self.assertEqual(config["jwks"], {"keys":[{"kid":"safe"}]})

    def test_additive_readback_defaults_do_not_hide_changed_or_removed_old_fields(self):
        old = {"token_ttl":600, "token_policies":["default"]}
        current = old | {"role_type":"jwt", "user_claim":"sub", "bound_claims_type":"string", "bound_claims":None}
        self.assertTrue(retained_role_readback(current, old))
        for field, value in [("token_ttl",601), ("token_policies",[]), ("role_type","oidc"),
                             ("user_claim","different"), ("bound_claims_type","glob"),
                             ("bound_claims",{"value":42}), ("unexplained_field",True)]:
            self.assertFalse(retained_role_readback(current | {field:value}, old))
        removed = dict(current)
        del removed["token_policies"]
        self.assertFalse(retained_role_readback(removed, old))

    def test_each_required_phase_is_required_without_a_fixed_check_count(self):
        for prepare in (True, False):
            rows = [{"case":name, "passed":True} for name in sorted(required_cases(prepare))]
            self.assertTrue(complete(rows, prepare))
            self.assertTrue(complete(rows + [{"case":"extra.safe", "passed":True}], prepare))
            for index in range(len(rows)):
                self.assertFalse(complete(rows[:index] + rows[index+1:], prepare), rows[index])
            self.assertFalse(complete(rows + [rows[0]], prepare))
            self.assertFalse(complete(rows + [{"case":"extra.failed", "passed":False}], prepare))
            self.assertFalse(complete(rows + [{"case":"extra.nonboolean", "passed":1}], prepare))
        self.assertFalse(complete([], True))
        self.assertFalse(complete([None], True))

    def test_preparation_cannot_be_reported_as_a_completed_upgrade(self):
        rows = [{"case":name, "passed":True} for name in required_cases(True)]
        self.assertTrue(complete(rows, True))
        self.assertFalse(complete(rows, False))


if __name__ == '__main__':
    unittest.main()
